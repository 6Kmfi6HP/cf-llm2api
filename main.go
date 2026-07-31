package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func newBaseTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
}

var httpClient = &http.Client{
	Timeout:   600 * time.Second,
	Transport: newBaseTransport(),
}

var streamHTTPClient = &http.Client{
	Timeout:   0,
	Transport: newBaseTransport(),
}

// ======================== SOCKS5 代理 ========================

type Socks5Proxy struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Billing header regex for stripping Anthropic system message headers
var reBillingHeader = regexp.MustCompile(`(?m)^x-anthropic-billing-header:\s*.*$`)

var (
	socks5Proxies []Socks5Proxy
	socks5Mu      sync.RWMutex
)

type socks5ClientKey struct {
	Addr     string
	Username string
	Password string
	Stream   bool
}

var (
	socks5ClientsMu sync.Mutex
	socks5Clients   = map[socks5ClientKey]*http.Client{}
)

func socks5Dial(proxy Socks5Proxy) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := dialer.DialContext(ctx, network, proxy.Addr)
		if err != nil {
			return nil, fmt.Errorf("socks5 connect to %s: %w", proxy.Addr, err)
		}
		fail := func(format string, args ...any) (net.Conn, error) {
			conn.Close()
			return nil, fmt.Errorf(format, args...)
		}

		deadline := time.Now().Add(15 * time.Second)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return fail("socks5 set deadline: %w", err)
		}

		authMethod := byte(0x00)
		if proxy.Username != "" {
			authMethod = 0x02
		}
		if _, err := conn.Write([]byte{0x05, 0x01, authMethod}); err != nil {
			return fail("socks5 handshake write: %w", err)
		}
		handshake := make([]byte, 2)
		if _, err := io.ReadFull(conn, handshake); err != nil {
			return fail("socks5 handshake read: %w", err)
		}
		if handshake[0] != 0x05 {
			return fail("socks5: unexpected protocol version 0x%02x", handshake[0])
		}
		switch handshake[1] {
		case 0x00:
		case 0x02:
			if proxy.Username == "" {
				return fail("socks5: server requires authentication")
			}
			if len(proxy.Username) > 255 || len(proxy.Password) > 255 {
				return fail("socks5: username or password is too long")
			}
			auth := []byte{0x01, byte(len(proxy.Username))}
			auth = append(auth, proxy.Username...)
			auth = append(auth, byte(len(proxy.Password)))
			auth = append(auth, proxy.Password...)
			if _, err := conn.Write(auth); err != nil {
				return fail("socks5 auth write: %w", err)
			}
			authResponse := make([]byte, 2)
			if _, err := io.ReadFull(conn, authResponse); err != nil {
				return fail("socks5 auth read: %w", err)
			}
			if authResponse[1] != 0x00 {
				return fail("socks5: authentication failed")
			}
		default:
			return fail("socks5: unsupported authentication method 0x%02x", handshake[1])
		}

		host, portText, err := net.SplitHostPort(target)
		if err != nil {
			return fail("socks5: invalid target %s: %w", target, err)
		}
		portNumber, err := strconv.Atoi(portText)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fail("socks5: invalid target port %q", portText)
		}
		request := []byte{0x05, 0x01, 0x00}
		if ip := net.ParseIP(host); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				request = append(request, 0x01)
				request = append(request, ipv4...)
			} else {
				request = append(request, 0x04)
				request = append(request, ip.To16()...)
			}
		} else {
			if len(host) == 0 || len(host) > 255 {
				return fail("socks5: invalid target hostname")
			}
			request = append(request, 0x03, byte(len(host)))
			request = append(request, host...)
		}
		request = append(request, byte(portNumber>>8), byte(portNumber))
		if _, err := conn.Write(request); err != nil {
			return fail("socks5 connect write: %w", err)
		}

		response := make([]byte, 4)
		if _, err := io.ReadFull(conn, response); err != nil {
			return fail("socks5 connect read: %w", err)
		}
		if response[0] != 0x05 || response[1] != 0x00 {
			return fail("socks5: connect failed, status 0x%02x", response[1])
		}
		addressLength := 0
		switch response[3] {
		case 0x01:
			addressLength = 4
		case 0x03:
			length := make([]byte, 1)
			if _, err := io.ReadFull(conn, length); err != nil {
				return fail("socks5: read bind hostname length: %w", err)
			}
			addressLength = int(length[0])
		case 0x04:
			addressLength = 16
		default:
			return fail("socks5: unknown bind address type 0x%02x", response[3])
		}
		if _, err := io.ReadFull(conn, make([]byte, addressLength+2)); err != nil {
			return fail("socks5: read bind address: %w", err)
		}
		if err := conn.SetDeadline(time.Time{}); err != nil {
			return fail("socks5 clear deadline: %w", err)
		}
		return conn, nil
	}
}

func configuredSocks5Proxy(addr string) (Socks5Proxy, bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return Socks5Proxy{}, false
	}
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	for _, proxy := range socks5Proxies {
		if proxy.Addr == addr {
			return proxy, true
		}
	}
	return Socks5Proxy{}, false
}

func socks5ProxyLabel(proxy Socks5Proxy) string {
	if proxy.Name != "" {
		return proxy.Name + " (" + proxy.Addr + ")"
	}
	return proxy.Addr
}

func getModelHTTPClient(proxyAddr string, stream bool) (*http.Client, string) {
	proxy, ok := configuredSocks5Proxy(proxyAddr)
	if !ok {
		if stream {
			return streamHTTPClient, "direct"
		}
		return httpClient, "direct"
	}
	key := socks5ClientKey{
		Addr:     proxy.Addr,
		Username: proxy.Username,
		Password: proxy.Password,
		Stream:   stream,
	}
	socks5ClientsMu.Lock()
	defer socks5ClientsMu.Unlock()
	if client := socks5Clients[key]; client != nil {
		return client, socks5ProxyLabel(proxy)
	}
	transport := newBaseTransport()
	transport.DialContext = socks5Dial(proxy)
	client := &http.Client{Transport: transport, Timeout: 600 * time.Second}
	if stream {
		client.Timeout = 0
	}
	socks5Clients[key] = client
	return client, socks5ProxyLabel(proxy)
}

func modelProxyLabel(proxyAddr string) string {
	if proxy, ok := configuredSocks5Proxy(proxyAddr); ok {
		return socks5ProxyLabel(proxy)
	}
	return "direct"
}

func clearSocks5ClientCache() {
	socks5ClientsMu.Lock()
	defer socks5ClientsMu.Unlock()
	for _, client := range socks5Clients {
		if transport, ok := client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	socks5Clients = map[socks5ClientKey]*http.Client{}
}

// ======================== 随机 ID ========================

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}
	return string(b)
}

// ======================== OpenCode 会话 ========================

var (
	upstreamCfgs = map[string]*UpstreamConfig{}
	requestCount atomic.Int64
	// cpaTranslatorCfg 是 CPA 翻译层灰度开关的运行期拷贝，由 applyConfig 从 AppConfig 同步，由 configMu 保护。
	cpaTranslatorCfg CPATranslatorConfig
	// claudeCompatCfg 是 Claude 入站兼容夹层开关的运行期拷贝，同由 configMu 保护。
	claudeCompatCfg ClaudeCompatConfig
)

// ======================== 模型 ========================

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

var (
	upstreamKeyCursorMu sync.Mutex
	upstreamKeyCursor   = map[string]int{}
)

func splitUpstreamAPIKeys(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	keys := make([]string, 0, strings.Count(raw, "\n")+1)
	for _, line := range strings.Split(raw, "\n") {
		key := strings.TrimSpace(line)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func getUpstreamAPIKeys(upstream *UpstreamConfig) []string {
	if upstream == nil {
		return nil
	}
	return splitUpstreamAPIKeys(upstream.APIKey)
}

func nextUpstreamAPIKeyIndex(name string, total int) int {
	if total <= 1 {
		return 0
	}
	resolvedName := effectiveUpstreamName(name)
	upstreamKeyCursorMu.Lock()
	defer upstreamKeyCursorMu.Unlock()
	idx := upstreamKeyCursor[resolvedName] % total
	upstreamKeyCursor[resolvedName] = (idx + 1) % total
	return idx
}

func selectUpstreamAPIKey(name string, upstream *UpstreamConfig) (string, int, []string) {
	keys := getUpstreamAPIKeys(upstream)
	if len(keys) == 0 {
		return "", -1, nil
	}
	idx := nextUpstreamAPIKeyIndex(name, len(keys))
	return keys[idx], idx, keys
}

func rotateUpstreamAPIKey(keys []string, current int) (string, int) {
	if len(keys) == 0 {
		return "", -1
	}
	if current < 0 {
		current = 0
	}
	next := (current + 1) % len(keys)
	return keys[next], next
}

func formatUpstreamAPIKeySlot(index int, total int) string {
	if index < 0 || total <= 0 {
		return "0/0"
	}
	return fmt.Sprintf("%d/%d", index+1, total)
}

func waitForRetry(ctx context.Context, baseDelay time.Duration) error {
	delay := baseDelay
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Second
	}
	if delay >= 30*time.Second {
		return 30 * time.Second
	}
	delay *= 2
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func shouldRetryUpstreamStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func cloneUpstreamConfig(cfg *UpstreamConfig) *UpstreamConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.CustomModels != nil {
		cp.CustomModels = append([]string(nil), cfg.CustomModels...)
	}
	cp.CloudflareCredentials = cloneCloudflareCredentials(cfg.CloudflareCredentials)
	return &cp
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameUpstreamConfig(a, b *UpstreamConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.BaseURL == b.BaseURL &&
		a.APIKey == b.APIKey &&
		a.APIType == b.APIType &&
		a.ResponsesReasoningFormat == b.ResponsesReasoningFormat &&
		sameStringSlice(a.CustomModels, b.CustomModels) &&
		sameCloudflareCredentials(a.CloudflareCredentials, b.CloudflareCredentials)
}

func sameCloudflareCredentials(a, b []CloudflareCredential) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// upstreamsConfigChanged 判断上游连接相关配置是否变化（模型列表依赖这些字段）。
// 别名、推理映射、代理等不影响上游模型列表。
func upstreamsConfigChanged(oldMap map[string]*UpstreamConfig, newMap map[string]*UpstreamConfig) bool {
	if len(oldMap) != len(newMap) {
		return true
	}
	for name, newCfg := range newMap {
		oldCfg, ok := oldMap[name]
		if !ok || !sameUpstreamConfig(oldCfg, newCfg) {
			return true
		}
	}
	return false
}

func normalizeSingleUpstream(cfg *UpstreamConfig) bool {
	if cfg == nil {
		return false
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.APIType == "" {
		cfg.APIType = UpstreamOpenAI
	}
	if cfg.APIType == UpstreamCloudflareWorkersAI && cfg.BaseURL == "" {
		cfg.BaseURL = cloudflareDefaultBaseURL
	}
	if cfg.APIType == UpstreamCloudflareWorkersAI {
		cfg.APIKey = ""
		seen := map[string]struct{}{}
		credentials := make([]CloudflareCredential, 0, len(cfg.CloudflareCredentials))
		for _, raw := range cfg.CloudflareCredentials {
			credential, ok := normalizeCloudflareCredential(raw)
			if !ok {
				continue
			}
			if _, exists := seen[credential.ID]; exists {
				continue
			}
			seen[credential.ID] = struct{}{}
			credentials = append(credentials, credential)
		}
		cfg.CloudflareCredentials = credentials
	}
	cfg.ResponsesReasoningFormat = strings.TrimSpace(cfg.ResponsesReasoningFormat)
	if len(cfg.CustomModels) > 0 {
		cleaned := make([]string, 0, len(cfg.CustomModels))
		for _, model := range cfg.CustomModels {
			model = strings.TrimSpace(model)
			if model != "" {
				cleaned = append(cleaned, model)
			}
		}
		cfg.CustomModels = cleaned
	}
	return cfg.BaseURL != ""
}

func sortedUpstreamNames(m map[string]*UpstreamConfig) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func getUpstreamModelsEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	return base + "/models"
}

// ttfbReadCloser wraps an io.ReadCloser and logs the time-to-first-byte
// on the first Read call, then delegates all subsequent calls to the inner ReadCloser.
type ttfbReadCloser struct {
	inner      io.ReadCloser
	once       sync.Once
	start      time.Time
	upstream   string
	model      string
	clientAPI  string
	keySlot    string
	proxyLabel string
}

func (r *ttfbReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	r.once.Do(func() {
		ttfb := time.Since(r.start)
		log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s proxy=%s ttfb=%s", r.clientAPI, r.upstream, r.model, r.keySlot, r.proxyLabel, ttfb.Round(time.Millisecond))
	})
	return n, err
}

func (r *ttfbReadCloser) Close() error {
	return r.inner.Close()
}

func fetchModelsFromUpstream(name string, cfg *UpstreamConfig) ([]ModelInfo, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return []ModelInfo{}, nil
	}
	ownedBy := effectiveUpstreamName(name)
	if len(cfg.CustomModels) > 0 {
		var models []ModelInfo
		now := time.Now().Unix()
		for _, m := range cfg.CustomModels {
			models = append(models, ModelInfo{ID: m, Object: "model", Created: now, OwnedBy: ownedBy})
		}
		return models, nil
	}
	if cfg.APIType == UpstreamCloudflareWorkersAI {
		return fetchCloudflareModels(name, cfg)
	}
	endpoint := getUpstreamModelsEndpoint(cfg)
	apiKeys := getUpstreamAPIKeys(cfg)
	if len(apiKeys) == 0 {
		apiKeys = []string{""}
	}
	start := nextUpstreamAPIKeyIndex(name, len(apiKeys))
	var lastErr error
	for i := 0; i < len(apiKeys); i++ {
		apiKeyIndex := (start + i) % len(apiKeys)
		apiKey := apiKeys[apiKeyIndex]
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			if cfg.APIType == UpstreamAnthropic {
				req.Header.Set("x-api-key", apiKey)
				req.Header.Set("anthropic-version", "2023-06-01")
				req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
			} else {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var result struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil, err
			}
			var models []ModelInfo
			now := time.Now().Unix()
			for _, m := range result.Data {
				models = append(models, ModelInfo{ID: m.ID, Object: "model", Created: now, OwnedBy: ownedBy})
			}
			return models, nil
		}
		if shouldRetryUpstreamStatus(resp.StatusCode) && len(apiKeys) > 1 {
			lastErr = fmt.Errorf("models endpoint retryable status %d on key %s", resp.StatusCode, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)))
			continue
		}
		lastErr = fmt.Errorf("models endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		break
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("models endpoint request failed")
	}
	return nil, lastErr
}

// emptyCustomModelUpstreams 返回 normalize 后 custom_models 仍为空的上游名（已按名排序）。
// 仅统计 normalize 后保留下来的上游（有名字、有 BaseURL）；custom_models 是模型唯一来源，留空视为未配好。
func emptyCustomModelUpstreams(m map[string]*UpstreamConfig) []string {
	var empty []string
	for _, name := range sortedUpstreamNames(m) {
		if cfg := m[name]; cfg != nil && cfg.BaseURL != "" && len(cfg.CustomModels) == 0 {
			empty = append(empty, name)
		}
	}
	return empty
}

func effectiveUpstreamName(name string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "default"
}

func getConfiguredUpstreams() map[string]*UpstreamConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	upstreams := make(map[string]*UpstreamConfig, len(upstreamCfgs))
	for name, cfg := range upstreamCfgs {
		upstreams[name] = cloneUpstreamConfig(cfg)
	}
	return upstreams
}

func resolveUpstream(name string) (string, *UpstreamConfig) {
	configMu.RLock()
	defer configMu.RUnlock()
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		return "", nil
	}
	if cfg := cloneUpstreamConfig(upstreamCfgs[resolvedName]); cfg != nil {
		return resolvedName, cfg
	}
	return resolvedName, nil
}

func countConfiguredModels() int {
	upstreams := getConfiguredUpstreams()
	seen := map[string]struct{}{}
	for _, cfg := range upstreams {
		for _, m := range cfg.CustomModels {
			trimmed := strings.TrimSpace(m)
			if trimmed == "" {
				continue
			}
			seen[trimmed] = struct{}{}
		}
	}
	return len(seen)
}

func getAliasModelInfos() []ModelInfo {
	configMu.RLock()
	defer configMu.RUnlock()
	if len(modelAlias) == 0 {
		return []ModelInfo{}
	}
	names := make([]string, 0, len(modelAlias))
	for name := range modelAlias {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	now := time.Now().Unix()
	models := make([]ModelInfo, 0, len(names))
	for _, name := range names {
		models = append(models, ModelInfo{
			ID:      name,
			Object:  "model",
			Created: now,
			OwnedBy: "alias",
		})
	}
	return models
}

// ======================== 配置 ========================

var (
	port                 string
	configPath           = "config.json"
	cloudflareImportPath string
	cloudflareVerify     bool
	modelAlias           = map[string]ModelAlias{}

	reasoningEffortMap = map[string]string{}
	debugMode          bool
	configMu           sync.RWMutex
)

// ======================== 管理面板认证 ========================

var (
	adminPassword string
	sessions      = map[string]struct{}{}
	sessionsMu    sync.Mutex
)

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sessionsMu.Lock()
		_, ok := sessions[cookie.Value]
		sessionsMu.Unlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if adminPassword == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderLoginPage(w, "表单解析失败")
			return
		}
		if r.FormValue("password") != adminPassword {
			renderLoginPage(w, "密码错误")
			return
		}
		token, err := generateToken()
		if err != nil {
			renderLoginPage(w, "创建会话失败")
			return
		}
		sessionsMu.Lock()
		sessions[token] = struct{}{}
		sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderLoginPage(w, "")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ======================== Token 统计 ========================

type ModelStats struct {
	RequestCount     int64 `json:"request_count"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// DailyStats 单日统计，每天0点自动重置
type DailyStats struct {
	Date          string                 `json:"date"`
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
}

type TokenStatsData struct {
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
	Daily         *DailyStats            `json:"daily,omitempty"`
}

var (
	tokenStats     = &TokenStatsData{Models: map[string]*ModelStats{}, Daily: nil}
	tokenStatsMu   sync.Mutex
	tokenStatsPath = "stats.json"
	statsDate      string // 当前统计日期 YYYY-MM-DD
)

// ======================== 数据模型 ========================

type OpenAIRequest struct {
	Model               string         `json:"model"`
	Messages            []Message      `json:"messages"`
	Stream              bool           `json:"stream"`
	Temperature         *float64       `json:"temperature,omitempty"`
	MaxTokens           int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens int            `json:"max_completion_tokens,omitempty"`
	TopP                *float64       `json:"top_p,omitempty"`
	Thinking            any            `json:"thinking,omitempty"`
	ReasoningEffort     string         `json:"reasoning_effort,omitempty"`
	ExtraBody           map[string]any `json:"extra_body,omitempty"`
	StreamOptions       any            `json:"stream_options,omitempty"`
	Tools               []Tool         `json:"tools,omitempty"`
	ToolChoice          any            `json:"tool_choice,omitempty"`
}

type Message struct {
	Role             string     `json:"role,omitempty"`
	Content          any        `json:"content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string     `json:"tool_call_id,omitempty"`
	Name             string     `json:"name,omitempty"`
	ReasoningContent *string    `json:"reasoning_content,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type UpstreamType string

const (
	UpstreamOpenAI              UpstreamType = "openai"
	UpstreamAnthropic           UpstreamType = "anthropic"
	UpstreamResponses           UpstreamType = "openai-responses"
	UpstreamCloudflareWorkersAI UpstreamType = "cloudflare-workers-ai"
)

type UpstreamConfig struct {
	BaseURL                  string                 `json:"base_url"`
	APIKey                   string                 `json:"api_key"`
	APIType                  UpstreamType           `json:"api_type"`
	CustomModels             []string               `json:"custom_models,omitempty"`
	ResponsesReasoningFormat string                 `json:"responses_reasoning_format,omitempty"`
	CloudflareCredentials    []CloudflareCredential `json:"cloudflare_credentials,omitempty"`
}

// CPATranslatorConfig 控制是否用 CLIProxyAPI v7 sdk/translator 替代手写协议翻译（库式接入，灰度）。
// 全部默认 false：升级后仍走旧手写翻译路径，零行为变化；逐项打开以灰度切换。
//
//	Enabled            : 总开关，false 时其余字段全部忽略，永远走手写翻译
//	Requests           : 请求方向（入站→上游）用 CPA TranslateRequest
//	NonStreamResponses : 非流式响应方向用 CPA TranslateNonStream
//	StreamResponses    : 流式 SSE 响应方向用 CPA TranslateStream
//
// 任一方向 CPA 无可用翻译器时自动 fallback 回手写函数，无需此开关置 false。
type CPATranslatorConfig struct {
	Enabled            bool `json:"enabled,omitempty"`
	Requests           bool `json:"requests,omitempty"`
	NonStreamResponses bool `json:"non_stream_responses,omitempty"`
	StreamResponses    bool `json:"stream_responses,omitempty"`
}

// ClaudeCompatConfig 控制 Claude 入站兼容夹层（claude_compat.go）。
// 与 CPATranslatorConfig 的灰度语义不同：这两层补的是"本会被静默丢弃的内容"，属修复而非换实现，
// 因此**未配置即视为开启**（指针为 nil = true），开关只用于出问题时一键回退到旧行为。
//
//	InboundNormalize : L1 入站把 document/search_result/server-tool 结果/未知块降级为 text，thinking 补 signature
//	OutboundEnrich   : L5 出站给 thinking 签发 signature、补 usage 的 cache_* 字段
type ClaudeCompatConfig struct {
	InboundNormalize *bool `json:"inbound_normalize,omitempty"`
	OutboundEnrich   *bool `json:"outbound_enrich,omitempty"`
}

type AppConfig struct {
	ModelAlias map[string]ModelAlias `json:"model_alias"`

	ReasoningEffortMap map[string]string          `json:"reasoning_effort_map"`
	Socks5Proxies      []Socks5Proxy              `json:"socks5_proxies,omitempty"`
	Upstreams          map[string]*UpstreamConfig `json:"upstreams,omitempty"`
	CPATranslator      CPATranslatorConfig        `json:"cpa_translator,omitempty"`
	ClaudeCompat       ClaudeCompatConfig         `json:"claude_compat,omitempty"`
}

type ModelAlias struct {
	TargetModel   string `json:"target_model"`
	Upstream      string `json:"upstream,omitempty"`
	Socks5Proxy   string `json:"socks5_proxy,omitempty"`
	WithReasoning bool   `json:"with_reasoning,omitempty"`
	// ReasoningFormat 控制把 reasoning_effort 翻译成哪种上游推理方言：
	//   ""         = 默认，透传 reasoning_effort 顶层字符串
	//   "thinking"  = 注入 thinking:{type:enabled,budget_tokens:N} 对象
	// chat_template_kwargs 为预留值，本轮未实现，静默降级为默认。
	ReasoningFormat string `json:"reasoning_format,omitempty"`
	// AcceptedEfforts 限制该上游可接受的 effort 档集合；为空=不限制原值透传。
	// 非空时把入站 effort（经全局映射后）收敛到集合内语义最近档，避免越界 422（如 DeepSeek 仅 none|high|max）。
	AcceptedEfforts []string `json:"accepted_efforts,omitempty"`
}

// reasoningEffortRanks 是 effort 档的全序，用于 AcceptedEfforts 收敛与排序。
var reasoningEffortRanks = []string{"none", "low", "medium", "high", "xhigh", "max"}

// ======================== Anthropic Messages API 类型 ========================

type AnthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []AnthropicMessage `json:"messages"`
	System      any                `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Tools       []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice  any                `json:"tool_choice,omitempty"`
	Metadata    any                `json:"metadata,omitempty"`
	Thinking    any                `json:"thinking,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type AnthropicContent struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Input     any    `json:"input,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   any    `json:"content,omitempty"`
}

type AnthropicTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema"`
}

type AnthropicResponse struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Content      []AnthropicContent `json:"content"`
	Model        string             `json:"model"`
	StopReason   string             `json:"stop_reason"`
	StopSequence *string            `json:"stop_sequence"`
	Usage        *AnthropicUsage    `json:"usage,omitempty"`
}

type AnthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

// ======================== Responses API 类型 ========================

type ResponsesAPIRequest struct {
	Model             string          `json:"model"`
	Input             any             `json:"input"`
	Messages          []Message       `json:"messages,omitempty"`
	Instructions      string          `json:"instructions,omitempty"`
	Stream            bool            `json:"stream,omitempty"`
	Temperature       float64         `json:"temperature,omitempty"`
	MaxTokens         int             `json:"max_output_tokens,omitempty"`
	TopP              float64         `json:"top_p,omitempty"`
	FrequencyPenalty  float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty   float64         `json:"presence_penalty,omitempty"`
	Reasoning         ReasonEffort    `json:"reasoning,omitempty"`
	Include           []string        `json:"include,omitempty"`
	Store             *bool           `json:"store,omitempty"`
	Tools             []ResponsesTool `json:"tools,omitempty"`
	ToolChoice        any             `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	Stop              any             `json:"stop,omitempty"`
	User              string          `json:"user,omitempty"`
	StreamOptions     any             `json:"stream_options,omitempty"`
	Metadata          any             `json:"metadata,omitempty"`
}

type ResponsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Parameters  map[string]any  `json:"parameters,omitempty"`
	Function    *ToolFunction   `json:"function,omitempty"`
	Tools       []ResponsesTool `json:"tools,omitempty"`
}

type ResponseToolNameMapping struct {
	Namespace string
	Name      string
}

type ReasonEffort struct {
	Effort  string `json:"effort,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// ======================== 配置管理 ========================

func loadConfig(path string) AppConfig {
	var cfg AppConfig
	data, err := os.ReadFile(path)
	if err != nil {
		normalizeConfig(&cfg)
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("警告: 配置文件解析失败: %v", err)
	}
	normalizeConfig(&cfg)
	return cfg
}

// normalizeAcceptedEfforts 宽松规范化 AcceptedEfforts：逐项 trim/lower，丢弃不在 canonical 档序
// (none/low/medium/high/xhigh/max) 内的项，去重并按档序升序排序。全空返回 nil（=不限制）。
// 注意：用户填了内容但全为非法档名时（如 ["hgh"] 拼写错误）会降级为不限制，静默失效约束有风险，
// 故此时 log 告警提示（仍不返 400，符合宽松策略）。原 efforts 为空(nil/[]) 不告警。
func normalizeAcceptedEfforts(efforts []string) []string {
	if len(efforts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(efforts))
	out := make([]string, 0, len(efforts))
	for _, e := range efforts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if reasoningEffortRankIndex(e) < 0 {
			continue // 丢弃非法档（不在 canonical 序内）
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		log.Printf("[config] accepted_efforts 全部为非法档名（%v），约束将于运行时降级为不限制；请检查拼写，合法档：none/low/medium/high/xhigh/max", efforts)
		return nil
	}
	// 按档序排序（canonical 全序）。
	sort.Slice(out, func(i, j int) bool {
		return reasoningEffortRankIndex(out[i]) < reasoningEffortRankIndex(out[j])
	})
	return out
}

func normalizeConfig(cfg *AppConfig) {
	if cfg.ModelAlias == nil {
		cfg.ModelAlias = map[string]ModelAlias{}
	}
	for key, alias := range cfg.ModelAlias {
		trimmedKey := strings.TrimSpace(key)
		alias.TargetModel = strings.TrimSpace(alias.TargetModel)
		alias.Upstream = strings.TrimSpace(alias.Upstream)
		alias.Socks5Proxy = strings.TrimSpace(alias.Socks5Proxy)
		// ReasoningFormat 宽松校验：仅允许 ""(默认透传) 或 "thinking"；其它值（含预留 chat_template_kwargs）静默降级为 ""。
		alias.ReasoningFormat = strings.ToLower(strings.TrimSpace(alias.ReasoningFormat))
		if alias.ReasoningFormat != "thinking" {
			alias.ReasoningFormat = ""
		}
		// AcceptedEfforts 宽松校验：逐项 trim/lower，丢弃不在 6 档 canonical 序内的项，去重并按档序排序。全空留空切片(=不限制)。
		alias.AcceptedEfforts = normalizeAcceptedEfforts(alias.AcceptedEfforts)
		if trimmedKey == "" {
			delete(cfg.ModelAlias, key)
			continue
		}
		if trimmedKey != key {
			delete(cfg.ModelAlias, key)
		}
		cfg.ModelAlias[trimmedKey] = alias
	}

	if cfg.ReasoningEffortMap == nil {
		cfg.ReasoningEffortMap = map[string]string{}
	}
	normalizedProxies := make([]Socks5Proxy, 0, len(cfg.Socks5Proxies))
	proxyAddresses := make(map[string]struct{}, len(cfg.Socks5Proxies))
	for _, proxy := range cfg.Socks5Proxies {
		proxy.Addr = strings.TrimSpace(proxy.Addr)
		proxy.Name = strings.TrimSpace(proxy.Name)
		if proxy.Addr == "" {
			continue
		}
		if _, exists := proxyAddresses[proxy.Addr]; exists {
			continue
		}
		proxyAddresses[proxy.Addr] = struct{}{}
		normalizedProxies = append(normalizedProxies, proxy)
	}
	cfg.Socks5Proxies = normalizedProxies
	// 不静默清空 alias.Socks5Proxy：保留引用，交由 adminConfigHandler POST 阶段
	// 校验"孤儿代理引用"并返回 400，避免用户不知情地丢失配置。
	if cfg.Upstreams == nil {
		cfg.Upstreams = map[string]*UpstreamConfig{}
	}
	normalizedUpstreams := make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		trimmedName := strings.TrimSpace(name)
		copied := cloneUpstreamConfig(upstream)
		if trimmedName == "" || !normalizeSingleUpstream(copied) {
			continue
		}
		normalizedUpstreams[trimmedName] = copied
	}
	cfg.Upstreams = normalizedUpstreams
	if len(cfg.Upstreams) == 0 {
		return
	}
}

func saveConfig(path string, cfg AppConfig) error {
	normalizeConfig(&cfg)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func applyConfig(cfg AppConfig) bool {
	configMu.Lock()
	defer configMu.Unlock()
	if cfg.ModelAlias != nil {
		modelAlias = cfg.ModelAlias
	}

	if cfg.ReasoningEffortMap != nil {
		reasoningEffortMap = cfg.ReasoningEffortMap
	}
	upstreamsChanged := upstreamsConfigChanged(upstreamCfgs, cfg.Upstreams)
	if upstreamsChanged {
		resetCloudflarePoolState()
	}
	upstreamCfgs = make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		upstreamCfgs[name] = cloneUpstreamConfig(upstream)
	}

	socks5Mu.Lock()
	if cfg.Socks5Proxies != nil {
		socks5Proxies = cfg.Socks5Proxies
	}
	socks5Mu.Unlock()
	clearSocks5ClientCache()

	// CPA 翻译层灰度开关（与 upstreamCfgs 同属 configMu 保护）。
	cpaTranslatorCfg = cfg.CPATranslator
	claudeCompatCfg = cfg.ClaudeCompat

	return upstreamsChanged
}

// isKnownAlias 判断 model 是否为已配置且填写了 target_model 的别名。
// 严格模式下客户端 model 必须是有效别名，否则推理请求将被拒绝。
func isKnownAlias(model string) bool {
	m := strings.TrimSpace(model)
	if m == "" {
		return false
	}
	configMu.RLock()
	alias, ok := modelAlias[m]
	configMu.RUnlock()
	return ok && alias.TargetModel != ""
}

func resolveModel(model string) (string, ModelAlias, string, *UpstreamConfig) {
	m := strings.TrimSpace(model)
	alias := ModelAlias{}
	configMu.RLock()
	if found, ok := modelAlias[m]; ok {
		alias = found
	}
	configMu.RUnlock()
	if alias.TargetModel != "" {
		m = alias.TargetModel
	}
	upstreamName, upstream := resolveUpstream(alias.Upstream)
	if m == "" {
		m = strings.TrimSpace(model)
	}
	return m, alias, upstreamName, upstream
}

func getConfiguredUpstreamCount() int {
	configMu.RLock()
	defer configMu.RUnlock()
	return len(upstreamCfgs)
}

func getReasoningEffortMap() map[string]string {
	configMu.RLock()
	defer configMu.RUnlock()
	cp := make(map[string]string, len(reasoningEffortMap))
	for k, v := range reasoningEffortMap {
		cp[k] = v
	}
	return cp
}

// ======================== Token 统计 ========================

func getToday() string {
	return time.Now().Format("2006-01-02")
}

func checkAndResetDailyStats() {
	today := getToday()
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	if statsDate == "" {
		statsDate = today
		if tokenStats.Daily == nil || tokenStats.Daily.Date != today {
			tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
		}
		return
	}
	if statsDate != today {
		log.Printf("[统计] 日期变更 %s -> %s，重置每日统计", statsDate, today)
		statsDate = today
		tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
}

func loadTokenStats() {
	data, err := os.ReadFile(tokenStatsPath)
	if err != nil {
		checkAndResetDailyStats()
		return
	}
	var st TokenStatsData
	if err := json.Unmarshal(data, &st); err != nil {
		checkAndResetDailyStats()
		return
	}
	tokenStatsMu.Lock()
	if st.Models == nil {
		st.Models = map[string]*ModelStats{}
	}
	today := getToday()
	if st.Daily != nil && st.Daily.Date != today {
		log.Printf("[统计] 每日统计日期 %s 已过期，重置", st.Daily.Date)
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	} else if st.Daily == nil {
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
	statsDate = today
	tokenStats = &st
	tokenStatsMu.Unlock()
}

func saveTokenStats() {
	tokenStatsMu.Lock()
	data, err := json.MarshalIndent(tokenStats, "", "  ")
	tokenStatsMu.Unlock()
	if err != nil {
		return
	}
	os.WriteFile(tokenStatsPath, data, 0644)
}

func recordTokenUsage(model string, promptTokens, completionTokens, totalTokens int64) {
	checkAndResetDailyStats()
	tokenStatsMu.Lock()
	tokenStats.TotalRequests++
	ms, ok := tokenStats.Models[model]
	if !ok {
		ms = &ModelStats{}
		tokenStats.Models[model] = ms
	}
	ms.RequestCount++
	ms.PromptTokens += promptTokens
	ms.CompletionTokens += completionTokens
	ms.TotalTokens += totalTokens
	if tokenStats.Daily == nil {
		tokenStats.Daily = &DailyStats{Date: getToday(), Models: map[string]*ModelStats{}}
	}
	tokenStats.Daily.TotalRequests++
	dms, ok := tokenStats.Daily.Models[model]
	if !ok {
		dms = &ModelStats{}
		tokenStats.Daily.Models[model] = dms
	}
	dms.RequestCount++
	dms.PromptTokens += promptTokens
	dms.CompletionTokens += completionTokens
	dms.TotalTokens += totalTokens
	tokenStatsMu.Unlock()
	go saveTokenStats()
}

// ======================== Thinking/Reasoning 判断 ========================

func numberFromAny(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func reasoningEffortFromThinking(value any) string {
	switch v := value.(type) {
	case map[string]any:
		t, _ := v["type"].(string)
		switch strings.ToLower(t) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			if budget, ok := numberFromAny(v["budget_tokens"]); ok && budget > 0 {
				switch {
				case budget < 4000:
					return "low"
				case budget <= 16000:
					return "medium"
				default:
					return "high"
				}
			}
			return "medium"
		}
	case map[string]string:
		switch strings.ToLower(v["type"]) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			return "medium"
		}
	case bool:
		if v {
			return "medium"
		}
		return "none"
	}
	return ""
}

func ensureReasoningEffort(req *OpenAIRequest, alias ModelAlias) {
	if req == nil || req.ReasoningEffort != "" {
		return
	}
	if effort := reasoningEffortFromThinking(req.Thinking); effort != "" {
		if effort != "none" {
			req.ReasoningEffort = effort
		}
		return
	}
	if req.ExtraBody != nil {
		if effort := reasoningEffortFromThinking(req.ExtraBody["thinking"]); effort != "" {
			if effort != "none" {
				req.ReasoningEffort = effort
			}
			return
		}
	}
}

func shouldUseLegacyResponsesReasoningEffort(upstream *UpstreamConfig) bool {
	if upstream == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(upstream.ResponsesReasoningFormat))
	return v == "reasoning_effort" || v == "legacy" || v == "legacy_reasoning_effort"
}

func setResponsesReasoningEffort(req map[string]any, effort string, upstream *UpstreamConfig) {
	if effort == "" || effort == "none" {
		return
	}
	if shouldUseLegacyResponsesReasoningEffort(upstream) {
		req["reasoning_effort"] = effort
		return
	}
	req["reasoning"] = map[string]any{"effort": effort}
}

func mapConfiguredReasoningEffort(effort string) string {
	if effort == "" {
		return ""
	}
	effortMap := getReasoningEffortMap()
	if mapped, ok := effortMap[effort]; ok {
		return mapped
	}
	return effort
}

// ======================== 上游格式转换 ========================

// reasoningEffortToAnthropicThinking maps OpenAI-compatible reasoning_effort
// to Anthropic thinking with a default budget_tokens (required by Anthropic API).
func reasoningEffortToAnthropicThinking(effort string) map[string]any {
	switch strings.ToLower(effort) {
	case "low":
		return map[string]any{"type": "enabled", "budget_tokens": 4000}
	case "medium":
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	case "high":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "xhigh":
		return map[string]any{"type": "enabled", "budget_tokens": 64000}
	case "max":
		// max 是最高推理档，预算不低于 xhigh。沿用 64000（当前可用最高预算，避免臆测上游硬上限超过该值）。
		return map[string]any{"type": "enabled", "budget_tokens": 64000}
	case "adaptive":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "":
		return nil
	default:
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	}
}

// reasoningEffortRankIndex 返回 effort 在 reasoningEffortRanks 中的下标；不在其中返回 -1。
func reasoningEffortRankIndex(effort string) int {
	for i, r := range reasoningEffortRanks {
		if r == effort {
			return i
		}
	}
	return -1
}

// normalizeReasoningEffortToAlias 把入站 raw effort（未经全局映射）按 alias.AcceptedEfforts 收敛到
// canonical 档集合内语义最近的档。在 convertRequest 中调用顺序为 raw → 本函数归一化 → 全局映射，
// 故本函数接收的是归一化前的原始 effort（仅 canonical 域内做大小写/空白归一用于比较）。
//   - accepted 为空：不限制，原值返回（保持现有行为，保留大小写不破坏 reasoning_effort_map 命中）。
//   - effort 为空：原值返回。
//   - effort == "none"：特判直透，不收敛到 min（尊重客户端"禁推理"意图，即便集合不含 none）。
//   - 命中集合：返回 canonical（lower 归一后）值。
//   - 否则按 reasoningEffortRanks 全序 clamp/取最近档：低于 min 取 min、高于 max 取 max；
//     中间绝对距离最小者，距离相等取较低档（保证确定性）。accepted 若未排序/含非 canonical 档，
//     函数内部自排序并丢弃非法档，不依赖调用方已规范化。
func normalizeReasoningEffortToAlias(effort string, accepted []string) string {
	if effort == "" || len(accepted) == 0 {
		return effort // 空集/空 effort：不限制，原值返回（保持旧行为）
	}
	// 进入 canonical 收敛路径：归一大小写/空白用于档序比较与 accepted 命中。
	canonical := strings.ToLower(strings.TrimSpace(effort))
	if canonical == "none" {
		return "none"
	}
	for _, a := range accepted {
		if strings.ToLower(strings.TrimSpace(a)) == canonical {
			return canonical
		}
	}
	idx := reasoningEffortRankIndex(canonical)
	// 收集 accepted 在全序中的下标（可能未排序/含重复），按 rank 升序排序，使函数自洽不依赖调用方已规范化。
	accRanks := make([]int, 0, len(accepted))
	for _, a := range accepted {
		// 防御性 trim/lower，使函数完全自洽——即便绕过 normalizeConfig 直接传 [" HIGH "] 也能识别。
		a = strings.ToLower(strings.TrimSpace(a))
		ri := reasoningEffortRankIndex(a)
		if ri >= 0 {
			accRanks = append(accRanks, ri)
		}
	}
	if len(accRanks) == 0 {
		// accepted 全为非 canonical 档：无法收敛，原值透传。
		return canonical
	}
	sort.Ints(accRanks)
	// effort 非 none 且不在 6 档内（未知值）：客户端用了我们不认识的档名，意图显然是"要推理"，
	// 故收敛到集合内最高的"启用推理"档（排除 none|rank>0）。若 accepted 只含 none 而无启用档，
	// 不擅自禁推理——透传原值交由上游处理（可能 422，但优于静默把强推理值变成 none）。
	if idx < 0 {
		for i := len(accRanks) - 1; i >= 0; i-- {
			if accRanks[i] > 0 { // rank 0 == none
				return reasoningEffortRanks[accRanks[i]]
			}
		}
		return canonical // accepted 无启用档，透传未知原值
	}
	// clamp：低于最小档取最小档、高于最大档取最大档（accRanks 已升序，min=accRanks[0], max=末尾）。
	if idx < accRanks[0] {
		return reasoningEffortRanks[accRanks[0]]
	}
	if idx > accRanks[len(accRanks)-1] {
		return reasoningEffortRanks[accRanks[len(accRanks)-1]]
	}
	// 中间：绝对距离最小；tie 取较低档（遍历升序，第一个最小即为较低档）.
	bestRank := accRanks[0]
	bestDist := absInt(idx - bestRank)
	for _, cand := range accRanks[1:] {
		// 跳过与前一相同的 rank（去重），tie 比较天然保留首个(较低)档。
		d := absInt(idx - cand)
		if d < bestDist {
			bestDist = d
			bestRank = cand
		}
	}
	return reasoningEffortRanks[bestRank]
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// request body: prefer explicit thinking, fall back to reasoning_effort.
func buildAnthropicThinking(req map[string]any) any {
	if thinking, ok := req["thinking"]; ok {
		if tm, ok := thinking.(map[string]any); ok {
			if t, _ := tm["type"].(string); strings.EqualFold(t, "enabled") {
				if _, has := tm["budget_tokens"]; !has {
					tm["budget_tokens"] = 16000
				}
			}
			return tm
		}
		if tm, ok := thinking.(map[string]string); ok {
			switch strings.ToLower(tm["type"]) {
			case "disabled":
				return nil
			case "enabled":
				return map[string]any{"type": "enabled", "budget_tokens": 16000}
			default:
				return map[string]any{"type": tm["type"]}
			}
		}
		return thinking
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" && re != "none" {
		return reasoningEffortToAnthropicThinking(re)
	}
	return nil
}

// openAIToAnthropicRequest 将 OpenAI Chat 请求转为 Anthropic Messages 格式
func openAIToAnthropicRequest(body []byte) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}

	model, _ := req["model"].(string)
	msgs, _ := req["messages"].([]any)

	var systemTexts []string
	var anthropicMsgs []map[string]any
	handleContent := func(content any, role string) []map[string]any {
		var blocks []map[string]any
		switch c := content.(type) {
		case string:
			if c != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": c})
			}
		case []any:
			for _, item := range c {
				if p, ok := item.(map[string]any); ok {
					switch p["type"] {
					case "text":
						if t, ok := p["text"].(string); ok && t != "" {
							blocks = append(blocks, map[string]any{"type": "text", "text": t})
						}
					case "image_url":
						blocks = append(blocks, convertOpenAIImageToAnthropic(p))
					}
				}
			}
		}
		return blocks
	}

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			if s, ok := content.(string); ok {
				systemTexts = append(systemTexts, s)
			}
			continue
		}

		if role == "assistant" {
			var blocks []map[string]any

			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				blocks = append(blocks, map[string]any{"type": "thinking", "thinking": rc})
			}

			blocks = append(blocks, handleContent(content, role)...)

			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					var args any = map[string]any{}
					if rawArgs, ok := fn["arguments"]; ok && rawArgs != nil {
						switch v := rawArgs.(type) {
						case string:
							if v != "" {
								var parsed any
								if json.Unmarshal([]byte(v), &parsed) == nil {
									args = parsed
								}
							}
						default:
							b, _ := json.Marshal(v)
							var parsed any
							if json.Unmarshal(b, &parsed) == nil {
								args = parsed
							}
						}
					}
					blocks = append(blocks, map[string]any{
						"type": "tool_use", "id": id, "name": name, "input": args,
					})
				}
			}

			if len(blocks) == 0 {
				blocks = append(blocks, map[string]any{"type": "text", "text": ""})
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "assistant", "content": blocks})
			continue
		}

		if role == "tool" {
			toolCallID, _ := msg["tool_call_id"].(string)
			var resultText string
			if s, ok := content.(string); ok {
				resultText = s
			} else {
				b, _ := json.Marshal(content)
				resultText = string(b)
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "tool_result", "tool_use_id": toolCallID, "content": resultText},
				},
			})
			continue
		}

		if role == "user" {
			blocks := handleContent(content, role)
			if len(blocks) == 0 {
				continue
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "user", "content": blocks})
		}
	}

	if len(anthropicMsgs) == 0 {
		return body
	}

	anthropicReq := map[string]any{
		"model":      model,
		"messages":   anthropicMsgs,
		"max_tokens": 4096,
	}
	if len(systemTexts) > 0 {
		anthropicReq["system"] = strings.Join(systemTexts, "\n")
	}
	if stream, _ := req["stream"].(bool); stream {
		anthropicReq["stream"] = true
	}
	// Anthropic 的 temperature 取值域是 [0,1]，OpenAI 是 [0,2]——越界原样透传上游必 400，故 clamp。
	// 同时改用"字段存在"判断：旧的 !=0 会把客户端显式的 temperature:0 当作未设丢掉。
	if raw, ok := req["temperature"]; ok {
		if temp, ok := raw.(float64); ok {
			anthropicReq["temperature"] = clampUnitRange(temp)
		}
	}
	if raw, ok := req["top_p"]; ok {
		if topP, ok := raw.(float64); ok {
			anthropicReq["top_p"] = clampUnitRange(topP)
		}
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		anthropicReq["max_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		anthropicReq["tools"] = convertOpenAIToolsToAnthropic(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		switch v := tc.(type) {
		case string:
			// OpenAI: "auto", "none", "required" -> Anthropic: {type: ...}
			switch v {
			case "auto":
				anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
			case "none":
				anthropicReq["tool_choice"] = map[string]any{"type": "none"}
			case "required":
				anthropicReq["tool_choice"] = map[string]any{"type": "any"}
			default:
				anthropicReq["tool_choice"] = tc
			}
		case map[string]any:
			// OpenAI: {"type": "function", "function": {"name": "xxx"}}
			// Anthropic: {"type": "tool", "name": "xxx"}
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					anthropicReq["tool_choice"] = map[string]any{"type": "tool", "name": name}
				} else {
					anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
				}
			} else {
				anthropicReq["tool_choice"] = tc
			}
		default:
			anthropicReq["tool_choice"] = tc
		}
	}
	if t := buildAnthropicThinking(req); t != nil {
		anthropicReq["thinking"] = t
		// Anthropic 强制 budget_tokens < max_tokens。max_tokens 缺省只有 4096，而档级 budget
		// 最小 4000、medium 就到 16000——客户端没显式给 max_tokens 时这里必然 400，
		// 因此把 max_tokens 抬到 budget 之上（Anthropic 允许 max_tokens 远大于 budget）。
		if budget := anthropicThinkingBudget(t); budget > 0 {
			if cur, _ := anthropicReq["max_tokens"].(int); cur <= budget {
				anthropicReq["max_tokens"] = budget + 4096
			}
		}
	}

	result, _ := json.Marshal(anthropicReq)
	return result
}

// clampUnitRange 把采样参数收敛到 Anthropic 接受的 [0,1]。
func clampUnitRange(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// anthropicThinkingBudget 从 thinking 对象里取 budget_tokens；缺失或非数值返回 0。
func anthropicThinkingBudget(thinking any) int {
	tm, ok := thinking.(map[string]any)
	if !ok {
		return 0
	}
	switch v := tm["budget_tokens"].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func convertOpenAIImageToAnthropic(part map[string]any) map[string]any {
	imgURL, _ := part["image_url"].(map[string]any)
	if imgURL == nil {
		return part
	}
	url, _ := imgURL["url"].(string)
	if strings.HasPrefix(url, "data:") {
		parts := strings.SplitN(url, ",", 2)
		if len(parts) == 2 {
			mediaType := strings.TrimPrefix(parts[0], "data:")
			if idx := strings.Index(mediaType, ";"); idx >= 0 {
				mediaType = mediaType[:idx]
			}
			return map[string]any{
				"type": "image",
				"source": map[string]any{
					"type":       "base64",
					"media_type": mediaType,
					"data":       parts[1],
				},
			}
		}
	}
	return map[string]any{
		"type": "image",
		"source": map[string]any{
			"type": "url",
			"url":  url,
		},
	}
}

func convertOpenAIToolsToAnthropic(tools []any) []map[string]any {
	var result []map[string]any
	for _, t := range tools {
		tc, _ := t.(map[string]any)
		if tc == nil {
			continue
		}
		fn, _ := tc["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		params := fn["parameters"]
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		result = append(result, map[string]any{
			"name": name, "description": desc, "input_schema": params,
		})
	}
	return result
}

// openAIToResponsesRequest 将 OpenAI Chat 请求转为 OpenAI Responses API 格式
func openAIToResponsesRequest(body []byte, upstream *UpstreamConfig) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		log.Printf("Warning: normalizeRawMessagesToolCallArguments failed: %v", err)
	}

	msgs, _ := req["messages"].([]any)
	var instructions string
	var input []map[string]any

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			if s, ok := content.(string); ok {
				if instructions == "" {
					instructions = s
				} else {
					instructions += "\n" + s
				}
			}
			continue
		}

		if role == "assistant" {
			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				input = append(input, map[string]any{
					"type":    "reasoning",
					"summary": []any{},
					"content": []any{map[string]any{"type": "reasoning_text", "text": rc}},
				})
			}
			text := extractTextFromContentParts(content)
			if text != "" {
				input = append(input, map[string]any{
					"role":    "assistant",
					"content": text,
				})
			}
			// Responses 协议要求 function_call 作为独立 item，不能挂在 assistant 消息上
			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					args, _ := fn["arguments"].(string)
					input = append(input, map[string]any{
						"type":      "function_call",
						"call_id":   id,
						"name":      name,
						"arguments": args,
					})
				}
			}
			continue
		}

		if role == "tool" {
			// Responses 协议使用 function_call_output 而不是 role=tool 消息
			toolCallID, _ := msg["tool_call_id"].(string)
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": toolCallID,
				"output":  extractTextFromContentParts(content),
			})
			continue
		}

		// user / 其他角色
		input = append(input, map[string]any{
			"role":    role,
			"content": extractTextFromContentParts(content),
		})
	}

	respReq := map[string]any{
		"model": req["model"],
	}
	if instructions != "" {
		respReq["instructions"] = instructions
	}
	if len(input) > 0 {
		respReq["input"] = input
	}
	if stream, _ := req["stream"].(bool); stream {
		respReq["stream"] = true
	}
	if temp, _ := req["temperature"].(float64); temp != 0 {
		respReq["temperature"] = temp
	}
	if topP, _ := req["top_p"].(float64); topP != 0 {
		respReq["top_p"] = topP
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		respReq["max_output_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		respReq["tools"] = convertChatToolsToResponses(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		respReq["tool_choice"] = convertChatToolChoiceToResponses(tc)
	}
	if ptc, ok := req["parallel_tool_calls"]; ok {
		respReq["parallel_tool_calls"] = ptc
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(re), upstream)
	} else if effort := reasoningEffortFromThinking(req["thinking"]); effort != "" && effort != "none" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(effort), upstream)
	}

	result, _ := json.Marshal(respReq)
	return result
}

// convertResponsesToChat 将 OpenAI Responses API 响应转为 OpenAI Chat 格式
func convertResponsesToChat(body []byte, modelID string) []byte {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}

	totalText := ""
	totalReasoning := ""
	var toolCalls []map[string]any
	if output, ok := resp["output"].([]any); ok {
		for _, item := range output {
			if m, ok := item.(map[string]any); ok {
				switch m["type"] {
				case "reasoning":
					reasoning := ""
					if summary, ok := m["summary"].([]any); ok {
						for _, s := range summary {
							if sm, ok := s.(map[string]any); ok {
								if t, ok := sm["text"].(string); ok {
									reasoning += t
								}
							}
						}
					}
					if reasoning == "" {
						if ec, ok := m["encrypted_content"].(string); ok && ec != "" {
							reasoning = ec
						}
					}
					if reasoning != "" {
						totalReasoning += reasoning
					}
				case "message":
					if content, ok := m["content"].([]any); ok {
						for _, block := range content {
							if b, ok := block.(map[string]any); ok {
								switch b["type"] {
								case "output_text":
									if t, ok := b["text"].(string); ok {
										totalText += t
									}
								}
							}
						}
					}
				case "function_call":
					callID, _ := m["call_id"].(string)
					name, _ := m["name"].(string)
					args, _ := m["arguments"].(string)
					toolCalls = append(toolCalls, map[string]any{
						"id":   callID,
						"type": "function",
						"function": map[string]any{
							"name":      name,
							"arguments": args,
						},
					})
				}
			}
		}
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	if status, _ := resp["status"].(string); status == "incomplete" {
		finishReason = "length"
	}
	message := map[string]any{
		"role":    "assistant",
		"content": totalText,
	}
	if totalReasoning != "" {
		message["reasoning_content"] = totalReasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if resp["id"] == nil {
		resp["id"] = "resp_" + randomString(16)
	}
	if len(toolCalls) > 0 {
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
	}

	chatResp := map[string]any{
		"id":      resp["id"],
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := resp["usage"]; ok {
		chatResp["usage"] = usage
	}

	result, _ := json.Marshal(chatResp)
	return result
}

// ======================== 消息处理 ========================
// normalizeContent 是 dumb pipe 透传：保留 string 与 []any 两种入参形状
// （其它非常规类型走 json.Marshal 兜底），不解析或过滤任何 multimodal part。
// 能力协商由 opencode 客户端 + 上游负责；这里既不"硬降级"也不"补全"。
func normalizeContent(content any) any {
	if content == nil {
		return nil
	}
	if s, ok := content.(string); ok {
		return s
	}
	if arr, ok := content.([]any); ok {
		return arr
	}
	b, err := json.Marshal(content)
	if err != nil {
		return nil
	}
	return string(b)
}

func fixToolCallGaps(messages []Message) []Message {
	toolResponses := map[string]*Message{}
	for i := range messages {
		if messages[i].Role == "tool" && messages[i].ToolCallID != "" {
			toolResponses[messages[i].ToolCallID] = &messages[i]
		}
	}
	fixed := make([]Message, 0, len(messages)+len(messages)/4)
	emitted := map[string]bool{}
	for _, msg := range messages {
		if msg.Role == "tool" && msg.ToolCallID != "" {
			if emitted[msg.ToolCallID] {
				continue
			}
		}
		fixed = append(fixed, msg)
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				if resp, found := toolResponses[tc.ID]; found {
					fixed = append(fixed, *resp)
				} else {
					fixed = append(fixed, Message{Role: "tool", ToolCallID: tc.ID, Content: "Tool call result not available"})
				}
				emitted[tc.ID] = true
			}
		}
	}
	return fixed
}

// normalizeToolCallArguments 归一化 assistant tool_call 的 arguments。
// 策略（对照 CLIProxyAPI claude_openai_request.go:233-248）：能解析为 JSON object
// 则规整后透传；非 object（如 null/数字/字符串/数组）或非法 JSON 一律兜底为 "{}"，
// 绝不向调用方返回 error——避免上游本可处理却被本网关抢先 400。
// 调用方据此保证：arguments 永远是合法 JSON 字符串，且该 tool_call 永远会被发出。
func normalizeToolCallArguments(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}"
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "{}"
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return "{}"
	}
	normalized, err := json.Marshal(obj)
	if err != nil {
		return "{}"
	}
	return string(normalized)
}

func toolCallArgumentsPreview(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return truncatePreview(raw, 160)
}

func truncatePreview(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	runes := []rune(raw)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return raw
}

func messageContentPreview(content any) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return truncatePreview(v, 160)
	case []any:
		return truncatePreview(extractTextFromContentParts(v), 160)
	default:
		b, _ := json.Marshal(v)
		return truncatePreview(string(b), 160)
	}
}

func logToolCallArgumentsValidationFailure(source string, messageIndex, toolCallIndex int, toolCallID, toolName, rawArgs string, content any, err error) {
	log.Printf("[tool-call arguments invalid] source=%s message_index=%d tool_call_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q content_preview=%q err=%v",
		source,
		messageIndex,
		toolCallIndex,
		toolCallID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		messageContentPreview(content),
		err,
	)
}

func logStreamToolCallArgumentsValidationFailure(source, itemID, callID, toolName, rawArgs string, outputIndex int, err error) {
	log.Printf("[tool-call stream invalid] source=%s item_id=%q output_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q err=%v",
		source,
		itemID,
		outputIndex,
		callID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		err,
	)
}

// normalizeMessagesToolCallArguments 归一化所有 assistant 消息的 tool_call arguments。
// 不返回 error：非法/非 object 的 arguments 一律兜底为 "{}" 并记一条 warn 日志，
// 该 tool_call 仍会被正常发出——避免上游本可处理却被本网关抢先 400
// （对照 CLIProxyAPI claude_openai_request.go:233-248 的兜底策略）。
func normalizeMessagesToolCallArguments(messages []Message) []Message {
	for i := range messages {
		if messages[i].Role != "assistant" || len(messages[i].ToolCalls) == 0 {
			continue
		}
		for j := range messages[i].ToolCalls {
			raw := messages[i].ToolCalls[j].Function.Arguments
			normalized := normalizeToolCallArguments(raw)
			if normalized == "{}" && strings.TrimSpace(raw) != "" && strings.TrimSpace(raw) != "{}" {
				logToolCallArgumentsValidationFailure(
					"normalizeMessagesToolCallArguments",
					i,
					j,
					messages[i].ToolCalls[j].ID,
					messages[i].ToolCalls[j].Function.Name,
					raw,
					messages[i].Content,
					fmt.Errorf("arguments not a JSON object, fallback to {}"),
				)
			}
			messages[i].ToolCalls[j].Function.Arguments = normalized
		}
	}
	return messages
}

// normalizeRawMessagesToolCallArguments 归一化原始 map 形态 messages 里的 assistant tool_call arguments。
// 同样不返回 error：非法/非 object 一律兜底 "{}" + warn 日志，tool_call 照常发出。
func normalizeRawMessagesToolCallArguments(rawMessages any) error {
	msgs, ok := rawMessages.([]any)
	if !ok {
		return nil
	}
	for i, rawMsg := range msgs {
		msg, ok := rawMsg.(map[string]any)
		if !ok || msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "assistant" {
			continue
		}
		rawToolCalls, ok := msg["tool_calls"].([]any)
		if !ok {
			continue
		}
		for j, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok || tc == nil {
				continue
			}
			toolCallID, _ := tc["id"].(string)
			fn, ok := tc["function"].(map[string]any)
			if !ok || fn == nil {
				continue
			}
			toolName, _ := fn["name"].(string)
			var rawArgs string
			switch v := fn["arguments"].(type) {
			case string:
				rawArgs = v
			case nil:
				rawArgs = ""
			default:
				b, _ := json.Marshal(v)
				rawArgs = string(b)
			}
			normalized := normalizeToolCallArguments(rawArgs)
			if normalized == "{}" && strings.TrimSpace(rawArgs) != "" && strings.TrimSpace(rawArgs) != "{}" {
				logToolCallArgumentsValidationFailure(
					"normalizeRawMessagesToolCallArguments",
					i,
					j,
					toolCallID,
					toolName,
					rawArgs,
					msg["content"],
					fmt.Errorf("arguments not a JSON object, fallback to {}"),
				)
			}
			fn["arguments"] = normalized
		}
	}
	return nil
}

func ensureReasoningContent(messages []Message, withReasoning bool) []Message {
	// Only inject empty reasoning_content when WithReasoning is enabled (DeepSeek upstream).
	// Other upstreams don't need this and may reject the unknown field.
	if !withReasoning {
		return messages
	}
	for i := range messages {
		if messages[i].Role == "assistant" && messages[i].ReasoningContent == nil {
			empty := ""
			messages[i].ReasoningContent = &empty
		}
	}
	return messages
}

func convertMessagesForUpstream(messages []Message, withReasoning bool) []map[string]any {
	converted := make([]map[string]any, 0, len(messages))
	for _, msg := range messages {
		clean := map[string]any{}
		if msg.Role != "" {
			clean["role"] = msg.Role
		}
		content := normalizeContent(msg.Content)
		reasoningContent := msg.ReasoningContent
		// Strip x-anthropic-billing-header from system messages
		if msg.Role == "system" {
			if s, ok := content.(string); ok {
				content = strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
				if content == "" {
					continue
				}
			} else if s, ok := content.([]any); ok {
				// Handle multi-part content in system messages
				var cleaned []any
				for _, part := range s {
					p, ok := part.(map[string]any)
					if !ok {
						continue
					}
					if txt, ok := p["text"].(string); ok {
						txt = strings.TrimSpace(reBillingHeader.ReplaceAllString(txt, ""))
						if txt != "" {
							p["text"] = txt
							cleaned = append(cleaned, p)
						}
					}
				}
				if len(cleaned) == 0 {
					continue
				}
				content = cleaned
			}
		}
		shouldSendContent := content != nil
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			switch v := content.(type) {
			case string:
				shouldSendContent = strings.TrimSpace(v) != ""
			case []any:
				shouldSendContent = len(v) > 0
			}
		}
		if shouldSendContent {
			clean["content"] = content
		}
		if withReasoning && reasoningContent != nil && *reasoningContent != "" {
			clean["reasoning_content"] = *reasoningContent
		}
		if len(msg.ToolCalls) > 0 {
			clean["tool_calls"] = msg.ToolCalls
		}
		if msg.ToolCallID != "" {
			clean["tool_call_id"] = msg.ToolCallID
		}
		if msg.Name != "" {
			clean["name"] = msg.Name
		}
		converted = append(converted, clean)
	}
	return converted
}

// ======================== 完整请求转换（含 thinking/reasoning_effort/ExtraBody） ========================

func convertRequest(req *OpenAIRequest, alias ModelAlias) map[string]any {
	converted := map[string]any{
		"model":    req.Model,
		"messages": convertMessagesForUpstream(req.Messages, alias.WithReasoning),
		"stream":   req.Stream,
	}
	if req.Temperature != nil {
		converted["temperature"] = *req.Temperature
	}
	if req.MaxTokens != 0 {
		converted["max_tokens"] = req.MaxTokens
	}
	if req.MaxCompletionTokens != 0 {
		converted["max_completion_tokens"] = req.MaxCompletionTokens
	}
	// Inject stream_options.include_usage for streaming requests.
	if req.Stream {
		streamOptions := map[string]any{"include_usage": true}
		if existing, ok := req.StreamOptions.(map[string]any); ok {
			for k, v := range existing {
				streamOptions[k] = v
			}
			streamOptions["include_usage"] = true
		}
		converted["stream_options"] = streamOptions
	}
	if req.TopP != nil {
		converted["top_p"] = *req.TopP
	}
	if len(req.Tools) > 0 {
		converted["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		converted["tool_choice"] = req.ToolChoice
	}

	// thinking/reasoning_effort describe the current request and are independent
	// from withReasoning, which only controls replaying historical reasoning_content.
	// 思考对象优先级：客户端显式 thinking > ExtraBody.thinking > thinking 方言注入。
	hasThinking := false
	if req.Thinking != nil {
		converted["thinking"] = req.Thinking
		hasThinking = true
	} else if req.ExtraBody != nil {
		if thinking, ok := req.ExtraBody["thinking"]; ok && thinking != nil {
			converted["thinking"] = thinking
			hasThinking = true
		}
	}
	effort := req.ReasoningEffort
	if effort == "" && req.ExtraBody != nil {
		effort, _ = req.ExtraBody["reasoning_effort"].(string)
	}
	// effort 处理三步（顺序重要）：
	//   1) 按 alias.AcceptedEfforts 把 canonical effort 收敛到集合内最近档（AcceptedEfforts 空=不限制）.
	//   2) 再走全局 ReasoningEffortMap 把 canonical 档映射成上游可能用的 wire 值（厂商专属串）.
	// 先归一化后映射：归一化只作用于 canonical 档，映射产出 wire 值，两层不互相抵消。
	thinkingFormat := strings.ToLower(strings.TrimSpace(alias.ReasoningFormat))
	if effort != "" {
		normalized := normalizeReasoningEffortToAlias(effort, alias.AcceptedEfforts)
		// none 是明确的"禁推理"语义，绕过全局 ReasoningEffortMap——
		// 防止用户误配 map:{none→high} 把禁推理强行变成推理，违背客户端意图。
		mapped := normalized
		if normalized != "none" {
			mapped = mapConfiguredReasoningEffort(normalized)
		}
		// thinking 方言：由 effort 反推 thinking 对象注入；抑制顶层 reasoning_effort。
		// - normalized 非 none：注入 thinking{enabled,budget} 触发推理。
		// - normalized == none 且 client 未显式给 thinking：**不发 thinking 对象**。
		//   某些兼容上游不认 thinking:{type:disabled}，发送后反而会触发推理，
		//   glm 的"禁推理"= 不发 thinking 对象（缺该对象即走"不推理"默认，而非 enabled 默认）。故 none 路径保持不发思考字段。
		//   客户端显式 req.Thinking={type:disabled} 仍原样透传（客户端责任，本网关不改其意图）。
		if thinkingFormat == "thinking" {
			if !hasThinking && normalized != "" && normalized != "none" {
				converted["thinking"] = reasoningEffortToAnthropicThinking(normalized)
			}
			// 注：thinking 方言下不写 reasoning_effort（thinking 对象是替代方言，先抑制策略，端到端验证后定夺）.
		} else {
			// 非 thinking 方言：透传 reasoning_effort 给上游（含 none——DeepSeek 等用 none|high|max，
			// none 是合法禁推理档，应透传让上游明确禁推理，保持旧行为）.
			converted["reasoning_effort"] = mapped
		}
	}

	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			if k == "thinking" || k == "reasoning_effort" {
				continue
			}
			if _, exists := converted[k]; !exists {
				converted[k] = v
			}
		}
	}
	return converted
}
func buildUpstreamBody(req *OpenAIRequest, alias ModelAlias) []byte {
	converted := convertRequest(req, alias)
	b, err := json.Marshal(converted)
	if err != nil {
		log.Printf("Error marshaling upstream body: %v", err)
	}
	return b
}

// ======================== Anthropic 格式兼容 ========================

func isAnthropicFormat(body []byte) bool {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if typ, _ := obj["type"].(string); typ == "message" {
			return true
		}
	}
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start", "content_block_start", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop", "ping":
			return true
		}
		return false
	}
	return false
}

func parseAnthropicSSE(body []byte) (map[string]any, string, string, []map[string]any) {
	lines := bytes.Split(body, []byte("\n"))
	var anthropicMsg map[string]any
	var textBuilder, thinkingBuilder, currentToolInputBuilder strings.Builder
	var currentToolUse map[string]any
	var toolUseBlocks []map[string]any
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start":
			if m, ok := event["message"].(map[string]any); ok {
				anthropicMsg = m
			}
		case "content_block_start":
			if cb, ok := event["content_block"].(map[string]any); ok {
				if cbType, _ := cb["type"].(string); cbType == "tool_use" {
					currentToolUse = cb
					currentToolInputBuilder.Reset()
				}
			}
		case "content_block_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if t, ok := delta["text"].(string); ok {
					textBuilder.WriteString(t)
				}
				if dt, _ := delta["type"].(string); dt == "thinking_delta" {
					if th, ok := delta["thinking"].(string); ok {
						thinkingBuilder.WriteString(th)
					}
				}
				if dt, _ := delta["type"].(string); dt == "input_json_delta" {
					if partial, ok := delta["partial_json"].(string); ok {
						currentToolInputBuilder.WriteString(partial)
					}
				}
			}
		case "content_block_stop":
			if currentToolUse != nil {
				inputStr := currentToolInputBuilder.String()
				var input any = inputStr
				var parsed any
				if json.Unmarshal([]byte(inputStr), &parsed) == nil {
					input = parsed
				}
				currentToolUse["input"] = input
				toolUseBlocks = append(toolUseBlocks, currentToolUse)
				currentToolUse = nil
			}
		case "message_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if anthropicMsg == nil {
					anthropicMsg = map[string]any{}
				}
				if stop, ok := delta["stop_reason"].(string); ok {
					anthropicMsg["stop_reason"] = stop
				}
				if usage, ok := delta["usage"].(map[string]any); ok {
					anthropicMsg["usage"] = usage
				}
			}
		case "message_stop":
		case "error":
			return nil, "", "", nil
		}
	}
	return anthropicMsg, textBuilder.String(), thinkingBuilder.String(), toolUseBlocks
}

func buildOpenAIResponse(anthropicMsg map[string]any, text string, reasoning string, toolUseBlocks []map[string]any, modelID string) []byte {
	if anthropicMsg == nil {
		return nil
	}
	now := time.Now().Unix()
	role, _ := anthropicMsg["role"].(string)
	if role == "" {
		role = "assistant"
	}
	finishReason, _ := anthropicMsg["stop_reason"].(string)
	if finishReason == "tool_use" {
		finishReason = "tool_calls"
	} else if finishReason == "end_turn" {
		finishReason = "stop"
	} else if finishReason == "max_tokens" {
		finishReason = "length"
	}
	message := map[string]any{"role": role, "content": text}
	if reasoning != "" {
		message["reasoning_content"] = reasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if len(toolUseBlocks) > 0 {
		var toolCalls []map[string]any
		for _, tb := range toolUseBlocks {
			toolInput := tb["input"]
			argsJSON, _ := json.Marshal(toolInput)
			toolCalls = append(toolCalls, map[string]any{
				"id":   tb["id"],
				"type": "function",
				"function": map[string]any{
					"name":      tb["name"],
					"arguments": string(argsJSON),
				},
			})
		}
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
		if text == "" {
			choice["message"].(map[string]any)["content"] = nil
		}
	}
	resp := map[string]any{
		"id":      anthropicMsg["id"],
		"object":  "chat.completion",
		"created": now,
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := anthropicMsg["usage"].(map[string]any); ok {
		openAIUsage := map[string]any{}
		if v, ok := usage["input_tokens"]; ok {
			openAIUsage["prompt_tokens"] = v
		}
		if v, ok := usage["output_tokens"]; ok {
			openAIUsage["completion_tokens"] = v
		}
		if pt, ok1 := openAIUsage["prompt_tokens"]; ok1 {
			if ct, ok2 := openAIUsage["completion_tokens"]; ok2 {
				ptF, _ := pt.(float64)
				ctF, _ := ct.(float64)
				openAIUsage["total_tokens"] = int64(ptF + ctF)
			}
		}
		resp["usage"] = openAIUsage
	}
	result, _ := json.Marshal(resp)
	return result
}

func convertAnthropicMessageToOpenAI(msg map[string]any, modelID string) []byte {
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	var textBuilder strings.Builder
	var thinkingBuilder strings.Builder
	var toolUses []map[string]any
	if content, ok := msg["content"].([]any); ok {
		for _, c := range content {
			if block, ok := c.(map[string]any); ok {
				switch block["type"] {
				case "text":
					if t, ok := block["text"].(string); ok {
						textBuilder.WriteString(t)
					}
				case "thinking":
					if t, ok := block["thinking"].(string); ok {
						thinkingBuilder.WriteString(t)
					}
				case "tool_use":
					toolUses = append(toolUses, block)
				}
			}
		}
	}
	return buildOpenAIResponse(msg, textBuilder.String(), thinkingBuilder.String(), toolUses, modelID)
}

func convertAnthropicToOpenAI(body []byte, modelID string) []byte {
	var singleMsg map[string]any
	if json.Unmarshal(body, &singleMsg) == nil {
		if typ, _ := singleMsg["type"].(string); typ == "message" {
			return convertAnthropicMessageToOpenAI(singleMsg, modelID)
		}
	}
	msg, text, reasoning, toolUses := parseAnthropicSSE(body)
	if msg == nil {
		return body
	}
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	return buildOpenAIResponse(msg, text, reasoning, toolUses, modelID)
}

// ======================== 响应清理 ========================

func cleanNulls(m map[string]any) {
	for k, v := range m {
		if v == nil {
			delete(m, k)
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}

func hasNonEmptyString(value any) bool {
	s, ok := value.(string)
	return ok && s != ""
}

func normalizeReasoningContent(m map[string]any) {
	if m == nil || hasNonEmptyString(m["reasoning_content"]) {
		return
	}
	if v, ok := m["reasoning"]; ok {
		m["reasoning_content"] = v
	}
}

func cleanStreamDelta(delta map[string]any) {
	normalizeReasoningContent(delta)
	if v, ok := delta["content"]; ok && v == nil {
		delete(delta, "content")
	}
	if s, ok := delta["content"].(string); ok && s == "" {
		delete(delta, "content")
	}
	if v, ok := delta["reasoning_content"]; ok && v == nil {
		delete(delta, "reasoning_content")
	}
	if s, ok := delta["reasoning_content"].(string); ok && s == "" {
		delete(delta, "reasoning_content")
	}
	// 删除与 reasoning_content 重复的 reasoning 字段
	if rc, ok := delta["reasoning_content"].(string); ok && rc != "" {
		delete(delta, "reasoning")
	}
	if v, ok := delta["reasoning"]; ok && v == nil {
		delete(delta, "reasoning")
	}
	if s, ok := delta["reasoning"].(string); ok && s == "" {
		delete(delta, "reasoning")
	}
	if s, ok := delta["role"].(string); ok && s == "" {
		delete(delta, "role")
	}
}

// convertStreamChunkWithUsage 转换流式 chunk 并同时提取 usage，避免二次解析
func convertStreamChunkWithUsage(line string) (string, map[string]any) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
		return line, nil
	}
	if !strings.HasPrefix(line, "data: ") {
		return line, nil
	}
	data := line[6:]
	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return line, nil
	}

	// 提取 usage
	var usage map[string]any
	if u, ok := raw["usage"].(map[string]any); ok {
		usage = u
	}

	choices, ok := raw["choices"].([]any)
	if !ok || len(choices) == 0 {
		// choices 为空但有 usage 时，仍需转发给客户端
		if usage != nil {
			raw["choices"] = []any{}
			delete(raw, "cost")
			delete(raw, "service_tier")
			delete(raw, "prompt_logprobs")
			delete(raw, "prompt_token_ids")
			delete(raw, "kv_transfer_params")
			if v, ok := raw["usage"]; ok && v == nil {
				delete(raw, "usage")
			}
			converted, err := json.Marshal(raw)
			if err != nil {
				return "", usage
			}
			return "data: " + string(converted), usage
		}
		return "", usage
	}
	for i, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if delta, ok := choice["delta"].(map[string]any); ok {
			cleanStreamDelta(delta)
			choice["delta"] = delta
		}
		if msg, ok := choice["message"].(map[string]any); ok {
			normalizeReasoningContent(msg)
			cleanNulls(msg)
			choice["message"] = msg
		}
		if v, ok := choice["logprobs"]; ok && v == nil {
			delete(choice, "logprobs")
		}
		if v, ok := choice["finish_reason"]; ok && v == nil {
			delete(choice, "finish_reason")
		}
		if s, ok := choice["finish_reason"].(string); ok && s == "" {
			delete(choice, "finish_reason")
		}
		// 清理上游扩展字段
		delete(choice, "stop_reason")
		delete(choice, "token_ids")
		choices[i] = choice
	}
	raw["choices"] = choices
	if v, ok := raw["usage"]; ok && v == nil {
		delete(raw, "usage")
	}
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	converted, err := json.Marshal(raw)
	if err != nil {
		return line, usage
	}
	return "data: " + string(converted), usage
}

func convertResponse(data []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("Warning: convertResponse unmarshal failed: %v", err)
		return data, nil
	}
	if choices, ok := raw["choices"].([]any); ok {
		for i, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					normalizeReasoningContent(msg)
					// 删除与 reasoning_content 重复的 reasoning 字段
					if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
						delete(msg, "reasoning")
					}
					cleanNulls(msg)
					choice["message"] = msg
				}
				if v, ok := choice["logprobs"]; ok && v == nil {
					delete(choice, "logprobs")
				}
				// 清理上游扩展字段
				delete(choice, "stop_reason")
				delete(choice, "token_ids")
				choices[i] = choice
			}
		}
		raw["choices"] = choices
	}
	if usage, ok := raw["usage"].(map[string]any); ok {
		cleanU := map[string]any{}
		if v, ok := usage["prompt_tokens"]; ok && v != nil {
			cleanU["prompt_tokens"] = v
		}
		if v, ok := usage["completion_tokens"]; ok && v != nil {
			cleanU["completion_tokens"] = v
		}
		if v, ok := usage["total_tokens"]; ok && v != nil {
			cleanU["total_tokens"] = v
		}
		if len(cleanU) > 0 {
			raw["usage"] = cleanU
		} else {
			delete(raw, "usage")
		}
	}
	// 清理上游顶层扩展字段
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	return json.Marshal(raw)
}

// ======================== 上游端点 ========================

func getUpstreamEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	switch upstream.APIType {
	case UpstreamOpenAI:
		return base + "/chat/completions"
	case UpstreamAnthropic:
		return base + "/messages"
	case UpstreamResponses:
		return base + "/responses"
	case UpstreamCloudflareWorkersAI:
		return ""
	default:
		return base + "/chat/completions"
	}
}

func buildUpstreamRequest(endpoint, apiKey string, body []byte, upstream *UpstreamConfig) (*http.Request, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			req.Header.Set("x-api-key", apiKey)
			req.Header.Set("anthropic-version", "2023-06-01")
			req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
		} else {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func prepareOpenAIUpstreamBody(reqBody []byte, modelID string, upstream *UpstreamConfig) ([]byte, error) {
	var bodyMap map[string]any
	if err := json.Unmarshal(reqBody, &bodyMap); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}
	bodyMap["model"] = modelID
	marshaled, _ := json.Marshal(bodyMap)
	tryBody := marshaled
	if upstream != nil {
		switch upstream.APIType {
		case UpstreamAnthropic:
			tryBody = openAIToAnthropicRequest(marshaled)
		case UpstreamResponses:
			tryBody = openAIToResponsesRequest(marshaled, upstream)
		}
	}
	return tryBody, nil
}

func callPreparedUpstream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string, rawResponse ...bool) ([]byte, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}
	if upstream.APIType == UpstreamCloudflareWorkersAI {
		return callCloudflareNonStream(ctx, preparedBody, upstreamName, modelID, clientAPI, upstream, proxyAddr)
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream)
	retryDelay := 1 * time.Second
	proxyLabel := modelProxyLabel(proxyAddr)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		var c *http.Client
		c, proxyLabel = getModelHTTPClient(proxyAddr, false)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
		startTTFB := time.Now()
		resp, err := c.Do(up)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ttfb := time.Since(startTTFB)
			log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s proxy=%s ttfb=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, ttfb.Round(time.Millisecond))
			b, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, 0, nil, readErr
			}
			if len(rawResponse) > 0 && rawResponse[0] {
				// rawResponse: skip conversion, return as-is
			} else if upstream != nil && upstream.APIType == UpstreamResponses {
				b = convertResponsesToChat(b, modelID)
			} else if isAnthropicFormat(b) {
				b = convertAnthropicToOpenAI(b, modelID)
			}
			return b, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s proxy=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			manyKeys := len(apiKeys) > 1
			if manyKeys {
				// 多 key：429/5xx 时立即切到下一把 key 轮询，不退避、不等待
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				if err := waitForRetry(ctx, retryDelay); err != nil {
					return nil, 0, nil, err
				}
			}
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			if manyKeys {
				// 多 key：沿用 rotate 选定的 key，不重新按游标选（保留 429 切 key 的意图）
				apiKeys = getUpstreamAPIKeys(upstream)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
				retryDelay = nextRetryDelay(retryDelay)
			}
			if manyKeys {
				retryDelay = 1 * time.Second
			}
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error: %s", string(errBody))
	}
}

func callUpstream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string, rawResponse ...bool) ([]byte, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream, proxyAddr, rawResponse...)
}

func callPreparedUpstreamStream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}
	if upstream.APIType == UpstreamCloudflareWorkersAI {
		return callCloudflareStream(ctx, preparedBody, upstreamName, modelID, clientAPI, upstream, proxyAddr)
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream)
	retryDelay := 1 * time.Second
	proxyLabel := modelProxyLabel(proxyAddr)
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		var c *http.Client
		c, proxyLabel = getModelHTTPClient(proxyAddr, true)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s proxy=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel)
		startTTFB := time.Now()
		resp, err := c.Do(up)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay); err != nil {
				return nil, 0, nil, err
			}
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			wrappedBody := &ttfbReadCloser{
				inner:      resp.Body,
				start:      startTTFB,
				upstream:   effectiveUpstreamName(upstreamName),
				model:      modelID,
				clientAPI:  clientAPI,
				keySlot:    formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)),
				proxyLabel: proxyLabel,
			}
			return wrappedBody, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s proxy=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), proxyLabel, resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			manyKeys := len(apiKeys) > 1
			if manyKeys {
				// 多 key：429/5xx 时立即切到下一把 key 轮询，不退避、不等待
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				if err := waitForRetry(ctx, retryDelay); err != nil {
					return nil, 0, nil, err
				}
			}
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			if manyKeys {
				// 多 key：沿用 rotate 选定的 key，不重新按游标选（保留 429 切 key 的意图）
				apiKeys = getUpstreamAPIKeys(upstream)
			} else {
				// 单 key：按指数退避，下一轮用更长的退避等待
				apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
				retryDelay = nextRetryDelay(retryDelay)
			}
			if manyKeys {
				retryDelay = 1 * time.Second
			}
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error")
	}
}

func callUpstreamStream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstreamStream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream, proxyAddr)
}

func stripBillingHeaderText(s string) string {
	return strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
}

func stripBillingHeaderFromResponsesItems(items any) {
	arr, ok := items.([]any)
	if !ok {
		return
	}
	for _, item := range arr {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "system" && role != "developer" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = stripBillingHeaderText(content)
		case []any:
			for _, part := range content {
				pm, ok := part.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := pm["text"].(string); ok {
					pm["text"] = stripBillingHeaderText(text)
				}
			}
		}
	}
}

func ensureResponsesIncludeUsage(req map[string]any) {
	stream, _ := req["stream"].(bool)
	if !stream {
		return
	}
	if so, ok := req["stream_options"].(map[string]any); ok {
		so["include_usage"] = true
		req["stream_options"] = so
		return
	}
	req["stream_options"] = map[string]any{"include_usage": true}
}

// prepareAnthropicPassthroughBody 在 Anthropic↔Anthropic 同协议直通时规范化原 body（仅改 model、归一 tool args）。
// 它有意 bypass alias 推理方言/effort 归一化：同协议直通时客户端 thinking 对象已在上游协议原生字段内透传，
// 应用 convertRequest 的 thinking 注入/easoning_effort 收敛会破坏协议语义，故不在直通路径处理推理参数。
func prepareAnthropicPassthroughBody(body []byte, modelID string) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	return json.Marshal(req)
}

func proxyAnthropicPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	var inputTokens, outputTokens, cacheCreationInputTokens, cacheReadInputTokens float64
	recordedUsage := false

	updateAnthropicUsage := func(usage map[string]any) {
		if usage == nil {
			return
		}
		if v, ok := getFloat(usage, "input_tokens"); ok && v > 0 {
			inputTokens = v
		}
		if v, ok := getFloat(usage, "cache_creation_input_tokens"); ok && v > 0 {
			cacheCreationInputTokens = v
		}
		if v, ok := getFloat(usage, "cache_read_input_tokens"); ok && v > 0 {
			cacheReadInputTokens = v
		}
		if v, ok := getFloat(usage, "output_tokens"); ok && v >= 0 {
			outputTokens = v
		}
	}

	recordAnthropicUsage := func() {
		if recordedUsage {
			return
		}
		promptTokens := inputTokens + cacheCreationInputTokens + cacheReadInputTokens
		totalTokens := promptTokens + outputTokens
		if totalTokens <= 0 {
			return
		}
		recordedUsage = true
		recordTokenUsage(model, int64(promptTokens), int64(outputTokens), int64(totalTokens))
	}
	defer func() {
		// If the stream ended after message_delta but before message_stop, still
		// keep the gateway stats consistent. Claude Code receives the raw stream;
		// this only affects this gateway's admin stats.
		if outputTokens > 0 {
			recordAnthropicUsage()
		}
	}()

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if data != "" && data != "[DONE]" {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						switch currentEvent {
						case "message_start":
							if msg, ok := payload["message"].(map[string]any); ok {
								if usage, ok := msg["usage"].(map[string]any); ok {
									updateAnthropicUsage(usage)
								}
							}
						case "message_delta":
							if usage, ok := payload["usage"].(map[string]any); ok {
								updateAnthropicUsage(usage)
							}
						case "message_stop":
							recordAnthropicUsage()
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// prepareResponsesPassthroughBody 在 Responses↔Responses 同协议直通时规范化原 body
// （改 model、归一 tool args、剥离 billing 头、保证 stream usage）。
// 有意 bypass alias.ReasoningFormat / AcceptedEfforts / 全局 effort map：同协议直通时客户端
// Responses 的 reasoning.effort 已在协议原生字段内透传，应用 convertRequest 归一化/注入会破坏协议语义。
// alias 参数已传入但本路径不消费——留作未来按需在直通层做 effort 收敛的扩展点（当前 deepseek 等走
// 非 Responses 直通不触发本路径，直通 effort 越界风险为有意接受的边界）。
func prepareResponsesPassthroughBody(body []byte, modelID string, alias ModelAlias) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	if instructions, ok := req["instructions"].(string); ok {
		req["instructions"] = stripBillingHeaderText(instructions)
	}
	stripBillingHeaderFromResponsesItems(req["input"])
	stripBillingHeaderFromResponsesItems(req["messages"])
	ensureResponsesIncludeUsage(req)

	return json.Marshal(req)
}

func proxyResponsesPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if data != "" && data != "[DONE]" && (currentEvent == "response.completed" || currentEvent == "response.incomplete") {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						if u := extractResponsesUsage(payload); u != nil {
							recordUsageMap(model, u)
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func extractResponsesUsage(payload map[string]any) map[string]any {
	if u, ok := payload["usage"].(map[string]any); ok {
		return u
	}
	if resp, ok := payload["response"].(map[string]any); ok {
		if u, ok := resp["usage"].(map[string]any); ok {
			return u
		}
	}
	return nil
}

func recordUsageMap(model string, u map[string]any) {
	pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
	ct, _ := getFloat(u, "completion_tokens", "output_tokens")
	tt, _ := getFloat(u, "total_tokens")
	if tt == 0 && pt+ct > 0 {
		tt = pt + ct
	}
	if tt > 0 {
		recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
	}
}

func responsesUsageToChatUsage(u map[string]any) map[string]any {
	if u == nil {
		return nil
	}
	pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
	ct, _ := getFloat(u, "completion_tokens", "output_tokens")
	tt, _ := getFloat(u, "total_tokens")
	if tt == 0 && pt+ct > 0 {
		tt = pt + ct
	}
	return map[string]any{
		"prompt_tokens":     int64(pt),
		"completion_tokens": int64(ct),
		"total_tokens":      int64(tt),
	}
}

func responsesStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, recordUsage bool) {
	defer respBody.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)
	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	currentEvent := ""
	roleSent := false
	doneSent := false
	hasToolCalls := false
	toolIndexes := map[string]int{}
	nextToolIndex := 0

	emit := func(delta map[string]any, finishReason any, usage map[string]any) {
		if !roleSent {
			chunk := map[string]any{
				"id":      chunkID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
			}
			b, _ := json.Marshal(chunk)
			w.Write([]byte("data: " + string(b) + "\n\n"))
			roleSent = true
		}
		if delta == nil {
			delta = map[string]any{}
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finishReason}},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		b, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(b) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	getToolIndex := func(item map[string]any) int {
		id, _ := item["id"].(string)
		if id == "" {
			id, _ = item["call_id"].(string)
		}
		if id == "" {
			id = fmt.Sprintf("tool_%d", nextToolIndex)
		}
		if idx, ok := toolIndexes[id]; ok {
			return idx
		}
		idx := nextToolIndex
		toolIndexes[id] = idx
		nextToolIndex++
		return idx
	}

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			} else if strings.HasPrefix(trimmed, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if data == "[DONE]" {
					doneSent = true
					break
				}
				if data != "" {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						eventType, _ := payload["type"].(string)
						if eventType == "" {
							eventType = currentEvent
						}
						switch eventType {
						case "response.output_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"content": text}, nil, nil)
							}
						case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"reasoning_content": text}, nil, nil)
							}
						case "response.output_item.added":
							if item, ok := payload["item"].(map[string]any); ok {
								if typ, _ := item["type"].(string); typ == "function_call" {
									idx := getToolIndex(item)
									callID, _ := item["call_id"].(string)
									if callID == "" {
										callID, _ = item["id"].(string)
									}
									name, _ := item["name"].(string)
									hasToolCalls = true
									emit(map[string]any{"tool_calls": []map[string]any{{
										"index": float64(idx),
										"id":    callID,
										"type":  "function",
										"function": map[string]any{
											"name":      name,
											"arguments": "",
										},
									}}}, nil, nil)
								}
							}
						case "response.function_call_arguments.delta":
							itemID, _ := payload["item_id"].(string)
							if itemID == "" {
								itemID, _ = payload["call_id"].(string)
							}
							idx, ok := toolIndexes[itemID]
							if !ok {
								idx = nextToolIndex
								toolIndexes[itemID] = idx
								nextToolIndex++
							}
							if delta, _ := payload["delta"].(string); delta != "" {
								emit(map[string]any{"tool_calls": []map[string]any{{
									"index":    float64(idx),
									"function": map[string]any{"arguments": delta},
								}}}, nil, nil)
							}
						case "response.completed", "response.incomplete":
							usage := responsesUsageToChatUsage(extractResponsesUsage(payload))
							if recordUsage && usage != nil {
								recordUsageMap(model, usage)
							}
							finishReason := "stop"
							if hasToolCalls {
								finishReason = "tool_calls"
							}
							if eventType == "response.incomplete" {
								finishReason = "length"
							}
							emit(map[string]any{}, finishReason, usage)
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	if !doneSent {
		w.Write([]byte("data: [DONE]\n\n"))
	}
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== 安全响应头过滤 ========================

var safeResponseHeaders = map[string]bool{
	"Content-Type":          true,
	"Retry-After":           true,
	"RateLimit-Limit":       true,
	"RateLimit-Remaining":   true,
	"RateLimit-Reset":       true,
	"X-RateLimit-Limit":     true,
	"X-RateLimit-Remaining": true,
	"X-RateLimit-Reset":     true,
}

func filterResponseHeaders(h http.Header) http.Header {
	filtered := make(http.Header)
	for k, v := range h {
		if safeResponseHeaders[k] {
			filtered[k] = v
		}
	}
	return filtered
}

func copyFilteredResponseHeaders(dst http.Header, src http.Header) {
	for k, values := range filterResponseHeaders(src) {
		dst.Del(k)
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func normalizeUpstreamStatus(status int) int {
	if status < 100 || status > 999 {
		return http.StatusBadGateway
	}
	return status
}

func applyUpstreamErrorHeaders(w http.ResponseWriter, upstreamHeaders http.Header, status int) int {
	status = normalizeUpstreamStatus(status)
	copyFilteredResponseHeaders(w.Header(), upstreamHeaders)
	w.Header().Set("X-Upstream-Status", strconv.Itoa(status))
	if status == http.StatusTooManyRequests {
		w.Header().Set("X-Upstream-Rate-Limited", "true")
	}
	return status
}

// mapUpstreamErrorBody converts upstream error responses to standard OpenAI format
func mapUpstreamErrorBody(body []byte, upstreamType UpstreamType) []byte {
	if len(body) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		for _, line := range bytes.Split(trimmed, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			trimmed = payload
			break
		}
	}
	var parsed map[string]any
	if json.Unmarshal(trimmed, &parsed) != nil {
		return trimmed
	}
	// Already has OpenAI-format error
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if _, hasMsg := errObj["message"]; hasMsg {
			return trimmed
		}
	}
	// Anthropic: { "error": { "type": "...", "message": "..." } }
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			b, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"message": msg,
					"type":    errObj["type"],
				},
			})
			return b
		}
	}
	// Top-level message
	if msg, ok := parsed["message"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
				"type":    parsed["type"],
				"code":    parsed["type"],
			},
		})
		return b
	}
	// msg field
	if msg, ok := parsed["msg"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
			},
		})
		return b
	}
	return trimmed
}

// ======================== Chat Completions Handler ========================

func chatCompletionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/chat/completions\n%s", cnt, string(body))
	}

	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(req.Model)
	if !isKnownAlias(req.Model) {
		http.Error(w, `{"error":{"message":"model not found; only configured aliases are accepted","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	req.Model = resolvedModel
	if req.Model == "" {
		http.Error(w, `{"error":"model is required"}`, http.StatusBadRequest)
		return
	}

	// 多模态路由：检测到图片时转发到配置的上游

	req.Messages = fixToolCallGaps(req.Messages)
	// arguments 非法/非 object 已在归一化层兜底为 "{}"，不再因 tool_call 格式回 400。
	req.Messages = normalizeMessagesToolCallArguments(req.Messages)
	ensureReasoningEffort(&req, modelAliasInfo)
	req.Messages = ensureReasoningContent(req.Messages, modelAliasInfo.WithReasoning)

	// CPA 翻译层（库式灰度）：开关开时用 CPA TranslateRequest 替代手写 buildUpstreamBody，
	// CPAGet 路径用 callPreparedUpstream(Stream) 直发翻译体跳过二次 prepare，响应走 cpaTranslateNonStream。
	// 开关关或该方向 CPA 无翻译器时整条回退手写路径（route==nil），行为与旧版完全一致。
	cpaEnabled := cpaRequestsEnabled()
	var cpaRoute *cpaTranslationRoute
	upstreamBody := buildUpstreamBody(&req, modelAliasInfo) // 默认手写（灰度关 / fallback 兜底）
	if cpaEnabled {
		clientFmt := cpaClientFormat("chat")
		upstreamFmt := formatForUpstream(upstream)
		canonicalEffort := req.ReasoningEffort
		clientThinking := req.Thinking
		if clientThinking == nil && req.ExtraBody != nil {
			clientThinking = req.ExtraBody["thinking"]
		}
		// fallback=手写路径（确保 CPA 无翻译方向时退回项目手写，语义与旧版一致）。
		fb := func([]byte) ([]byte, error) {
			return buildUpstreamBody(&req, modelAliasInfo), nil
		}
		route, translated, terr := cpaTranslateRequest(r.Context(), clientFmt, upstreamFmt, req.Model, body, req.Stream, fb)
		if terr == nil && route != nil {
			cpaRoute = route
			upstreamBody = patchCPARequestForAlias(translated, canonicalEffort, clientThinking, modelAliasInfo, upstreamFmt)
		}
		// route==nil：CPA 无该方向翻译器（如 Chat→Responses），upstreamBody 维持上面手写 buildUpstreamBody 结果。
	}

	if req.Stream {
		// CPA 路径直发翻译体（跳过 callUpstreamStream 内二次 prepare；流式响应翻译 glue 待阶段3，暂仍走原手写 stream 分派）
		var upResp io.ReadCloser
		var status int
		var upHeader http.Header
		var err error
		if cpaRoute != nil {
			upResp, status, upHeader, err = callPreparedUpstreamStream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy)
		} else {
			upResp, status, upHeader, err = callUpstreamStream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy)
		}
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
			return
		}
		defer upResp.Close()
		// 如果上游是 Anthropic，需要将 Anthropic SSE 流转为 OpenAI Chat SSE 格式
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			anthropicStreamToChatHandler(w, upResp, req.Model)
			return
		}
		if upstream != nil && upstream.APIType == UpstreamResponses {
			responsesStreamToChatHandler(w, upResp, req.Model, true)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		reader := bufio.NewReader(upResp)
		doneSeen := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				if r.Context().Err() != nil {
					log.Printf("[client disconnect] api=chat upstream=%s model=%s while reading stream", effectiveUpstreamName(upstreamName), req.Model)
					return
				}
				log.Printf("[upstream stream read error] api=chat upstream=%s model=%s error=%v", effectiveUpstreamName(upstreamName), req.Model, err)
				// OpenAI-compatible clients require error to be an object. The
				// stream has already started, so fail in-band without replaying it.
				w.Write([]byte("data: {\"error\":{\"message\":\"upstream stream read error\",\"type\":\"upstream_error\"}}\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}
			if doneSeen {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "data: [DONE]" {
				doneSeen = true
				w.Write([]byte("data: [DONE]\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				continue
			}

			out, usage := convertStreamChunkWithUsage(line)
			if out == "" {
				// 空choices chunk，但可能有 usage
				if usage != nil {
					pt, _ := usage["prompt_tokens"].(float64)
					ct, _ := usage["completion_tokens"].(float64)
					tt, _ := usage["total_tokens"].(float64)
					if tt > 0 {
						recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
					}
				}
				continue
			}

			// 提取 usage（已在 convertStreamChunkWithUsage 中解析）
			if usage != nil && !doneSeen {
				pt, _ := usage["prompt_tokens"].(float64)
				ct, _ := usage["completion_tokens"].(float64)
				tt, _ := usage["total_tokens"].(float64)
				if tt > 0 {
					recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
				}
			}

			w.Write([]byte(out))
			w.Write([]byte("\n\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return
	}

	// CPA 路径用 callPreparedUpstream 直发翻译体并拿 raw 响应（跳过 callUpstream 内二次 prepare
	// 与 convertResponse/convertResponsesToChat/convertAnthropicToOpenAI 的提前转换）。
	var respBody []byte
	var status int
	var upHeader http.Header
	if cpaRoute != nil {
		respBody, status, upHeader, err = callPreparedUpstream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy, true)
	} else {
		respBody, status, upHeader, err = callUpstream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream, modelAliasInfo.Socks5Proxy)
	}
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
		}
		return
	}
	// 响应翻译：
	//   - cpaRoute!=nil 时 respBody 是 raw 上游响应（callPreparedUpstream raw=true），需按上游格式翻回 Chat。
	//     CPA 响应翻译在质量够好方向（cpaResponseUsableForRoute）且开关开时用；否则手写 handwrittenResponseToChat。
	//   - cpaRoute==nil 时 respBody 已是 callUpstream 二次转换后的 Chat，仅做 convertResponse 清洗。
	outBody := respBody
	if cpaRoute != nil {
		upstreamFmt := formatForUpstream(upstream)
		if cpaNonStreamEnabled() && cpaResponseUsableForRoute(cpaRoute, false) {
			outBody = cpaTranslateNonStream(r.Context(), cpaRoute, respBody, func(b []byte) []byte {
				return handwrittenResponseToChat(b, req.Model, upstreamFmt)
			})
		} else {
			outBody = handwrittenResponseToChat(respBody, req.Model, upstreamFmt)
		}
	} else {
		convertedResp, err := convertResponse(respBody)
		if err == nil {
			outBody = convertedResp
		}
	}
	// Record token usage（在最终客户端格式输出端记一次）
	var usageResp2 map[string]any
	if json.Unmarshal(outBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt == 0 && pt+ct > 0 {
				tt = pt + ct
			}
			if tt > 0 {
				recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(outBody)
}

// ======================== Models Handler ========================

func listModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	models := getAliasModelInfos()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   models,
	})
}

// ======================== Anthropic Messages API ========================

func extractAnthropicSystemText(system any) string {
	if system == nil {
		return ""
	}
	switch v := system.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if block, ok := item.(map[string]any); ok {
				if block["type"] == "text" {
					if text, ok := block["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func cleanJSONSchema(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema
	}
	delete(m, "$schema")
	delete(m, "title")
	delete(m, "examples")
	delete(m, "additionalProperties")
	if m["type"] == "string" {
		delete(m, "format")
	}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			m[k] = cleanJSONSchema(sub)
		}
		if arr, ok := v.([]any); ok {
			for i, elem := range arr {
				if sub, ok := elem.(map[string]any); ok {
					arr[i] = cleanJSONSchema(sub)
				}
			}
			m[k] = arr
		}
	}
	return m
}

func anthropicToOpenAIMessages(anthropicMsgs []AnthropicMessage, system any) []Message {
	var messages []Message
	if sysText := extractAnthropicSystemText(system); sysText != "" {
		messages = append(messages, Message{Role: "system", Content: sysText})
	}
	for _, msg := range anthropicMsgs {
		switch content := msg.Content.(type) {
		case string:
			messages = append(messages, Message{Role: msg.Role, Content: content})
		case []any:
			var textParts []string
			var reasoningParts []string
			var toolCalls []ToolCall
			var toolResults []Message
			var imageParts []map[string]any
			for _, item := range content {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				blockType, _ := block["type"].(string)
				switch blockType {
				case "text":
					if text, ok := block["text"].(string); ok && text != "" {
						textParts = append(textParts, text)
					}
				case "image":
					source, _ := block["source"].(map[string]any)
					if source != nil {
						srcType, _ := source["type"].(string)
						mediaType, _ := source["media_type"].(string)
						data, _ := source["data"].(string)
						if srcType == "base64" && data != "" {
							if mediaType == "" {
								mediaType = "image/png"
							}
							imageParts = append(imageParts, map[string]any{
								"type": "image_url",
								"image_url": map[string]string{
									"url": "data:" + mediaType + ";base64," + data,
								},
							})
						} else if srcType == "url" {
							if url, ok := source["url"].(string); ok && url != "" {
								imageParts = append(imageParts, map[string]any{
									"type": "image_url",
									"image_url": map[string]string{
										"url": url,
									},
								})
							}
						}
					}
				case "thinking":
					if thinking, ok := block["thinking"].(string); ok && thinking != "" {
						reasoningParts = append(reasoningParts, thinking)
					}
				case "tool_use":
					id, _ := block["id"].(string)
					name, _ := block["name"].(string)
					var args string
					switch input := block["input"].(type) {
					case string:
						args = input
					default:
						if input != nil {
							b, _ := json.Marshal(input)
							args = string(b)
						}
					}
					if args == "" {
						args = "{}"
					}
					toolCalls = append(toolCalls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: args,
						},
					})
				case "tool_result":
					toolUseID, _ := block["tool_use_id"].(string)
					// 非文本子块（image/document/search_result/未知块）也要让模型看见，
					// 不能只取 text 子块把成功结果吞成空 tool message。语义与 CPA 路径一致，
					// 见 claude_compat.go 的 claudeToolResultContentToText。
					var resultText string
					switch c := block["content"].(type) {
					case string:
						resultText = c
					case []any:
						resultText = claudeToolResultContentToText(c)
					default:
						if c != nil {
							b, _ := json.Marshal(c)
							resultText = string(b)
						}
					}
					toolResults = append(toolResults, Message{
						Role:       "tool",
						ToolCallID: toolUseID,
						Content:    resultText,
					})
				}
			}
			om := Message{Role: msg.Role}
			if len(imageParts) > 0 {
				var contentArr []any
				for _, img := range imageParts {
					contentArr = append(contentArr, img)
				}
				if len(textParts) > 0 {
					contentArr = append(contentArr, map[string]any{
						"type": "text",
						"text": strings.Join(textParts, "\n"),
					})
				}
				om.Content = contentArr
			} else if len(textParts) > 0 {
				om.Content = strings.Join(textParts, "\n")
			} else if len(toolCalls) == 0 {
				om.Content = ""
			}
			if len(reasoningParts) > 0 {
				rc := strings.Join(reasoningParts, "\n")
				om.ReasoningContent = &rc
			}
			if len(toolCalls) > 0 {
				om.ToolCalls = toolCalls
			}
			messages = append(messages, om)
			messages = append(messages, toolResults...)
		default:
			b, _ := json.Marshal(content)
			messages = append(messages, Message{Role: msg.Role, Content: string(b)})
		}
	}
	return messages
}

func anthropicToOpenAITools(anthropicTools []AnthropicTool) []Tool {
	tools := make([]Tool, 0, len(anthropicTools))
	for _, ct := range anthropicTools {
		params := ct.InputSchema
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		params = cleanJSONSchema(params)
		paramsMap, ok := params.(map[string]any)
		if !ok {
			// 非对象类型（如数组、字符串）的 input_schema 退化为空对象
			paramsMap = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		tools = append(tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        ct.Name,
				Description: ct.Description,
				Parameters:  paramsMap,
			},
		})
	}
	return tools
}

func convertAnthropicToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		// Anthropic 也允许字符串，但标准是对象；直接透传
		return v
	case map[string]any:
		t, _ := v["type"].(string)
		switch t {
		case "auto", "none":
			return t
		case "any":
			// Anthropic any -> OpenAI required
			return "required"
		case "tool":
			name, _ := v["name"].(string)
			if name == "" {
				return "auto"
			}
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		default:
			return choice
		}
	default:
		return choice
	}
}

func buildAnthropicErrorBody(errorType, message string) []byte {
	if strings.TrimSpace(errorType) == "" {
		errorType = "api_error"
	}
	if strings.TrimSpace(message) == "" {
		message = "upstream error"
	}
	b, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errorType,
			"message": message,
		},
	})
	return b
}

func upstreamErrorToAnthropic(errObj any, fallback string) (string, string) {
	errType := "api_error"
	msg := fallback
	if m, ok := errObj.(map[string]any); ok {
		if s, ok := m["type"].(string); ok && strings.TrimSpace(s) != "" {
			errType = s
		}
		if s, ok := m["message"].(string); ok && strings.TrimSpace(s) != "" {
			msg = s
		}
		if code, ok := m["code"]; ok && code != nil {
			msg = fmt.Sprintf("%s (upstream code: %v)", msg, code)
		}
	} else if s, ok := errObj.(string); ok && strings.TrimSpace(s) != "" {
		msg = s
	}
	if strings.TrimSpace(msg) == "" {
		msg = "upstream error"
	}
	return errType, msg
}

func openAIToAnthropicResponse(chatBody []byte, model string) ([]byte, bool) {
	var raw map[string]any
	if err := json.Unmarshal(chatBody, &raw); err == nil {
		if errObj, ok := raw["error"]; ok {
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream returned error")
			log.Printf("Warning: upstream returned error object: type=%s message=%s", errType, msg)
			return buildAnthropicErrorBody(errType, msg), false
		}
	}

	var chat struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
		Choices []struct {
			Message struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: openAIToAnthropicResponse unmarshal failed: %v", err)
		return buildAnthropicErrorBody("api_error", "upstream returned invalid JSON: "+err.Error()), false
	}
	if len(chat.Choices) == 0 {
		preview := truncatePreview(string(chatBody), 500)
		log.Printf("Warning: upstream returned chat completion without choices: %s", preview)
		return buildAnthropicErrorBody("api_error", "upstream returned chat completion without choices"), false
	}

	content := []AnthropicContent{}
	stopReason := "end_turn"

	msg := chat.Choices[0].Message
	fr := chat.Choices[0].FinishReason
	reasoning := msg.ReasoningContent
	if reasoning == "" {
		reasoning = msg.Reasoning
	}
	if reasoning != "" {
		content = append(content, AnthropicContent{
			Type:     "thinking",
			Thinking: reasoning,
		})
	}
	if msg.Content != "" {
		content = append(content, AnthropicContent{
			Type: "text",
			Text: msg.Content,
		})
	}
	for _, tc := range msg.ToolCalls {
		var input any
		json.Unmarshal([]byte(tc.Function.Arguments), &input)
		if input == nil {
			input = map[string]any{}
		}
		content = append(content, AnthropicContent{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: input,
		})
	}
	switch fr {
	case "stop":
		stopReason = "end_turn"
	case "length":
		stopReason = "max_tokens"
	case "tool_calls", "function_call":
		stopReason = "tool_use"
	}

	if len(content) == 0 {
		log.Printf("Warning: upstream returned empty assistant message for model %s", model)
		return buildAnthropicErrorBody("api_error", "upstream returned empty assistant message"), false
	}

	resp := AnthropicResponse{
		ID:           fmt.Sprintf("msg_%s", randomString(24)),
		Type:         "message",
		Role:         "assistant",
		Content:      content,
		Model:        model,
		StopReason:   stopReason,
		StopSequence: nil,
	}
	if chat.Usage != nil {
		inputTokens, _ := getFloat(chat.Usage, "input_tokens", "prompt_tokens")
		outputTokens, _ := getFloat(chat.Usage, "output_tokens", "completion_tokens")
		// 与流式路径（见 anthropicStreamHandler 末段）共用 splitOpenAIInputWithCache：OpenAI 的
		// prompt_tokens 含缓存命中部分，Anthropic 把缓存读取单列。拆出来后 input_tokens 与
		// cache_read_input_tokens 之和仍等于上游口径，客户端的缓存统计不再恒为空（PR#2 review comment 2）。
		inputTokensInt, cacheReadInt := splitOpenAIInputWithCache(
			int(toFloat64(inputTokens)),
			int(toFloat64(extractOpenAICachedTokens(chat.Usage))),
		)
		resp.Usage = &AnthropicUsage{
			InputTokens:              inputTokensInt,
			OutputTokens:             int(toFloat64(outputTokens)),
			CacheCreationInputTokens: 0, // Chat 上游无 cache creation 量；缺省补 0 与官方协议一致
			CacheReadInputTokens:     cacheReadInt,
		}
	}
	result, _ := json.Marshal(resp)
	return result, true
}

// extractOpenAICachedTokens 取出 OpenAI usage 里 prompt_tokens_details.cached_tokens，
// 即上游口径中属于"缓存命中"的输入量。缺失或非法时返回 0。非流式转换与流式末段共用同一口径。
func extractOpenAICachedTokens(usage map[string]any) float64 {
	if usage == nil {
		return 0
	}
	details, ok := usage["prompt_tokens_details"].(map[string]any)
	if !ok {
		return 0
	}
	if v, ok := details["cached_tokens"]; ok {
		return toFloat64(v)
	}
	return 0
}

// splitOpenAIInputWithCache 把 OpenAI 口径的 (inputTokens, cachedTokens) 拆解成 Anthropic 口径：
// prompt_tokens 含缓存命中部分，Anthropic 把缓存读取单列，故 input_tokens 要扣除 cachedTokens。
// 非法/负的 cachedTokens 一律按 0 处理；cached 超过 input 的异常口径下把 cached 钳回 input、
// input 钳到 0（不留负数）。非流式与流式两条路径共用同一算法，避免两处各写一遍出现口径漂移。
func splitOpenAIInputWithCache(inputTokens, cachedTokens int) (inputTokensOut, cacheRead int) {
	if cachedTokens < 0 {
		cachedTokens = 0
	}
	if inputTokens < 0 {
		inputTokens = 0
	}
	if cachedTokens == 0 {
		return inputTokens, 0
	}
	if inputTokens >= cachedTokens {
		return inputTokens - cachedTokens, cachedTokens
	}
	return 0, inputTokens
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func getFloat(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return n, true
			case float32:
				return float64(n), true
			case int:
				return float64(n), true
			case int64:
				return float64(n), true
			case int32:
				return float64(n), true
			}
		}
	}
	return 0, false
}

func anthropicMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/messages\n%s", cnt, string(body))
	}

	var anthropicReq AnthropicRequest
	if err := json.Unmarshal(body, &anthropicReq); err != nil {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Invalid JSON"}}`, http.StatusBadRequest)
		return
	}
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(anthropicReq.Model)
	if !isKnownAlias(anthropicReq.Model) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "model not found; only configured aliases are accepted"}})
		return
	}
	anthropicReq.Model = resolvedModel

	// 上游是 Anthropic 类型时，下游入口与上游同为 Anthropic 协议，直接透传
	if upstream != nil && upstream.APIType == UpstreamAnthropic {
		rawBody, err := prepareAnthropicPassthroughBody(body, anthropicReq.Model)
		if err != nil {
			log.Printf("[request invalid] path=/v1/messages mode=passthrough model=%q err=%v", anthropicReq.Model, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": err.Error()}})
			return
		}
		if anthropicReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
			if err != nil || status < 200 || status >= 300 {
				errResp := map[string]any{
					"type":  "error",
					"error": map[string]string{"type": "api_error", "message": "upstream error"},
				}
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(errResp)
				return
			}
			defer upResp.Close()
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyAnthropicPassthroughStream(w, upResp, anthropicReq.Model); err != nil && debugMode {
				log.Printf("[anthropic raw stream passthrough error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
			}
			return
		}
		// Record token usage
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				it, _ := u["input_tokens"].(float64)
				ot, _ := u["output_tokens"].(float64)
				tt := it + ot
				if tt > 0 {
					recordTokenUsage(anthropicReq.Model, int64(it), int64(ot), int64(tt))
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[client response] (Anthropic passthrough)\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 上游非 Anthropic 类型，走 Chat 中间格式转换

	// 合规字段留痕：inference_geo 这类"客户端会当成保证"的字段在非 Anthropic 上游无法兑现。
	// 仍按降级原则放行不报错，但记一条日志，避免静默给出假保证。
	logUnenforceableComplianceFields(body, anthropicReq.Model, upstream)

	// L1 入站降级（claude_compat.go）：把上游/翻译器无法表达的 Claude 块换成等价 text 块，
	// 避免 document / search_result / server-tool 结果 / 未知新块被静默丢弃。放在 struct 重解析之前，
	// CPA 与手写 fallback 两条路径共享收益。passthrough 已在上方 return，真 Claude 上游不受影响。
	if claudeInboundNormalizeEnabled() {
		if normalized := normalizeClaudeInboundRequest(body); !bytes.Equal(normalized, body) {
			var renewed AnthropicRequest
			if err := json.Unmarshal(normalized, &renewed); err == nil {
				body = normalized
				renewed.Model = anthropicReq.Model // 保住上面 resolveModel 的结果，别被客户端原值覆盖回去
				anthropicReq = renewed
			}
		}
	}

	messages := anthropicToOpenAIMessages(anthropicReq.Messages, anthropicReq.System)
	messages = fixToolCallGaps(messages)
	// arguments 非法/非 object 已在归一化层兜底为 "{}"，不再因 tool_call 格式回 400。
	messages = normalizeMessagesToolCallArguments(messages)

	chatReq := OpenAIRequest{
		Model:    anthropicReq.Model,
		Messages: messages,
		Stream:   anthropicReq.Stream,
		Thinking: anthropicReq.Thinking,
	}
	if anthropicReq.MaxTokens > 0 {
		chatReq.MaxTokens = anthropicReq.MaxTokens
	}
	if anthropicReq.Temperature != nil {
		chatReq.Temperature = anthropicReq.Temperature
	}
	if anthropicReq.TopP != nil {
		chatReq.TopP = anthropicReq.TopP
	}
	if len(anthropicReq.Tools) > 0 {
		chatReq.Tools = anthropicToOpenAITools(anthropicReq.Tools)
	}
	if anthropicReq.ToolChoice != nil {
		chatReq.ToolChoice = convertAnthropicToolChoice(anthropicReq.ToolChoice)
	} else if len(chatReq.Tools) > 0 {
		chatReq.ToolChoice = "auto"
	}

	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	// CPA 翻译层（库式灰度）：开关开且上游非 Anthropic 时，用 CPA Claude→上游格式 替代手写
	// anthropicToOpenAIMessages→buildUpstreamBody，保留 Anthropic 原始请求结构。passthrough 已在上方处理 Claude 上游。
	// CPAGet 路径用 callPreparedUpstream(raw=true)/Stream 直发翻译体，响应走 cpaTranslateNonStream（Anthropic 入站响应方向 Chat→Claude 在白名单）。
	cpaEnabled := cpaRequestsEnabled()
	var cpaRoute *cpaTranslationRoute
	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo) // 默认手写（灰度关 / fallback 兜底）
	if cpaEnabled {
		clientFmt := cpaClientFormat("anthropic")
		upstreamFmt := formatForUpstream(upstream)
		canonicalEffort := chatReq.ReasoningEffort
		clientThinking := anthropicReq.Thinking
		fb := func([]byte) ([]byte, error) {
			return buildUpstreamBody(&chatReq, modelAliasInfo), nil
		}
		route, translated, terr := cpaTranslateRequest(r.Context(), clientFmt, upstreamFmt, anthropicReq.Model, body, anthropicReq.Stream, fb)
		if terr == nil && route != nil {
			cpaRoute = route
			upstreamBody = patchCPARequestForAlias(translated, canonicalEffort, clientThinking, modelAliasInfo, upstreamFmt)
		}
		// route==nil：CPA 无该方向翻译器（如 Claude→Responses），upstreamBody 维持上面手写 buildUpstreamBody 结果。
	}

	// 两条路径统一补丁：补回被翻译层吞掉但上游能吃的字段（stop/top_p/top_k/response_format），
	// 并删掉会让上游直接 400 的 max_tokens:0。见 cpa_translator.go 的 patchClaudeUpstreamBody。
	upstreamBody = patchClaudeUpstreamBody(upstreamBody, body, upstream)

	if anthropicReq.Stream {
		// CPA 路径直发翻译体（跳过 callUpstreamStream 内二次 prepare；流式响应翻译 glue 待阶段3，仍走原手写 stream 分派）
		var upResp io.ReadCloser
		var status int
		var upHeader http.Header
		var err error
		if cpaRoute != nil {
			upResp, status, upHeader, err = callPreparedUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
		} else {
			upResp, status, upHeader, err = callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
		}
		if err != nil || status < 200 || status >= 300 {
			errResp := map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": "upstream error"},
			}
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(errResp)
			return
		}
		defer upResp.Close()
		// 注：Anthropic 上游已在上方同协议直通处理，此处不会到达。
		// Responses 上游：先转为 Chat SSE 流，再转为 Anthropic SSE 流
		if upstream != nil && upstream.APIType == UpstreamResponses {
			pr2, pw2 := io.Pipe()
			go func() {
				defer pw2.Close()
				chatW2 := &pipeResponseWriter{w: pw2}
				// The outer anthropicStreamHandler records the converted usage.
				// Avoid double-counting gateway stats for Responses -> Anthropic.
				responsesStreamToChatHandler(chatW2, upResp, anthropicReq.Model, false)
			}()
			anthropicStreamHandler(w, io.NopCloser(pr2), anthropicReq.Model)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Anthropic SSE 流
			anthropicStreamHandler(w, upResp, anthropicReq.Model)
		}
		return
	}

	// CPA 路径用 callPreparedUpstream(raw=true) 直发翻译体拿 raw 响应；否则 callUpstream（内部二次转换）。
	var respBody []byte
	var status int
	var upHeader http.Header
	if cpaRoute != nil {
		respBody, status, upHeader, err = callPreparedUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy, true)
	} else {
		respBody, status, upHeader, err = callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream, modelAliasInfo.Socks5Proxy)
	}
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
		}
		return
	}

	// 响应翻译：
	//   - cpaRoute!=nil 时 respBody 是 raw 上游响应，需按上游格式翻回 Claude 客户端格式。
	//     Anthropic 入站响应方向 Chat→Claude 在白名单（cpaResponseUsableForRoute），开关开时走 cpaTranslateNonStream；
	//     否则手写 handwrittenResponseToClaude（Responses 上游 Responses→Chat→Claude 两段 / Chat 上游 openAIToAnthropicResponse）。
	//   - cpaRoute==nil 时 respBody 已是 callUpstream 二次转换后的 Chat，用 openAIToAnthropicResponse。
	var anthropicRespBody []byte
	if cpaRoute != nil {
		upstreamFmt := formatForUpstream(upstream)
		if cpaNonStreamEnabled() && cpaResponseUsableForRoute(cpaRoute, false) {
			anthropicRespBody = cpaTranslateNonStream(r.Context(), cpaRoute, respBody, func(b []byte) []byte {
				return handwrittenResponseToClaude(b, anthropicReq.Model, upstreamFmt)
			})
		} else {
			anthropicRespBody = handwrittenResponseToClaude(respBody, anthropicReq.Model, upstreamFmt)
		}
	} else {
		var convertedOK bool
		anthropicRespBody, convertedOK = openAIToAnthropicResponse(respBody, anthropicReq.Model)
		if !convertedOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			w.Write(anthropicRespBody)
			return
		}
	}

	// L5 出站补全（claude_compat.go）：thinking 块签发 signature（多轮回放的闭环签发端）、
	// usage 补齐官方恒有的 cache_* 字段。
	if claudeOutboundEnrichEnabled() {
		anthropicRespBody = enrichClaudeResponse(anthropicRespBody)
	}

	// Record token usage（在最终客户端格式输出端记一次）
	var usageResp2 map[string]any
	if json.Unmarshal(anthropicRespBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt > 0 {
				recordTokenUsage(anthropicReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[client response]\n%s", string(anthropicRespBody))
	}
	w.Write(anthropicRespBody)
}

// anthropicStreamToolBlock 记录一个上游流式 tool_call 的完整累积状态。
// 工具参数先按上游 index 全量缓冲，到 finish_reason 后再逐个按
// content_block_start → input_json_delta → content_block_stop 严格串行输出。
// 这牺牲了参数逐片显示，但避免并行 tool_call 交错时产生重叠块、串块或半截 JSON。
type anthropicStreamToolBlock struct {
	id   string
	name string
	args string
}

func anthropicStreamHandler(w http.ResponseWriter, respBody io.ReadCloser, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	msgID := fmt.Sprintf("msg_%s", randomString(24))
	blockIndex := 0
	// 每个打开的块记住自己的 index（-1 = 未打开），不再用 blockIndex-1 推断。
	thinkingBlockIndex := -1
	textBlockIndex := -1
	// 累积思考全文，用于块关闭前签发 signature_delta。
	var thinkingText strings.Builder
	toolCallAccumulator := map[int]*anthropicStreamToolBlock{}
	toolCallOrder := []int{}
	// 真正宣告出去的 tool_use 块数量。双向给 stop_reason 把关：
	// 有块必须回 tool_use（否则客户端不执行工具，且历史里留下无配对 tool_result 的 tool_use，
	// 下一轮被上游判 400）；没块就不能回 tool_use（客户端会等一个永远不来的工具结果）。
	emittedToolBlocks := 0
	emittedContentBlocks := 0
	messageStartSent := false
	finishSeen := false
	finalStopReason := "end_turn"
	fullUsage := map[string]any{}
	defer func() {
		if len(fullUsage) > 0 {
			pt, _ := fullUsage["prompt_tokens"].(float64)
			ct, _ := fullUsage["completion_tokens"].(float64)
			tt, _ := fullUsage["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
			}
		}
	}()

	emitAnthropicEvent := func(event string, data any) {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling Anthropic SSE event: %v", err)
			return
		}
		w.Write([]byte("event: " + event + "\n"))
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeThinkingBlock := func() {
		if thinkingBlockIndex < 0 {
			return
		}
		// 官方协议：thinking 块在 content_block_stop 之前会收到一个 signature_delta。
		// 本网关签发合成 signature（claude_compat.go），使客户端下一轮回传历史思考时，
		// CPA 的 signature 门禁放行、reasoning_content 不被丢弃。
		if claudeOutboundEnrichEnabled() {
			emitAnthropicEvent("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": thinkingBlockIndex,
				"delta": map[string]any{
					"type":      "signature_delta",
					"signature": synthesizeThinkingSignature(thinkingText.String()),
				},
			})
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": thinkingBlockIndex,
		})
		thinkingBlockIndex = -1
		thinkingText.Reset()
	}

	closeTextBlock := func() {
		if textBlockIndex < 0 {
			return
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": textBlockIndex,
		})
		textBlockIndex = -1
	}

	// emitStandaloneTextBlock 用一个完整、立即关闭的 text 块承载降级提示。
	// 仅在上游没有产出任何可用内容时使用，避免返回 content:[] 的成功消息。
	emitStandaloneTextBlock := func(text string) {
		idx := blockIndex
		blockIndex++
		emittedContentBlocks++
		emitAnthropicEvent("content_block_start", map[string]any{
			"type":  "content_block_start",
			"index": idx,
			"content_block": map[string]any{
				"type": "text",
				"text": "",
			},
		})
		emitAnthropicEvent("content_block_delta", map[string]any{
			"type":  "content_block_delta",
			"index": idx,
			"delta": map[string]any{
				"type": "text_delta",
				"text": text,
			},
		})
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":  "content_block_stop",
			"index": idx,
		})
	}

	// emitBufferedToolCalls 在 finish_reason 到达后才输出工具块。OpenAI 允许多个 tool_call
	// 的参数分片交错，Anthropic 却要求 content block 严格串行；全量缓冲后逐个输出可同时满足两者。
	// allow=false 用于 length/content_filter：此时工具参数可能被截断或被过滤，不能让客户端执行。
	emitBufferedToolCalls := func(allow bool) (emitted, dropped int) {
		for _, upstreamIndex := range toolCallOrder {
			acc := toolCallAccumulator[upstreamIndex]
			if acc == nil {
				continue
			}
			if !allow {
				log.Printf("[anthropic stream] 丢弃未完成的 tool_call: upstream_index=%d finish_reason 不允许执行", upstreamIndex)
				dropped++
				continue
			}
			if strings.TrimSpace(acc.name) == "" {
				log.Printf("[anthropic stream] 丢弃未成形的 tool_call: upstream_index=%d id=%q args_len=%d（上游始终未提供 function.name）",
					upstreamIndex, acc.id, len(acc.args))
				dropped++
				continue
			}

			args := strings.TrimSpace(acc.args)
			if args == "" {
				args = "{}"
			}
			var input map[string]any
			if err := json.Unmarshal([]byte(args), &input); err != nil || input == nil {
				log.Printf("[anthropic stream] 丢弃参数不完整的 tool_call: upstream_index=%d name=%q args_len=%d",
					upstreamIndex, acc.name, len(acc.args))
				dropped++
				continue
			}
			if acc.id == "" {
				acc.id = "toolu_" + randomString(12)
			}

			idx := blockIndex
			blockIndex++
			emittedContentBlocks++
			emittedToolBlocks++
			emitted++
			emitAnthropicEvent("content_block_start", map[string]any{
				"type":  "content_block_start",
				"index": idx,
				"content_block": map[string]any{
					"type":  "tool_use",
					"id":    acc.id,
					"name":  acc.name,
					"input": map[string]any{},
				},
			})
			emitAnthropicEvent("content_block_delta", map[string]any{
				"type":  "content_block_delta",
				"index": idx,
				"delta": map[string]any{
					"type":         "input_json_delta",
					"partial_json": args,
				},
			})
			emitAnthropicEvent("content_block_stop", map[string]any{
				"type":  "content_block_stop",
				"index": idx,
			})
		}
		return emitted, dropped
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			break
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if errObj, ok := chunk["error"]; ok {
			closeThinkingBlock()
			closeTextBlock()
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream stream returned error")
			emitAnthropicEvent("error", map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    errType,
					"message": msg,
				},
			})
			return
		}

		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				fullUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		// finish_reason 已收尾后，部分 vLLM 上游还可能送 usage 尾包。只采 usage，任何内容
		// delta 都必须忽略，否则会在已关闭块甚至 message_stop 之后继续产事件。
		if finishSeen {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				fullUsage = usage
			}
			if len(delta) > 0 || finishReason != "" {
				log.Printf("[anthropic stream] 忽略 finish_reason 之后到达的内容 chunk")
			}
			continue
		}

		if !messageStartSent {
			messageStartSent = true
			emitAnthropicEvent("message_start", map[string]any{
				"type": "message_start",
				"message": map[string]any{
					"id":            msgID,
					"type":          "message",
					"role":          "assistant",
					"content":       []any{},
					"model":         model,
					"stop_reason":   nil,
					"stop_sequence": nil,
					"usage":         map[string]any{"input_tokens": 0, "output_tokens": 0},
				},
			})
			emitAnthropicEvent("ping", map[string]any{"type": "ping"})
		}

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				closeTextBlock()
				if thinkingBlockIndex < 0 {
					thinkingBlockIndex = blockIndex
					blockIndex++
					emittedContentBlocks++
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": thinkingBlockIndex,
						"content_block": map[string]any{
							"type":      "thinking",
							"thinking":  "",
							"signature": "",
						},
					})
				}
				thinkingText.WriteString(rcStr)
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": thinkingBlockIndex,
					"delta": map[string]any{
						"type":     "thinking_delta",
						"thinking": rcStr,
					},
				})
			}
		}

		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ := c.(string)
			if contentStr != "" {
				closeThinkingBlock()
				if textBlockIndex < 0 {
					textBlockIndex = blockIndex
					blockIndex++
					emittedContentBlocks++
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": textBlockIndex,
						"content_block": map[string]any{
							"type": "text",
							"text": "",
						},
					})
				}
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": textBlockIndex,
					"delta": map[string]any{
						"type": "text_delta",
						"text": contentStr,
					},
				})
			}
		}

		if rawToolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTC := range rawToolCalls {
				tc, ok := rawTC.(map[string]any)
				if !ok {
					continue
				}
				idxFloat, _ := tc["index"].(float64)
				upstreamIndex := int(idxFloat)

				acc, exists := toolCallAccumulator[upstreamIndex]
				if !exists {
					acc = &anthropicStreamToolBlock{}
					toolCallAccumulator[upstreamIndex] = acc
					toolCallOrder = append(toolCallOrder, upstreamIndex)
				}

				// id / name 可能分散在不同分片里到达，先到先得；arguments 始终按到达顺序累积。
				if id, _ := tc["id"].(string); id != "" && acc.id == "" {
					acc.id = id
				}
				fn, _ := tc["function"].(map[string]any)
				if name, _ := fn["name"].(string); name != "" && acc.name == "" {
					acc.name = name
				}
				if argDelta, _ := fn["arguments"].(string); argDelta != "" {
					acc.args += argDelta
				}
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			fullUsage = usage
		}

		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			if finishSeen {
				// finish 之后的 choices 只允许携带 usage；内容与第二个 finish 都不能再改写已收尾的消息。
				continue
			}
			closeThinkingBlock()
			closeTextBlock()

			allowTools := finishReason == "stop" || finishReason == "tool_calls" || finishReason == "function_call"
			_, droppedTools := emitBufferedToolCalls(allowTools)
			toolCallOrder = nil

			switch {
			case finishReason == "length":
				finalStopReason = "max_tokens"
			case finishReason == "content_filter":
				// 当前不构造 refusal/stop_details；保留兼容降级，不把过滤截断伪装为 tool_use。
				finalStopReason = "end_turn"
			case emittedToolBlocks > 0:
				// 只要响应里真正发出了 tool_use，客户端就必须执行工具；即使上游错报 stop，
				// 这里也校正为 tool_use，避免下一轮历史出现无配对的工具调用而被判 400。
				finalStopReason = "tool_use"
			default:
				finalStopReason = "end_turn"
			}

			if emittedContentBlocks == 0 {
				msg := "[upstream returned no usable content]"
				if droppedTools > 0 {
					msg = "[upstream returned an incomplete tool call; it was ignored]"
				}
				emitStandaloneTextBlock(msg)
			}
			finishSeen = true
			// 继续读取 finish 后的 usage-only chunk；后续内容 delta 会被忽略。
		}
	}
	closeThinkingBlock()
	closeTextBlock()
	if !messageStartSent {
		emitAnthropicEvent("error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "upstream stream ended without message_start",
			},
		})
		return
	}
	if !finishSeen {
		// 没有 finish_reason 就无法确认缓冲中的 tool arguments 是否完整。绝不把半截 JSON
		// 宣告成成功 tool_use，也不伪装成正常 end_turn；用流内 error 让 SDK 明确识别失败。
		emitAnthropicEvent("error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "upstream stream ended before finish_reason",
			},
		})
		return
	}

	inputTokens := 0
	if v, ok := fullUsage["prompt_tokens"]; ok {
		inputTokens = int(toFloat64(v))
	}
	outputTokens := 0
	if v, ok := fullUsage["completion_tokens"]; ok {
		outputTokens = int(toFloat64(v))
	}
	// OpenAI 的 prompt_tokens 含缓存命中部分，Anthropic 把缓存读取单列。与非流式路径共用
	// splitOpenAIInputWithCache，口径一致、避免两处各写一遍出现漂移。
	inputTokens, cacheReadTokens := splitOpenAIInputWithCache(
		inputTokens,
		int(toFloat64(extractOpenAICachedTokens(fullUsage))),
	)

	if !finishSeen {
		finalStopReason = "end_turn"
	}

	emitAnthropicEvent("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   finalStopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{
			"input_tokens":                inputTokens,
			"output_tokens":               outputTokens,
			"cache_creation_input_tokens": 0,
			"cache_read_input_tokens":     cacheReadTokens,
		},
	})
	emitAnthropicEvent("message_stop", map[string]any{"type": "message_stop"})
}

// ======================== Anthropic 流式转换 ========================

// pipeResponseWriter 适配 io.Writer 到 http.ResponseWriter 接口
type pipeResponseWriter struct {
	w      io.Writer
	header http.Header
}

func (p *pipeResponseWriter) Header() http.Header {
	if p.header == nil {
		p.header = make(http.Header)
	}
	return p.header
}

func (p *pipeResponseWriter) Write(data []byte) (int, error) {
	return p.w.Write(data)
}

func (p *pipeResponseWriter) WriteHeader(code int) {}

func (p *pipeResponseWriter) Flush() {
	// no-op for pipe; writes are synchronous
}

// anthropicStreamToChatHandler 将上游 Anthropic SSE 流实时转为 OpenAI Chat SSE 格式并写入客户端
func anthropicStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	roleSent := false
	toolCallAccumulator := map[int]map[string]string{}
	fullUsage := map[string]any{}

	defer func() {
		if len(fullUsage) > 0 {
			pt, _ := fullUsage["input_tokens"].(float64)
			ct, _ := fullUsage["output_tokens"].(float64)
			if pt > 0 || ct > 0 {
				recordTokenUsage(model, int64(pt), int64(ct), int64(pt+ct))
			}
		}
	}()

	emitChatChunk := func(delta map[string]any, finishReason any, usage map[string]any) {
		// 清理空 content，避免客户端收到 content:"" 的 chunk
		if c, ok := delta["content"].(string); ok && c == "" {
			delete(delta, "content")
		}
		if finishReason == nil || finishReason == "" {
			finishReason = nil
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{
				{
					"index":         0,
					"delta":         delta,
					"finish_reason": finishReason,
				},
			},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		jsonData, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading Anthropic stream: %v", err)
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}

		// Parse Anthropic SSE data lines
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var event map[string]any
		if json.Unmarshal([]byte(line[6:]), &event) != nil {
			continue
		}

		eventType, _ := event["type"].(string)

		switch eventType {
		case "message_start":
			if msg, ok := event["message"].(map[string]any); ok {
				if id, ok := msg["id"].(string); ok && id != "" {
					chunkID = "chatcmpl-" + id
				}
				if u, ok := msg["usage"].(map[string]any); ok {
					fullUsage = u
				}
			}
			if !roleSent {
				emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
				roleSent = true
			}

		case "content_block_start":
			block, _ := event["content_block"].(map[string]any)
			if block != nil {
				blockType, _ := block["type"].(string)
				switch blockType {
				case "tool_use":
					idx := len(toolCallAccumulator)
					callID, _ := block["id"].(string)
					name, _ := block["name"].(string)
					toolCallAccumulator[idx] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index": float64(idx),
								"id":    callID,
								"type":  "function",
								"function": map[string]any{
									"name":      name,
									"arguments": "",
								},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "content_block_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj == nil {
				continue
			}
			deltaType, _ := deltaObj["type"].(string)
			switch deltaType {
			case "thinking_delta":
				thinking, _ := deltaObj["thinking"].(string)
				if thinking != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"reasoning_content": thinking}, nil, nil)
				}
			case "text_delta":
				text, _ := deltaObj["text"].(string)
				if text != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"content": text}, nil, nil)
				}
			case "input_json_delta":
				partialJSON, _ := deltaObj["partial_json"].(string)
				index, _ := event["index"].(float64)
				idx := int(index)
				if tc, ok := toolCallAccumulator[idx]; ok {
					tc["args"] += partialJSON
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index":    float64(idx),
								"function": map[string]any{"arguments": partialJSON},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "message_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj != nil {
				stopReason, _ := deltaObj["stop_reason"].(string)
				finishReason := ""
				switch stopReason {
				case "end_turn":
					finishReason = "stop"
				case "max_tokens":
					finishReason = "length"
				case "tool_use":
					finishReason = "tool_calls"
				default:
					if stopReason != "" {
						finishReason = stopReason
					}
				}
				usage, _ := event["usage"].(map[string]any)
				if usage != nil {
					if ot, ok := usage["output_tokens"].(float64); ok {
						fullUsage["output_tokens"] = ot
					}
				}
				chatUsage := map[string]any{}
				if pt, ok := fullUsage["input_tokens"].(float64); ok {
					chatUsage["prompt_tokens"] = int64(pt)
				}
				if ot, ok := fullUsage["output_tokens"].(float64); ok {
					chatUsage["completion_tokens"] = int64(ot)
				}
				if _, ok := chatUsage["prompt_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if it, ok3 := u["input_tokens"].(float64); ok3 {
							chatUsage["prompt_tokens"] = int64(it)
							fullUsage["input_tokens"] = it
						}
					}
				}
				if _, ok := chatUsage["completion_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if ot, ok3 := u["output_tokens"].(float64); ok3 {
							chatUsage["completion_tokens"] = int64(ot)
							fullUsage["output_tokens"] = ot
						}
					}
				}
				pt := float64(0)
				if v, ok := chatUsage["prompt_tokens"].(int64); ok {
					pt = float64(v)
				}
				ct := float64(0)
				if v, ok := chatUsage["completion_tokens"].(int64); ok {
					ct = float64(v)
				}
				chatUsage["total_tokens"] = int64(pt + ct)
				if !roleSent {
					emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
					roleSent = true
				}
				emitChatChunk(map[string]any{}, finishReason, chatUsage)
			}

		case "message_stop":
			// nothing extra
		case "ping":
			// ignore
		}
	}

	w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Responses API ========================

func responsesInputToMessages(input any, instructions string) []Message {
	var messages []Message
	if instructions != "" {
		messages = append(messages, Message{Role: "system", Content: instructions})
	}
	switch v := input.(type) {
	case string:
		messages = append(messages, Message{Role: "user", Content: v})
	case []any:
		var pendingAssistant *Message
		ensurePendingAssistant := func() *Message {
			if pendingAssistant == nil {
				pendingAssistant = &Message{Role: "assistant", Content: ""}
			}
			return pendingAssistant
		}
		flushPendingAssistant := func() {
			if pendingAssistant == nil {
				return
			}
			if pendingAssistant.Content == nil {
				pendingAssistant.Content = ""
			}
			messages = append(messages, *pendingAssistant)
			pendingAssistant = nil
		}
		appendPendingReasoning := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if msg.ReasoningContent == nil || *msg.ReasoningContent == "" {
				rc := text
				msg.ReasoningContent = &rc
				return
			}
			rc := *msg.ReasoningContent + "\n" + text
			msg.ReasoningContent = &rc
		}
		appendPendingText := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if existing, ok := msg.Content.(string); ok && existing != "" {
				msg.Content = existing + "\n" + text
			} else {
				msg.Content = text
			}
		}
		for _, item := range v {
			switch elem := item.(type) {
			case string:
				flushPendingAssistant()
				messages = append(messages, Message{Role: "user", Content: elem})
			case map[string]any:
				itemType, _ := elem["type"].(string)
				switch itemType {
				case "function_call", "tool_call":
					if pendingAssistant != nil {
						if existing, ok := pendingAssistant.Content.(string); ok && strings.TrimSpace(existing) != "" && len(pendingAssistant.ToolCalls) == 0 {
							flushPendingAssistant()
						}
					}
					if tc, ok := responsesToolCallFromItem(elem); ok {
						msg := ensurePendingAssistant()
						msg.ToolCalls = append(msg.ToolCalls, tc)
					}
				case "function_call_output", "tool_result":
					flushPendingAssistant()
					callID, output := responsesToolOutputFromItem(elem)
					if callID != "" {
						messages = append(messages, Message{Role: "tool", ToolCallID: callID, Content: output})
					}
					continue
				case "reasoning":
					text := extractTextFromContentParts(elem["summary"])
					if text == "" {
						text = extractTextFromContentParts(elem["content"])
					}
					if text == "" {
						text, _ = elem["text"].(string)
					}
					appendPendingReasoning(text)
					continue
				case "message", "":
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					if role == "developer" {
						role = "system"
					}
					if role == "assistant" {
						text := extractTextFromContentParts(elem["content"])
						if pendingAssistant != nil && len(pendingAssistant.ToolCalls) > 0 && text != "" {
							flushPendingAssistant()
						}
						appendPendingText(text)
					} else {
						flushPendingAssistant()
						content := responsesContentToChatContent(elem["content"])
						if role == "system" {
							content = extractTextFromContentParts(elem["content"])
						}
						messages = append(messages, Message{Role: role, Content: content})
					}
				default:
					flushPendingAssistant()
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					content := responsesContentToChatContent(elem["content"])
					if content == "" {
						b, _ := json.Marshal(elem)
						content = string(b)
					}
					messages = append(messages, Message{Role: role, Content: content})
				}
			default:
				flushPendingAssistant()
				b, _ := json.Marshal(elem)
				messages = append(messages, Message{Role: "user", Content: string(b)})
			}
		}
		flushPendingAssistant()
	default:
		b, _ := json.Marshal(v)
		messages = append(messages, Message{Role: "user", Content: string(b)})
	}
	return messages
}

func responsesToolCallFromItem(elem map[string]any) (ToolCall, bool) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["id"].(string)
	}
	name, _ := elem["name"].(string)
	args, _ := elem["arguments"].(string)
	if args == "" {
		if rawArgs, ok := elem["arguments"]; ok && rawArgs != nil {
			b, _ := json.Marshal(rawArgs)
			args = string(b)
		}
	}
	if name == "" {
		if tu, ok := elem["tool_use"].(map[string]any); ok {
			name, _ = tu["name"].(string)
			if callID == "" {
				callID, _ = tu["id"].(string)
			}
			if a, ok := tu["arguments"].(string); ok {
				args = a
			} else if inp, ok := tu["input"]; ok {
				b, _ := json.Marshal(inp)
				args = string(b)
			}
		}
	}
	if callID == "" || name == "" {
		return ToolCall{}, false
	}
	if args == "" {
		args = "{}"
	}
	return ToolCall{
		ID:   callID,
		Type: "function",
		Function: FunctionCall{
			Name:      name,
			Arguments: args,
		},
	}, true
}

func responsesToolOutputFromItem(elem map[string]any) (string, any) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["tool_use_id"].(string)
	}
	if callID == "" {
		return "", ""
	}
	var output any
	switch o := elem["output"].(type) {
	case string:
		output = o
	case []any:
		if converted := responsesContentToChatContent(o); converted != "" {
			output = converted
		} else {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	default:
		if o != nil {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	}
	switch v := output.(type) {
	case nil:
		output = "[tool output missing]"
	case string:
		if v == "" {
			output = "[tool output missing]"
		}
	case []any:
		if len(v) == 0 {
			output = "[tool output missing]"
		}
	}
	return callID, output
}

// convertChatToolsToResponses 将 OpenAI Chat tools 转为 Responses tools 格式
func convertChatToolsToResponses(tools []any) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok || tool == nil {
			continue
		}
		t, _ := tool["type"].(string)
		if t == "" {
			t = "function"
		}
		// Chat: {type:function, function:{name,description,parameters}}
		// Responses: {type:function, name, description, parameters}
		if fn, ok := tool["function"].(map[string]any); ok && fn != nil {
			item := map[string]any{"type": "function"}
			if name, ok := fn["name"].(string); ok {
				item["name"] = name
			}
			if desc, ok := fn["description"].(string); ok {
				item["description"] = desc
			}
			if params, ok := fn["parameters"]; ok {
				item["parameters"] = params
			} else {
				item["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			out = append(out, item)
			continue
		}
		// 已是 Responses function 形态（{type:function, name, parameters}）才保留；
		// 其余（无 function 子对象、非 function 的 builtin 等）静默丢弃，
		// 不原样塞入畸形 item 招来上游 400——对照 convertResponsesToolsWithMappings
		// 对未知 tool type 的 switch 无 default 丢弃行为，双向对称。
		if t == "function" {
			if name, _ := tool["name"].(string); name != "" {
				item := map[string]any{"type": "function", "name": name}
				if desc, ok := tool["description"]; ok {
					item["description"] = desc
				}
				if params, ok := tool["parameters"]; ok {
					item["parameters"] = params
				} else {
					item["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
				}
				out = append(out, item)
			}
		}
	}
	return out
}

// convertChatToolChoiceToResponses 将 OpenAI Chat tool_choice 转为 Responses tool_choice
func convertChatToolChoiceToResponses(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		return v
	case map[string]any:
		// Chat: {"type":"function","function":{"name":"xxx"}}
		// Responses: {"type":"function","name":"xxx"}
		if t, _ := v["type"].(string); t == "function" {
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					return map[string]any{"type": "function", "name": name}
				}
			}
			if name, ok := v["name"].(string); ok && name != "" {
				return map[string]any{"type": "function", "name": name}
			}
		}
		return v
	default:
		return choice
	}
}

func convertResponsesToolsWithMappings(tools []ResponsesTool) ([]Tool, map[string]ResponseToolNameMapping) {
	converted := make([]Tool, 0, len(tools))
	mappings := map[string]ResponseToolNameMapping{}
	for _, tool := range tools {
		switch tool.Type {
		case "function":
			if fn, ok := responsesToolFunction(tool, ""); ok {
				converted = append(converted, Tool{Type: "function", Function: fn})
			}
		case "namespace":
			namespace := strings.TrimSpace(tool.Name)
			for _, nested := range tool.Tools {
				if nested.Type != "function" {
					continue
				}
				if fn, ok := responsesToolFunction(nested, namespace); ok {
					converted = append(converted, Tool{Type: "function", Function: fn})
					mappings[fn.Name] = ResponseToolNameMapping{
						Namespace: namespace,
						Name:      responseToolName(nested),
					}
				}
			}
		}
	}
	return converted, mappings
}

func responsesToolFunction(tool ResponsesTool, namespace string) (ToolFunction, bool) {
	fn := ToolFunction{
		Name:        tool.Name,
		Description: tool.Description,
		Parameters:  tool.Parameters,
	}
	if tool.Function != nil {
		fn = *tool.Function
	}
	fn.Name = strings.TrimSpace(fn.Name)
	if fn.Name == "" {
		return ToolFunction{}, false
	}
	if namespace != "" {
		fn.Name = flattenNamespaceToolName(namespace, fn.Name)
	}
	if fn.Parameters == nil {
		fn.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return fn, true
}

func responseToolName(tool ResponsesTool) string {
	if tool.Function != nil {
		return strings.TrimSpace(tool.Function.Name)
	}
	return strings.TrimSpace(tool.Name)
}

func flattenNamespaceToolName(namespace, toolName string) string {
	ns := strings.TrimSuffix(strings.TrimSpace(namespace), "__")
	name := strings.TrimSpace(toolName)
	if ns == "" {
		return name
	}
	return ns + "__" + name
}

func convertResponsesToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	choiceMap, ok := choice.(map[string]any)
	if !ok {
		return choice
	}
	if choiceMap["type"] == "function" {
		if name, ok := choiceMap["name"].(string); ok && name != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		}
	}
	if choiceMap["type"] == "namespace" {
		namespace, _ := choiceMap["name"].(string)
		toolName, _ := choiceMap["tool"].(string)
		if toolName == "" {
			toolName, _ = choiceMap["tool_name"].(string)
		}
		if namespace != "" && toolName != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": flattenNamespaceToolName(namespace, toolName)},
			}
		}
	}
	return choice
}

func responseFunctionCallItem(itemID, status, arguments, callID, name string, mappings map[string]ResponseToolNameMapping) map[string]any {
	item := map[string]any{
		"id":        itemID,
		"type":      "function_call",
		"status":    status,
		"arguments": arguments,
		"call_id":   callID,
		"name":      name,
	}
	if mapping, ok := responseToolNameMapping(name, mappings); ok {
		item["name"] = mapping.Name
		item["namespace"] = mapping.Namespace
	}
	return item
}

func responseToolNameMapping(name string, mappings map[string]ResponseToolNameMapping) (ResponseToolNameMapping, bool) {
	if len(mappings) == 0 {
		return ResponseToolNameMapping{}, false
	}
	if mapping, ok := mappings[name]; ok {
		return mapping, true
	}
	normalized := normalizeResponseToolCallKey(name)
	if mapping, ok := mappings[normalized]; ok {
		return mapping, true
	}
	return ResponseToolNameMapping{}, false
}

func normalizeResponseToolCallKey(name string) string {
	normalized := strings.NewReplacer(":", "__", ".", "__", "/", "__", "-", "_").Replace(strings.TrimSpace(name))
	for strings.Contains(normalized, "___") {
		normalized = strings.ReplaceAll(normalized, "___", "__")
	}
	return normalized
}

func responsesContentToChatContent(content any) any {
	if content == nil {
		return ""
	}
	if s, ok := content.(string); ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		text := extractTextFromContentParts(content)
		if text != "" {
			return text
		}
		return ""
	}

	var converted []any
	var textParts []string
	hasImage := false
	for _, p := range parts {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch partType {
		case "input_text", "output_text", "summary_text", "text":
			if text, ok := part["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
				converted = append(converted, map[string]any{"type": "text", "text": text})
			}
		case "input_image", "image_url":
			imageURL := responsesImageURLFromPart(part)
			if imageURL != nil {
				hasImage = true
				converted = append(converted, map[string]any{"type": "image_url", "image_url": imageURL})
			}
		}
	}
	if len(converted) == 0 {
		return ""
	}
	if hasImage {
		return converted
	}
	return strings.Join(textParts, "\n")
}

func responsesImageURLFromPart(part map[string]any) map[string]any {
	url := ""
	detail := ""
	if v, ok := part["image_url"].(string); ok {
		url = v
	}
	if imageURL, ok := part["image_url"].(map[string]any); ok {
		if u, ok := imageURL["url"].(string); ok {
			url = u
		}
		if d, ok := imageURL["detail"].(string); ok {
			detail = d
		}
	}
	if url == "" {
		if v, ok := part["url"].(string); ok {
			url = v
		}
	}
	if detail == "" {
		detail, _ = part["detail"].(string)
	}
	if url == "" {
		return nil
	}
	imageURL := map[string]any{"url": url}
	if detail != "" {
		imageURL["detail"] = detail
	}
	return imageURL
}

func extractTextFromContentParts(content any) string {
	parts, ok := content.([]any)
	if !ok {
		if s, ok := content.(string); ok {
			return s
		}
		return ""
	}
	var texts []string
	for _, p := range parts {
		if part, ok := p.(map[string]any); ok {
			if part["type"] == "input_text" || part["type"] == "output_text" || part["type"] == "summary_text" || part["type"] == "text" {
				if t, ok := part["text"].(string); ok {
					texts = append(texts, t)
				}
			}
		}
	}
	return strings.Join(texts, "\n")
}

func responsesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/responses\n%s", cnt, string(body))
	}

	var respReq ResponsesAPIRequest
	if err := json.Unmarshal(body, &respReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(respReq.Model)
	if !isKnownAlias(respReq.Model) {
		http.Error(w, `{"error":{"message":"model not found; only configured aliases are accepted","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	respReq.Model = resolvedModel
	if respReq.Model == "" {
		http.Error(w, `{"error":"model is required"}`, http.StatusBadRequest)
		return
	}

	if upstream != nil && upstream.APIType == UpstreamResponses {
		rawBody, err := prepareResponsesPassthroughBody(body, respReq.Model, modelAliasInfo)
		if err != nil {
			log.Printf("[request invalid] path=/v1/responses mode=passthrough model=%q err=%v", respReq.Model, err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if respReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
			if err != nil || status < 200 || status >= 300 {
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyResponsesPassthroughStream(w, upResp, respReq.Model); err != nil && debugMode {
				log.Printf("[responses raw stream proxy error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			}
			return
		}
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
				ct, _ := getFloat(u, "completion_tokens", "output_tokens")
				tt, _ := getFloat(u, "total_tokens")
				if tt == 0 && pt+ct > 0 {
					tt = pt + ct
				}
				if tt > 0 {
					recordTokenUsage(respReq.Model, int64(pt), int64(ct), int64(tt))
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[responses raw response]\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 多模态路由

	messages := respReq.Messages
	if len(messages) == 0 {
		messages = responsesInputToMessages(respReq.Input, respReq.Instructions)
	} else if respReq.Instructions != "" {
		messages = append([]Message{{Role: "system", Content: respReq.Instructions}}, messages...)
	}

	chatReq := OpenAIRequest{
		Model:    respReq.Model,
		Messages: messages,
		Stream:   respReq.Stream,
	}
	toolNameMappings := map[string]ResponseToolNameMapping{}
	if respReq.Temperature != 0 {
		chatReq.Temperature = &respReq.Temperature
	}
	if respReq.MaxTokens != 0 {
		chatReq.MaxTokens = respReq.MaxTokens
	}
	if respReq.TopP != 0 {
		chatReq.TopP = &respReq.TopP
	}
	if len(respReq.Tools) > 0 {
		chatReq.Tools, toolNameMappings = convertResponsesToolsWithMappings(respReq.Tools)
	}
	if respReq.ToolChoice != nil {
		chatReq.ToolChoice = convertResponsesToolChoice(respReq.ToolChoice)
	}
	if respReq.ParallelToolCalls != nil {
		chatReq.ExtraBody = map[string]any{"parallel_tool_calls": *respReq.ParallelToolCalls}
	}
	// reasoning.effort describes the current request and is independent from
	// WithReasoning, which only controls replaying historical reasoning_content.
	// 保留 none（不再丢弃）：与 Chat/Messages 入站统一——让 convertRequest 接到 effort="none" 后，
	// 非 thinking 方言透传 reasoning_effort:none（DeepSeek 等认 none 禁推理）；thinking 方言注入 thinking{disabled}。
	// 旧实现丢弃 none 会导致 Responses 入站在禁推理时上游走默认（常 enabled），与其它入口不一致。
	if respReq.Reasoning.Effort != "" {
		chatReq.ReasoningEffort = respReq.Reasoning.Effort
	}
	// reasoning.summary 是 OpenAI Responses 输出摘要偏好，合法枚举仅 auto/concise/detailed（省略=不请求摘要）。
	// Chat 上游不消费 summary（仅用于内部决定是否发 summary 通道），故不转发。
	// 非法值直接 400 invalid_request_error / unsupported_value，与 OpenAI 官方 enum 行为一致（不静默降级吞非法输入）。
	respSummary := strings.ToLower(strings.TrimSpace(respReq.Reasoning.Summary))
	if respSummary != "" && respSummary != "auto" && respSummary != "concise" && respSummary != "detailed" {
		errBody, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"type":    "invalid_request_error",
				"code":    "unsupported_value",
				"param":   "reasoning.summary",
				"message": "Unsupported value: " + respReq.Reasoning.Summary + ". 'reasoning.summary' must be one of: auto, concise, detailed.",
			},
		})
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, string(errBody), http.StatusBadRequest)
		return
	}
	_ = respSummary // 预留：未来按 summary 偏好决定 reasoning item 是否并发 summary 通道

	chatReq.Messages = fixToolCallGaps(chatReq.Messages)
	// arguments 非法/非 object 已在归一化层兜底为 "{}"，不再因 tool_call 格式回 400。
	chatReq.Messages = normalizeMessagesToolCallArguments(chatReq.Messages)
	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	// CPA 翻译层（库式灰度）：开关开且上游非 Responses 时，用 CPA Responses→上游格式 替代手写
	// responsesInputToMessages/convertResponsesTools→buildUpstreamBody，保留 Responses 原始请求结构。passthrough 已在上方处理 Responses 上游。
	// CPAGet 路径用 callPreparedUpstream(raw=true)/Stream 直发翻译体；Responses 入站响应方向当前不在白名单，走 handwrittenResponseToResponses。
	cpaEnabled := cpaRequestsEnabled()
	var cpaRoute *cpaTranslationRoute
	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo) // 默认手写（灰度关 / fallback 兜底）
	if cpaEnabled {
		clientFmt := cpaClientFormat("openai-responses")
		upstreamFmt := formatForUpstream(upstream)
		canonicalEffort := chatReq.ReasoningEffort
		// Responses 入站无独立 thinking 对象（推理由 reasoning.effort 表达），clientThinking 置 nil。
		fb := func([]byte) ([]byte, error) {
			return buildUpstreamBody(&chatReq, modelAliasInfo), nil
		}
		route, translated, terr := cpaTranslateRequest(r.Context(), clientFmt, upstreamFmt, respReq.Model, body, respReq.Stream, fb)
		if terr == nil && route != nil {
			cpaRoute = route
			upstreamBody = patchCPARequestForAlias(translated, canonicalEffort, nil, modelAliasInfo, upstreamFmt)
		}
		// route==nil：CPA 无该方向翻译器，upstreamBody 维持上面手写 buildUpstreamBody 结果。
	}

	// callUpstream/callUpstreamStream 内部会根据当前请求选中的 upstream.APIType 自动转换请求格式
	// 不需要在这里手动转换，避免双重转换导致请求体丢失
	// 流式响应需要特殊处理
	if respReq.Stream {
		// CPA 路径直发翻译体（跳过 callUpstreamStream 内二次 prepare；流式响应翻译 glue 待阶段3，仍走原手写 stream 分派）
		var upResp io.ReadCloser
		var status int
		var upHeader http.Header
		var err error
		if cpaRoute != nil {
			upResp, status, upHeader, err = callPreparedUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
		} else {
			upResp, status, upHeader, err = callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
		}
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			return
		}
		defer upResp.Close()

		// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
		resp := &http.Response{
			StatusCode: status,
			Body:       upResp,
			Header:     make(http.Header),
		}
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			// Anthropic 上游：先转为 Chat SSE 流，再转为 Responses SSE 流
			pr, pw := io.Pipe()
			go func() {
				defer pw.Close()
				chatW := &pipeResponseWriter{w: pw}
				anthropicStreamToChatHandler(chatW, upResp, chatReq.Model)
			}()
			chatResp := &http.Response{
				StatusCode: status,
				Body:       pr,
				Header:     make(http.Header),
			}
			responsesStreamHandler(w, r, chatResp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Responses SSE 流
			responsesStreamHandler(w, r, resp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
		}
		return
	}

	// CPA 路径用 callPreparedUpstream(raw=true) 直发翻译体拿 raw 响应；否则 callUpstream（内部二次转换）。
	var respBody []byte
	var status int
	var upHeader http.Header
	if cpaRoute != nil {
		respBody, status, upHeader, err = callPreparedUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy, true)
	} else {
		respBody, status, upHeader, err = callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream, modelAliasInfo.Socks5Proxy)
	}
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
		}
		return
	}

	// 响应翻译：
	//   - cpaRoute!=nil 时 respBody 是 raw 上游响应，需按上游格式翻回 Responses 客户端格式。
	//     Responses 入站响应方向（Chat→Responses/Claude→Responses）当前都不在白名单 → handwrittenResponseToResponses
	//     （Anthropic 上游 Claude→Chat→Responses 两段 / Chat 上游 convertChatToResponses），带 tool name mapping。
	//     cpaResponseUsableForRoute 判断接口保留：未来 Responses 响应方向入白名单后自动走 cpaTranslateNonStream。
	//   - cpaRoute==nil 时 respBody 已是 callUpstream 二次转换后的 Chat，用 convertChatToResponses。
	upstreamFmt := formatForUpstream(upstream)
	var responsesBody []byte
	if cpaRoute != nil {
		if cpaNonStreamEnabled() && cpaResponseUsableForRoute(cpaRoute, false) {
			responsesBody = cpaTranslateNonStream(r.Context(), cpaRoute, respBody, func(b []byte) []byte {
				return handwrittenResponseToResponses(b, chatReq.Model, upstreamFmt, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
			})
		} else {
			responsesBody = handwrittenResponseToResponses(respBody, chatReq.Model, upstreamFmt, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
		}
	} else {
		// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
		// callUpstream 返回的 respBody 已统一为 Chat 格式，再转为 Responses API 格式
		responsesBody = convertChatToResponses(respBody, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
	}

	var usageResp2 map[string]any
	if json.Unmarshal(responsesBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt == 0 && pt+ct > 0 {
				tt = pt + ct
			}
			if tt > 0 {
				recordTokenUsage(chatReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[responses response]\n%s", string(responsesBody))
	}
	w.Write(responsesBody)
}

// ======================== Responses Stream Handler ========================

func responsesStreamHandler(w http.ResponseWriter, _ *http.Request, resp *http.Response, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(resp.Body)

	responseID := "resp_" + time.Now().Format("20060102150405") + "_" + randomString(8)
	reasoningID := "rs_" + responseID
	msgID := "msg_" + responseID + "_0"
	createdAt := time.Now().Unix()
	seq := 0

	reasoningStarted := false
	reasoningDone := false
	messageStarted := false
	messageDone := false
	isIncomplete := false
	incompleteReason := ""
	terminalFinishSeen := false
	fullReasoning := ""
	fullText := ""
	totalUsage := map[string]any{}
	createdSent := false
	toolCalls := map[int]map[string]any{}
	toolOrder := []int{}

	messageOutputIndex := func() int {
		if reasoningStarted {
			return 1
		}
		return 0
	}

	reasoningItem := func(status string) map[string]any {
		item := map[string]any{
			"id":      reasoningID,
			"type":    "reasoning",
			"summary": []any{},
		}
		if status != "" {
			item["status"] = status
		}
		if status == "completed" {
			item["encrypted_content"] = ""
		}
		if fullReasoning != "" {
			item["content"] = []any{map[string]any{"type": "reasoning_text", "text": fullReasoning}}
		}
		return item
	}

	messageItem := func(status string) map[string]any {
		content := []any{map[string]any{
			"type":        "output_text",
			"annotations": []any{},
			"logprobs":    []any{},
			"text":        fullText,
		}}
		return map[string]any{
			"id":      msgID,
			"type":    "message",
			"status":  status,
			"content": content,
			"role":    "assistant",
		}
	}

	emitReasoningDone := func() {
		if !reasoningStarted || reasoningDone {
			return
		}
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_text.done", map[string]any{
			"type":            "response.reasoning_text.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"content_index":   0,
			"text":            fullReasoning,
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    0,
			"item":            reasoningItem("completed"),
		})
		reasoningDone = true
	}

	emitMessageDone := func() {
		if !messageStarted || messageDone {
			return
		}
		idx := messageOutputIndex()
		seq++
		emitSSEEvent(w, flusher, "response.output_text.done", map[string]any{
			"type":            "response.output_text.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"text":            fullText,
			"logprobs":        []any{},
		})
		seq++
		emitSSEEvent(w, flusher, "response.content_part.done", map[string]any{
			"type":            "response.content_part.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": fullText},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            messageItem("completed"),
		})
		messageDone = true
	}

	emitToolCallDone := func(idx int, call map[string]any) {
		if done, _ := call["done"].(bool); done {
			return
		}
		itemID, _ := call["item_id"].(string)
		callID, _ := call["call_id"].(string)
		name, _ := call["name"].(string)
		args, _ := call["arguments"].(string)
		// arguments 非法/非 object 兜底为 "{}" 继续输出该 function_call，不标记 incomplete：
		// 对照 CLIProxyAPI 流式侧（claude_openai_response.go，arguments=="" 写 "{}"），
		// 避免上游可处理却被本网关标记为不完整而丢弃整个 tool_call。
		normalizedArgs := normalizeToolCallArguments(args)
		if normalizedArgs == "{}" && strings.TrimSpace(args) != "" && strings.TrimSpace(args) != "{}" {
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.emitToolCallDone", itemID, callID, name, args, idx, fmt.Errorf("arguments not a JSON object, fallback to {}"))
		}
		call["arguments"] = normalizedArgs
		call["done"] = true
		seq++
		emitSSEEvent(w, flusher, "response.function_call_arguments.done", map[string]any{
			"type":            "response.function_call_arguments.done",
			"sequence_number": seq,
			"item_id":         itemID,
			"output_index":    idx,
			"arguments":       normalizedArgs,
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            responseFunctionCallItem(itemID, "completed", normalizedArgs, callID, name, toolNameMappings),
		})
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			return
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if !createdSent {
			if id, ok := chunk["id"].(string); ok && id != "" {
				responseID = id
				reasoningID = "rs_" + responseID + "_0"
				msgID = "msg_" + responseID + "_0"
			}
			if created, ok := chunk["created"].(float64); ok {
				createdAt = int64(created)
			}
			seq++
			emitSSEEvent(w, flusher, "response.created", map[string]any{
				"type":            "response.created",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress", "background": false, "error": nil, "output": []any{}},
			})
			seq++
			emitSSEEvent(w, flusher, "response.in_progress", map[string]any{
				"type":            "response.in_progress",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress"},
			})
			createdSent = true
		}
		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				totalUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				if !reasoningStarted {
					seq++
					emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
						"type":            "response.output_item.added",
						"sequence_number": seq,
						"output_index":    0,
						"item":            reasoningItem("in_progress"),
					})
					reasoningStarted = true
				}
				fullReasoning += rcStr
				seq++
				emitSSEEvent(w, flusher, "response.reasoning_text.delta", map[string]any{
					"type":            "response.reasoning_text.delta",
					"sequence_number": seq,
					"item_id":         reasoningID,
					"output_index":    0,
					"content_index":   0,
					"delta":           rcStr,
				})
			}
		}

		contentStr := ""
		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ = c.(string)
		}
		if contentStr != "" {
			emitReasoningDone()
			if !messageStarted {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			fullText += contentStr
			seq++
			emitSSEEvent(w, flusher, "response.output_text.delta", map[string]any{
				"type":            "response.output_text.delta",
				"sequence_number": seq,
				"item_id":         msgID,
				"output_index":    messageOutputIndex(),
				"content_index":   0,
				"delta":           contentStr,
				"logprobs":        []any{},
			})
		}

		rawToolCalls, _ := delta["tool_calls"].([]any)
		for _, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok {
				continue
			}
			idxFloat, _ := tc["index"].(float64)
			upstreamIndex := int(idxFloat)
			call, exists := toolCalls[upstreamIndex]
			if !exists {
				outputIndex := messageOutputIndex()
				if messageStarted {
					outputIndex++
				}
				outputIndex += len(toolOrder)
				callID, _ := tc["id"].(string)
				if callID == "" {
					callID = "call_" + randomString(12)
				}
				fn, _ := tc["function"].(map[string]any)
				name, _ := fn["name"].(string)
				call = map[string]any{
					"output_index": outputIndex,
					"item_id":      "fc_" + callID,
					"call_id":      callID,
					"name":         name,
					"arguments":    "",
					"done":         false,
				}
				toolCalls[upstreamIndex] = call
				toolOrder = append(toolOrder, upstreamIndex)
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    outputIndex,
					"item":            responseFunctionCallItem(call["item_id"].(string), "in_progress", "", callID, name, toolNameMappings),
				})
			}
			fn, _ := tc["function"].(map[string]any)
			if name, _ := fn["name"].(string); name != "" {
				call["name"] = name
			}
			if argDelta, _ := fn["arguments"].(string); argDelta != "" {
				call["arguments"] = call["arguments"].(string) + argDelta
				seq++
				emitSSEEvent(w, flusher, "response.function_call_arguments.delta", map[string]any{
					"type":            "response.function_call_arguments.delta",
					"sequence_number": seq,
					"item_id":         call["item_id"],
					"output_index":    call["output_index"],
					"delta":           argDelta,
				})
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			totalUsage = usage
		}
		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			terminalFinishSeen = true
			if finishReason == "length" {
				isIncomplete = true
				incompleteReason = "max_output_tokens"
			}
			emitReasoningDone()
			if !messageStarted && len(toolCalls) == 0 {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			emitMessageDone()
			for _, idx := range toolOrder {
				emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
			}
		}
	}

	if !terminalFinishSeen {
		isIncomplete = true
		if incompleteReason == "" {
			incompleteReason = "stream_ended_early"
		}
		log.Printf("[responses stream incomplete] model=%q reason=%s message_started=%t tool_calls=%d", model, incompleteReason, messageStarted, len(toolOrder))
	}

	emitReasoningDone()
	emitMessageDone()
	if terminalFinishSeen {
		for _, idx := range toolOrder {
			emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
		}
	}

	output := []any{}
	if reasoningStarted {
		output = append(output, reasoningItem("completed"))
	}
	if messageStarted {
		output = append(output, messageItem("completed"))
	}
	for _, idx := range toolOrder {
		call := toolCalls[idx]
		args, _ := call["arguments"].(string)
		// 同 emitToolCallDone：非法/非 object 兜底 "{}"，该 tool_call 仍写入 output，不标记 incomplete。
		normalizedArgs := normalizeToolCallArguments(args)
		if normalizedArgs == "{}" && strings.TrimSpace(args) != "" && strings.TrimSpace(args) != "{}" {
			itemID, _ := call["item_id"].(string)
			callID, _ := call["call_id"].(string)
			name, _ := call["name"].(string)
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.output", itemID, callID, name, args, call["output_index"].(int), fmt.Errorf("arguments not a JSON object, fallback to {}"))
		}
		call["arguments"] = normalizedArgs
		itemStatus := "completed"
		if !terminalFinishSeen {
			itemStatus = "in_progress"
		}
		output = append(output, responseFunctionCallItem(
			call["item_id"].(string),
			itemStatus,
			normalizedArgs,
			call["call_id"].(string),
			call["name"].(string),
			toolNameMappings,
		))
	}

	responseStatus := "completed"
	incompleteDetails := any(nil)
	if isIncomplete {
		responseStatus = "incomplete"
		reason := incompleteReason
		if reason == "" {
			reason = "max_output_tokens"
		}
		incompleteDetails = map[string]any{"reason": reason}
	}
	completedResponse := map[string]any{
		"id":                 responseID,
		"object":             "response",
		"created_at":         createdAt,
		"status":             responseStatus,
		"background":         false,
		"error":              nil,
		"incomplete_details": incompleteDetails,
		"model":              model,
		"output":             output,
	}
	if len(tools) > 0 {
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		completedResponse["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		completedResponse["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}

	usage := map[string]any{}
	if len(totalUsage) > 0 {
		if v, ok := totalUsage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := totalUsage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := totalUsage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := totalUsage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := totalUsage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	completedResponse["usage"] = usage

	if len(totalUsage) > 0 {
		pt, _ := getFloat(totalUsage, "prompt_tokens", "input_tokens")
		ct, _ := getFloat(totalUsage, "completion_tokens", "output_tokens")
		tt := pt + ct
		if tt > 0 {
			recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
		}
	}

	emitSSEEvent(w, flusher, "response."+responseStatus, map[string]any{
		"type":     "response." + responseStatus,
		"response": completedResponse,
	})

	if flusher != nil {
		flusher.Flush()
	}
}

func convertChatToResponses(chatBody []byte, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) []byte {
	var chat struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: convertChatToResponses unmarshal failed: %v", err)
	}

	text := ""
	reasoning := ""
	finishReason := ""
	var toolCalls []ToolCall
	if len(chat.Choices) > 0 {
		text = chat.Choices[0].Message.Content
		reasoning = chat.Choices[0].Message.ReasoningContent
		if reasoning == "" {
			reasoning = chat.Choices[0].Message.Reasoning
		}
		toolCalls = chat.Choices[0].Message.ToolCalls
		finishReason = chat.Choices[0].FinishReason
	}

	status := "completed"
	if finishReason == "length" {
		status = "incomplete"
	}

	responses := map[string]any{
		"id":                 chat.ID,
		"object":             "response",
		"status":             status,
		"background":         false,
		"error":              nil,
		"incomplete_details": nil,
		"model":              model,
		"created_at":         chat.Created,
	}
	if len(tools) > 0 {
		// 回显时使用 Responses tools 形态
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		responses["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		responses["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}
	outputID := "msg_" + chat.ID + "_0"
	output := []any{}
	if reasoning != "" {
		output = append(output, map[string]any{
			"id":                "rs_" + chat.ID,
			"type":              "reasoning",
			"encrypted_content": "",
			"summary":           []any{map[string]any{"type": "summary_text", "text": reasoning}},
			"content":           []any{map[string]any{"type": "reasoning_text", "text": reasoning}},
		})
	}
	// 有文本时输出 message；仅有 tool_calls 时不注入空 message（与流式路径一致）
	if text != "" || len(toolCalls) == 0 {
		output = append(output, map[string]any{
			"id":     outputID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{map[string]any{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
				"logprobs":    []any{},
			}},
		})
	}
	for _, tc := range toolCalls {
		output = append(output, responseFunctionCallItem("fc_"+tc.ID, "completed", tc.Function.Arguments, tc.ID, tc.Function.Name, toolNameMappings))
	}
	responses["output"] = output
	usage := map[string]any{}
	if chat.Usage != nil {
		if v, ok := chat.Usage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := chat.Usage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := chat.Usage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := chat.Usage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := chat.Usage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	responses["usage"] = usage

	// 非流式 Responses API 直接返回 response 对象，不包成 SSE 事件外壳
	result, _ := json.Marshal(responses)
	return result
}

func emitSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, data map[string]any) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling SSE event: %v", err)
		return
	}
	w.Write([]byte("event: " + event + "\n"))
	w.Write([]byte("data: " + string(jsonData) + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Admin 管理页面 ========================

func upstreamModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	var probe *UpstreamConfig
	if r.Method == http.MethodPost && r.Body != nil {
		// 优先用请求体里的临时配置(未保存也能拉取),实现"填好 URL+key 直接试拉"。
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if len(strings.TrimSpace(string(data))) > 0 {
			probe = &UpstreamConfig{}
			if err := json.Unmarshal(data, probe); err != nil {
				http.Error(w, "invalid config json", http.StatusBadRequest)
				return
			}
		}
	}
	if probe == nil {
		// 没传请求体时回退用已保存配置(name 必填)。
		if name == "" {
			http.Error(w, "missing name", http.StatusBadRequest)
			return
		}
		_, up := resolveUpstream(name)
		if up == nil || up.BaseURL == "" {
			http.Error(w, "upstream not found", http.StatusNotFound)
			return
		}
		probe = cloneUpstreamConfig(up)
	}
	if probe.BaseURL == "" {
		http.Error(w, "missing base_url", http.StatusBadRequest)
		return
	}
	if name == "" {
		name = "preview"
	}
	// 始终向上游 /models 实时拉取,忽略已配置的 custom_models 快照。
	probe.CustomModels = nil
	models, err := fetchModelsFromUpstream(name, probe)
	if err != nil {
		log.Printf("上游 %s 模型拉取失败: %v", name, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ids := make([]string, 0, len(models))
	seen := map[string]struct{}{}
	for _, m := range models {
		trimmed := strings.TrimSpace(m.ID)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		ids = append(ids, trimmed)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"upstream": name,
		"models":   ids,
		"count":    len(ids),
	})
}

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 模型完全由用户在 custom_models 中配置，无需联网拉取。
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"upstreams": getConfiguredUpstreamCount(),
		"models":    countConfiguredModels(),
	})
}

func adminConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configMu.RLock()
		cfg := AppConfig{
			ModelAlias:         modelAlias,
			ReasoningEffortMap: reasoningEffortMap,
			Upstreams:          map[string]*UpstreamConfig{},
		}
		for name, upstream := range upstreamCfgs {
			cfg.Upstreams[name] = cloneUpstreamConfig(upstream)
			if cfg.Upstreams[name].APIType == UpstreamCloudflareWorkersAI {
				for i := range cfg.Upstreams[name].CloudflareCredentials {
					cfg.Upstreams[name].CloudflareCredentials[i].APIToken = ""
				}
			}
		}
		configMu.RUnlock()
		socks5Mu.RLock()
		cfg.Socks5Proxies = socks5Proxies
		socks5Mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"model_alias":          cfg.ModelAlias,
			"reasoning_effort_map": cfg.ReasoningEffortMap,
			"socks5_proxies":       cfg.Socks5Proxies,
			"upstreams":            cfg.Upstreams,
		}
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var cfg AppConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		// Cloudflare tokens are write-only. An empty token for an existing stable
		// credential ID means "keep the stored token".
		configMu.RLock()
		knownCloudflareCredentials := make([]CloudflareCredential, 0)
		for _, previous := range upstreamCfgs {
			if previous != nil && previous.APIType == UpstreamCloudflareWorkersAI {
				knownCloudflareCredentials = append(knownCloudflareCredentials, previous.CloudflareCredentials...)
			}
		}
		for name, incoming := range cfg.Upstreams {
			if incoming == nil || incoming.APIType != UpstreamCloudflareWorkersAI {
				continue
			}
			merged, err := mergeCloudflareCredentials(knownCloudflareCredentials, incoming.CloudflareCredentials)
			if err != nil {
				configMu.RUnlock()
				http.Error(w, `{"error":"invalid Cloudflare credentials"}`, http.StatusBadRequest)
				return
			}
			incoming.CloudflareCredentials = merged
			cfg.Upstreams[name] = incoming
		}
		configMu.RUnlock()
		normalizeConfig(&cfg)
		if empty := emptyCustomModelUpstreams(cfg.Upstreams); len(empty) > 0 {
			msg := "以下上游未配置模型，请点击\"获取模型列表\"或手动填写：" + strings.Join(empty, "、")
			http.Error(w, `{"error":"`+msg+`"}`, http.StatusBadRequest)
			return
		}
		// 校验别名引用的上游是否存在（前端已拦空 key/重复 key，这里后端兜底孤儿上游）
		for aliasKey, alias := range cfg.ModelAlias {
			if aliasUpstream := strings.TrimSpace(alias.Upstream); aliasUpstream != "" {
				if _, ok := cfg.Upstreams[aliasUpstream]; !ok {
					http.Error(w, `{"error":"别名 `+aliasKey+` 引用的上游 `+aliasUpstream+` 不存在"}`, http.StatusBadRequest)
					return
				}
			}
		}
		// 校验别名引用的 SOCKS5 代理是否存在（不再静默清空，避免用户不知情丢失配置）
		proxyAddrSet := make(map[string]struct{}, len(cfg.Socks5Proxies))
		for _, proxy := range cfg.Socks5Proxies {
			proxyAddrSet[strings.TrimSpace(proxy.Addr)] = struct{}{}
		}
		for aliasKey, alias := range cfg.ModelAlias {
			if aliasProxy := strings.TrimSpace(alias.Socks5Proxy); aliasProxy != "" {
				if _, ok := proxyAddrSet[aliasProxy]; !ok {
					http.Error(w, `{"error":"别名 `+aliasKey+` 引用的代理 `+aliasProxy+` 不存在"}`, http.StatusBadRequest)
					return
				}
			}
		}
		if err := saveConfig(configPath, cfg); err != nil {
			http.Error(w, `{"error":"Failed to save config"}`, http.StatusInternalServerError)
			return
		}
		upstreamsChanged := applyConfig(cfg)
		if debugMode {
			log.Printf("Config updated: aliases=%d, effort_map=%d, upstreams=%d, upstreams_changed=%v", len(cfg.ModelAlias), len(cfg.ReasoningEffortMap), len(cfg.Upstreams), upstreamsChanged)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminStatsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokenStatsMu.Lock()
		data, err := json.Marshal(tokenStats)
		tokenStatsMu.Unlock()
		if err != nil {
			http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodDelete:
		tokenStatsMu.Lock()
		tokenStats = &TokenStatsData{Models: map[string]*ModelStats{}, Daily: &DailyStats{Date: getToday(), Models: map[string]*ModelStats{}}}
		statsDate = getToday()
		tokenStatsMu.Unlock()
		saveTokenStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

func renderLoginPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminLoginHTML))
	if msg != "" {
		w.Write([]byte("<script>document.addEventListener('DOMContentLoaded',function(){var m=document.getElementById('login-msg');if(m){m.textContent='" + msg + "';m.style.display='block'}})</script>"))
	}
}

const adminLoginHTML = `<!DOCTYPE html>
<html lang="zh" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 — LLM Gateway</title>
<style>
:root{--bg:#f4f6fa;--surface:#fff;--border:#e2e6ed;--text:#1a1d26;--text-sec:#6a7180;--accent:#6c8aff;--accent-hover:#5a78f0;--radius:12px;--radius-sm:8px;--font:'Noto Sans SC',system-ui,-apple-system,sans-serif;--mono:'JetBrains Mono',Consolas,monospace}
[data-theme="dark"]{--bg:#0c0e14;--surface:#14161e;--border:#252835;--text:#e8eaf0;--text-sec:#8b90a5;--accent:#6c8aff;--accent-hover:#5a78f0}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(108,138,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(61,214,140,.03) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:400px;width:100%;position:relative;z-index:1}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:36px 32px 32px}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:20px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12px;color:var(--text-sec);margin-top:2px}
.subtitle{font-size:13px;color:var(--text-sec);margin-bottom:28px;margin-top:4px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--text-sec);margin-bottom:6px;letter-spacing:.3px}
.field input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:14px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(108,138,255,.1)}
.msg{display:none;background:rgba(240,96,96,.1);color:#d64545;padding:10px 14px;border-radius:var(--radius-sm);margin-bottom:16px;font-size:13px;text-align:center;border:1px solid rgba(240,96,96,.2)}
[data-theme="dark"] .msg{color:#f06060}
.btn{width:100%;padding:10px;border:none;border-radius:var(--radius-sm);font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font);background:var(--accent);color:#fff;transition:background .15s}
.btn:hover{background:var(--accent-hover)}
.theme-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
.theme-toggle{background:transparent;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:13px;color:var(--text-sec);font-family:var(--font);transition:all .15s}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}
@media(max-width:500px){.card{padding:24px 20px}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="theme-bar">
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">管理面板</div>
</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">☀</button>
</div>
<div class="subtitle">请输入管理密码以继续</div>
<div class="msg" id="login-msg"></div>
<form method="post" action="/login">
<div class="field">
<label for="pwd">密码</label>
<input id="pwd" name="password" type="password" placeholder="输入管理密码" autocomplete="current-password" required>
</div>
<button class="btn" type="submit">登录</button>
</form>
</div>
</div>
<script>
(function(){var t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark')}})();
function toggleTheme(){var d=document.documentElement;var n=d.getAttribute('data-theme')==='dark'?'light':'dark';if(n==='dark')d.setAttribute('data-theme','dark');else d.removeAttribute('data-theme');localStorage.setItem('theme',n);document.querySelector('.theme-toggle').textContent=n==='dark'?'🌙':'☀'}
</script>
</body>
</html>`

const adminHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Gateway 管理面板</title>
<style>
:root {
  --bg: #f4f6fa;
  --surface: #ffffff;
  --surface-2: #f0f2f7;
  --border: #e2e6ed;
  --border-light: #d0d4df;
  --text: #1a1d26;
  --text-sec: #6a7180;
  --text-ter: #9ca3b0;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.08);
  --accent-hover: #5a78f0;
  --green: #22a85a;
  --green-dim: rgba(34,168,90,.08);
  --green-hover: #1d9850;
  --orange: #d9600a;
  --orange-dim: rgba(217,96,10,.08);
  --orange-hover: #c45507;
  --red: #dc2626;
  --red-dim: rgba(220,38,38,.08);
  --radius: 12px;
  --radius-sm: 8px;
  --font: 'Noto Sans SC', system-ui, -apple-system, sans-serif;
  --mono: 'JetBrains Mono', Consolas, monospace;
  --glow-a: rgba(108,138,255,.03);
  --glow-b: rgba(61,214,140,.02);
  --stats-total-bg: #f0f2f7;
}
[data-theme="dark"] {
  --bg: #0c0e14;
  --surface: #14161e;
  --surface-2: #1a1d27;
  --border: #252835;
  --border-light: #2e3142;
  --text: #e8eaf0;
  --text-sec: #8b90a5;
  --text-ter: #5c6080;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.12);
  --accent-hover: #5a78f0;
  --green: #3dd68c;
  --green-dim: rgba(61,214,140,.12);
  --green-hover: #30c47a;
  --orange: #f0a050;
  --orange-dim: rgba(240,160,80,.12);
  --orange-hover: #e09040;
  --red: #f06060;
  --red-dim: rgba(240,96,96,.12);
  --glow-a: rgba(108,138,255,.04);
  --glow-b: rgba(61,214,140,.03);
  --stats-total-bg: var(--surface-2);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,var(--glow-a) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,var(--glow-b) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:1020px;margin:0 auto;padding:32px 24px;position:relative;z-index:1}
header{display:flex;align-items:flex-end;gap:16px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:22px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12.5px;color:var(--text-ter);margin-bottom:2px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;transition:border-color .2s}
.card:hover{border-color:var(--border-light)}
.card h2{font-size:13px;font-weight:600;margin-bottom:16px;letter-spacing:.2px;display:flex;align-items:center;gap:8px;color:var(--text-sec);text-transform:uppercase}
.card h2 .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.config-grid{display:grid;grid-template-columns:2fr 3fr;gap:16px;margin-top:16px}
.config-grid .card{margin-bottom:0}
.full-row{grid-column:1/-1}
.form-group{margin-bottom:14px}
.form-group:last-child{margin-bottom:0}
.form-group label{display:block;font-size:11.5px;font-weight:500;color:var(--text-ter);margin-bottom:5px;letter-spacing:.4px;text-transform:uppercase}
.form-group input[type="text"],.form-group input[type="url"],.form-group input[type="password"],.form-group textarea,.form-group select,.m-select{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:13px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus,.m-select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.form-group .hint{font-size:11px;color:var(--text-ter);margin-top:4px;line-height:1.4}
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.btn{padding:8px 16px;border-radius:var(--radius-sm);font-size:12.5px;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:var(--font);white-space:nowrap}
.btn-primary{background:var(--accent-dim);color:var(--accent)}
.btn-primary:hover{background:var(--accent);color:#fff}
.btn-default{background:var(--surface-2);color:var(--text-sec);border:1px solid var(--border)}
.btn-default:hover{border-color:var(--border-light);color:var(--text)}
.btn-success{background:var(--green-dim);color:var(--green)}
.btn-success:hover{background:var(--green);color:#fff}
.btn-warning{background:var(--orange-dim);color:var(--orange)}
.btn-warning:hover{background:var(--orange);color:#fff}
.btn-danger{background:var(--red-dim);color:var(--red)}
.btn-danger:hover{background:var(--red);color:#fff}
.btn-secondary{background:var(--surface);color:var(--text-ter);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--accent-dim);color:var(--accent);border-color:var(--accent)}
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;font-weight:500;color:var(--text-ter);padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px;letter-spacing:.4px;text-transform:uppercase;white-space:nowrap}
.tbl td{padding:7px 10px;border-bottom:1px solid var(--border)}
.tbl tr:last-child td{border-bottom:none}
.tbl input,.tbl textarea{width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.tbl textarea{min-height:72px;resize:vertical;line-height:1.4}
.tbl input:focus,.tbl textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.tbl .m-select{padding:6px 10px;font-size:12.5px}
.tbl th:last-child{width:52px}
.tbl td:last-child{white-space:nowrap;text-align:center}
#statsTable th:last-child{width:auto}
#statsTable td:last-child{text-align:left;white-space:nowrap}
.tbl .btn{padding:4px 10px;font-size:11px;white-space:nowrap}
#statsTable td:first-child{font-weight:500;color:var(--text)}
#statsTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#statsTable tbody tr:hover{background:var(--surface-2)}
#statsTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
#dailyTable th:last-child{width:auto}
#dailyTable td:last-child{text-align:left;white-space:nowrap}
#dailyTable td:first-child{font-weight:500;color:var(--text)}
#dailyTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#dailyTable tbody tr:hover{background:var(--surface-2)}
#dailyTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
.stats-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.stats-header .btns{display:flex;gap:6px;align-items:center}
.panel-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.panel-header h2{margin-bottom:0}
.panel-header .btns{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.upstream-list{display:flex;flex-direction:column;gap:10px}
.upstream-item{border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);overflow:hidden;transition:border-color .15s}
.upstream-item:hover{border-color:var(--border-light)}
.upstream-item summary{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;list-style:none;user-select:none}
.upstream-item summary::-webkit-details-marker{display:none}
.upstream-item summary::before{content:'›';font-size:19px;line-height:1;color:var(--text-ter);transition:transform .15s;flex-shrink:0}
.upstream-item[open] summary::before{transform:rotate(90deg)}
.upstream-item[open] summary{border-bottom:1px solid var(--border)}
.upstream-summary-name{font-size:13px;font-weight:600;color:var(--text);min-width:110px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.upstream-type-badge{padding:2px 7px;border-radius:999px;font-size:10px;line-height:1.5;white-space:nowrap}
.upstream-type-badge{background:var(--accent-dim);color:var(--accent)}
.upstream-summary-url{min-width:0;flex:1;color:var(--text-ter);font-family:var(--mono);font-size:11.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.upstream-summary-meta{color:var(--text-ter);font-size:10.5px;white-space:nowrap}
.upstream-body{padding:15px 14px 14px}
.upstream-form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.upstream-field{min-width:0}
.upstream-field.full{grid-column:1/-1}
.upstream-field label{display:block;font-size:10.5px;font-weight:500;color:var(--text-ter);margin-bottom:5px;letter-spacing:.35px;text-transform:uppercase}
.upstream-field input,.upstream-field textarea,.upstream-field select{width:100%;padding:8px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.upstream-field textarea{min-height:92px;resize:vertical;line-height:1.45}
.upstream-field input:focus,.upstream-field textarea:focus,.upstream-field select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.upstream-field .field-hint{margin-top:4px;color:var(--text-ter);font-size:10.5px}
.upstream-item-actions{display:flex;justify-content:flex-end;margin-top:14px;padding-top:12px;border-top:1px solid var(--border)}
.custom-models-row{display:flex;gap:8px}
.custom-models-row input{flex:1;min-width:0}
.custom-models-row .btn{flex:0 0 auto;align-self:flex-end;padding:8px 12px}
.upstream-empty{padding:24px;text-align:center;color:var(--text-ter);font-size:12.5px;border:1px dashed var(--border);border-radius:var(--radius-sm);background:var(--surface-2)}
#toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;color:#fff;opacity:0;transition:opacity .25s,transform .25s;z-index:999;transform:translateY(-8px);pointer-events:none;backdrop-filter:blur(8px)}
#toast.success{background:rgba(61,214,140,.85)}
#toast.error{background:rgba(240,96,96,.85)}
#toast.show{opacity:1;transform:translateY(0)}
.empty-hint{color:var(--text-ter);font-size:13px;padding:28px;text-align:center}
.advanced-settings{margin-top:18px;border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface-2);overflow:hidden;transition:border-color .15s}
.advanced-settings:hover{border-color:var(--border-light)}
.advanced-settings summary{display:flex;align-items:center;gap:9px;padding:11px 14px;cursor:pointer;list-style:none;color:var(--text-sec);font-size:12.5px;font-weight:600;user-select:none}
.advanced-settings summary::-webkit-details-marker{display:none}
.advanced-settings summary::before{content:'›';font-size:18px;line-height:1;color:var(--text-ter);transition:transform .15s}
.advanced-settings[open] summary::before{transform:rotate(90deg)}
.advanced-settings[open] summary{border-bottom:1px solid var(--border)}
.advanced-summary-count{margin-left:auto;color:var(--text-ter);font-size:11px;font-weight:400}
.advanced-content{padding:14px}
.advanced-hint{font-size:11px;color:var(--text-ter);margin-bottom:10px}
.effort-label-row,.effort-row{display:grid;grid-template-columns:minmax(120px,1fr) 28px minmax(120px,1fr) auto;gap:8px;align-items:center}
.effort-label-row{padding:0 1px 5px;color:var(--text-ter);font-size:10.5px;letter-spacing:.3px;text-transform:uppercase}
.effort-row{margin-bottom:8px}
.effort-row input{width:100%;padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.effort-row input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.effort-arrow{text-align:center;color:var(--text-ter);font-family:var(--mono)}
.effort-row .btn{padding:6px 10px;font-size:11px}
.effort-empty{padding:16px 8px;color:var(--text-ter);font-size:12px;text-align:center;border:1px dashed var(--border);border-radius:6px}
.effort-actions{margin-top:10px}
.think-row{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;transition:border-color .15s}
.think-row:hover{border-color:var(--border-light)}
.think-row input[type="checkbox"]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.think-row label{font-size:13px;font-weight:500;cursor:pointer;margin:0;color:var(--text)}
.think-row .hint{font-size:11px;color:var(--text-ter);margin:0 0 0 auto;white-space:nowrap}
@media(max-width:700px){.config-grid{grid-template-columns:1fr}.container{padding:16px 12px}header{flex-direction:column;align-items:flex-start;gap:8px}.effort-label-row,.effort-row{grid-template-columns:minmax(90px,1fr) 22px minmax(90px,1fr) auto}.upstream-form-grid{grid-template-columns:1fr}.upstream-field.full{grid-column:auto}.upstream-summary-url{display:none}.upstream-summary-meta{margin-left:auto}}
.theme-toggle{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;transition:all .15s;color:var(--text-sec);flex-shrink:0;line-height:1}
.theme-toggle:hover{border-color:var(--border-light);color:var(--text)}
</style>
</head>
<body>
<div class="container">
<header>
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">通用 LLM 代理网关</div>
</div>
</div>
<div style="display:flex;align-items:center;gap:8px">
<button class="theme-toggle" onclick="toggleTheme()" title="切换主题">☀</button>
<form method="post" action="/logout" style="margin:0"><button class="theme-toggle" type="submit" title="退出登录" style="font-size:14px">退出</button></form>
</div>
</header>

<div class="card">
<div class="stats-header">
<h2><span class="dot" style="background:var(--green)"></span>Token 统计</h2>
<div class="btns">
<button class="btn btn-success" onclick="reloadConfig()">刷新</button>
<button class="btn btn-danger" onclick="resetStats()">清空统计</button>
<span id="resetStatus" style="font-size:11px;color:var(--text-ter)"></span>
</div>
</div>
<div id="statsContent" style="font-size:12.5px">
<div class="empty-hint">加载中...</div>
</div>
</div>

<div class="config-grid">
<div class="card full-row">
<div class="panel-header">
<h2><span class="dot" style="background:var(--green)"></span>多上游配置</h2>
<div class="btns">
<button class="btn btn-primary" onclick="addUpstreamRow()">添加上游</button>
<button class="btn btn-success" onclick="saveConfig('上游配置')">保存上游</button>
</div>
</div>
<div class="upstream-list" id="upstreamList"></div>
</div>
<div class="card full-row">
<h2><span class="dot" style="background:var(--accent)"></span>模型映射</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="aliasTable">
<thead><tr><th style="width:12%">别名（请求名）</th><th style="width:11%">上游</th><th style="width:20%">实际模型（上游名）</th><th style="width:12%">代理出口</th><th style="width:14%">回传 reasoning</th><th style="width:11%">推理方言</th><th style="width:12%">可接受 effort</th><th style="width:8%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<details class="advanced-settings" id="reasoningEffortDetails">
<summary><span>高级设置 · 推理力度映射</span><span class="advanced-summary-count" id="effortSummary">未配置 · 原值透传</span></summary>
<div class="advanced-content">
<div class="advanced-hint">将客户端传入的 reasoning_effort 映射为上游支持的值；未配置的值保持原样。</div>
<div class="effort-label-row"><span>请求值</span><span></span><span>上游值</span><span></span></div>
<div id="effortList"></div>
<div class="effort-actions"><button class="btn btn-primary" onclick="addEffortRow()">添加映射</button></div>
</div>
</details>
<div class="actions">
<button class="btn btn-primary" onclick="addAliasRow()">添加别名</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>

<div class="card full-row">
<h2><span class="dot" style="background:var(--accent)"></span>SOCKS5 代理配置</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="socks5Table">
<thead><tr><th style="width:25%">名称</th><th style="width:28%">地址</th><th style="width:17%">用户名</th><th style="width:17%">密码</th><th style="width:13%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addSocks5Row()">添加代理</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
</div>
</div>
<div id="toast"></div>
<script>
let aliasData={},effortData={},modelListByUpstream={},upstreamData={},socks5Data=[];
function toggleTheme(){const d=document.documentElement;const cur=d.getAttribute('data-theme');const next=cur==='dark'?null:'dark';if(next)d.setAttribute('data-theme',next);else d.removeAttribute('data-theme');localStorage.setItem('theme',next||'light');document.querySelector('.theme-toggle').textContent=next==='dark'?'🌙':'☀'}
(function(){const t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');document.addEventListener('DOMContentLoaded',()=>{const b=document.querySelector('.theme-toggle');if(b)b.textContent='🌙'})}})();
function reloadConfig(){const sy=window.scrollY;fetch('/api/reload',{method:'POST'}).then(r=>r.json()).then(d=>{showToast('会话已刷新，模型 '+d.models+' 个','success')}).catch(()=>{}).finally(()=>{loadConfig();loadStats();setTimeout(()=>window.scrollTo(0,sy),100)})}
function apiTypeSelectHtml(selected){const v=selected||'openai';return '<select data-field="api_type" onchange="onUpstreamTypeChange(this)"><option value="openai"'+(v==='openai'?' selected':'')+'>OpenAI</option><option value="anthropic"'+(v==='anthropic'?' selected':'')+'>Anthropic</option><option value="openai-responses"'+(v==='openai-responses'?' selected':'')+'>Responses</option><option value="cloudflare-workers-ai"'+(v==='cloudflare-workers-ai'?' selected':'')+'>Cloudflare Workers AI</option></select>'}
function upstreamTypeLabel(value){if(value==='anthropic')return 'Anthropic';if(value==='openai-responses')return 'Responses';if(value==='cloudflare-workers-ai')return 'Cloudflare Workers AI';return 'OpenAI'}
function nonEmptyLineCount(value){return String(value||'').split(/\r?\n/).map(s=>s.trim()).filter(Boolean).length}
function customModelCount(value){return String(value||'').split(',').map(s=>s.trim()).filter(Boolean).length}
function responsesReasoningFormatHtml(value){const legacy=['reasoning_effort','legacy','legacy_reasoning_effort'].includes(value);return '<select data-field="responses_reasoning_format"><option value=""'+(!legacy?' selected':'')+'>标准 reasoning.effort</option><option value="legacy_reasoning_effort"'+(legacy?' selected':'')+'>兼容 reasoning_effort</option></select>'}
// aliasReasoningFormatHtml：推理方言下拉。""=默认透传 reasoning_effort；"thinking"=注入 thinking 对象。
function aliasReasoningFormatHtml(value){const v=(value==='thinking')?'thinking':'';return '<select data-field="reasoning_format" title="推理方言：默认透传 reasoning_effort；thinking 注入 thinking 对象"><option value=""'+(v===''?' selected':'')+'>默认 reasoning_effort</option><option value="thinking"'+(v==='thinking'?' selected':'')+'>thinking 对象</option></select>'}
// aliasAcceptedEffortsDisplay：把后端 []string 或旧逗号串统一成显示用逗号串。
function aliasAcceptedEffortsDisplay(value){if(Array.isArray(value))return value.map(s=>String(s).trim()).filter(Boolean).join(', ');if(typeof value==='string')return value.split(',').map(s=>s.trim()).filter(Boolean).join(', ');return ''}
function cfCredentialRows(credentials){return (credentials||[]).map(c=>'<tr data-cf-id="'+esc(c.id||'')+'"><td><input data-cf="account" value="'+esc(c.account_id||'')+'"></td><td><input data-cf="token" type="password" placeholder="留空保持不变"></td><td><input data-cf="enabled" type="checkbox"'+(c.enabled?' checked':'')+'></td><td data-cf="status">待验证</td><td><button type="button" class="btn btn-secondary" onclick="retryCFCredential(this)">重试</button> <button type="button" class="btn btn-danger" onclick="this.closest(\'tr\').remove()">删除</button></td></tr>').join('')}
function upstreamCardHtml(name,up,expanded){up=up||{};const apiType=up.api_type||'openai';const baseURL=up.base_url||'';const apiKey=up.api_key||'';const customModels=(up.custom_models||[]).join(',');const credentials=up.cloudflare_credentials||[];const keyCount=apiType==='cloudflare-workers-ai'?credentials.length:nonEmptyLineCount(apiKey);const modelCount=(up.custom_models||[]).length;let h='<details class="upstream-item" data-original-name="'+esc(name||'')+'"'+(expanded?' open':'')+'>';h+='<summary><span class="upstream-summary-name">'+esc(name||'未命名上游')+'</span><span class="upstream-type-badge">'+upstreamTypeLabel(apiType)+'</span><span class="upstream-summary-url">'+esc(baseURL||'尚未配置 Base URL')+'</span><span class="upstream-summary-meta">'+keyCount+' 凭据 · '+modelCount+' 模型</span></summary>';h+='<div class="upstream-body"><div class="upstream-form-grid">';h+='<div class="upstream-field"><label>名称</label><input value="'+esc(name||'')+'" data-field="name" placeholder="例如: main" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"></div>';h+='<div class="upstream-field"><label>接口类型</label>'+apiTypeSelectHtml(apiType)+'</div>';h+='<div class="upstream-field full"><label>Base URL</label><input value="'+esc(baseURL)+'" data-field="base_url" placeholder="https://example.com/v1" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"></div>';h+='<div class="upstream-field full generic-key-field"'+(apiType==='cloudflare-workers-ai'?' style="display:none"':'')+'><label>API Key（每行一个）</label><textarea data-field="api_key" placeholder="每行填写一个 API Key" oninput="updateUpstreamCardSummary(this)">'+esc(apiKey)+'</textarea></div>';h+='<div class="upstream-field full cf-credentials-field"'+(apiType==='cloudflare-workers-ai'?'':' style="display:none"')+'><label>Cloudflare 凭据</label><table class="tbl"><thead><tr><th>Account ID</th><th>新 Token</th><th>启用</th><th>状态</th><th></th></tr></thead><tbody data-cf-rows>'+cfCredentialRows(credentials)+'</tbody></table><div class="actions"><button type="button" class="btn btn-primary" onclick="addCFCredential(this)">新增凭据</button><button type="button" class="btn btn-secondary" onclick="importCFCredentials(this)">批量导入四段格式</button></div></div>';h+='<div class="upstream-field full"><label>自定义模型</label><div class="custom-models-row"><input value="'+esc(customModels)+'" data-field="custom_models" placeholder="model-a, model-b" oninput="updateUpstreamCardSummary(this)" onchange="syncUpstreamOptions()"><button type="button" class="btn btn-secondary" onclick="fetchUpstreamModels(this)">获取模型列表</button></div></div>';h+='<div class="upstream-field full responses-format-field"'+(apiType==='openai-responses'?'':' style="display:none"')+'><label>Responses 推理参数格式</label>'+responsesReasoningFormatHtml(up.responses_reasoning_format||'')+'</div>';h+='</div><div class="upstream-item-actions"><button class="btn btn-danger" onclick="delUpstream(this)">删除此上游</button></div></div></details>';return h}
function buildModelListByUpstreamFromCustomModels(){const grouped={};Object.keys(upstreamData).forEach(name=>{const arr=(upstreamData[name]&&Array.isArray(upstreamData[name].custom_models))?upstreamData[name].custom_models:(typeof (upstreamData[name]||{}).custom_models==='string'?(upstreamData[name].custom_models.split(',').map(s=>s.trim()).filter(Boolean)):[]);grouped[name]=Array.from(new Set(arr)).sort()});return grouped}
function normalizeAliasData(){const next={};const fmtVal=v=>(v==='thinking')?'thinking':'';Object.keys(aliasData||{}).forEach(k=>{const raw=aliasData[k];if(typeof raw==='object'&&raw){next[k]={target_model:raw.target_model||'',upstream:raw.upstream||'',socks5_proxy:raw.socks5_proxy||'',with_reasoning:!!raw.with_reasoning,reasoning_format:fmtVal(raw.reasoning_format),accepted_efforts:aliasAcceptedEffortsDisplay(raw.accepted_efforts)}}else{next[k]={target_model:typeof raw==='string'?raw:'',upstream:'',socks5_proxy:'',with_reasoning:false,reasoning_format:'',accepted_efforts:''}}});aliasData=next}
function normalizeUpstreamData(cfg){upstreamData=cfg.upstreams||{}}
async function loadConfig(){const sy=window.scrollY;try{const r=await fetch('/api/config');const cfg=await r.json();aliasData=cfg.model_alias||{};normalizeAliasData();effortData=cfg.reasoning_effort_map||{};socks5Data=cfg.socks5_proxies||[];normalizeUpstreamData(cfg);modelListByUpstream=buildModelListByUpstreamFromCustomModels()
renderUpstreamTable();renderAliasTable();renderEffortTable();renderSocks5Table();loadCFHealth();setTimeout(()=>window.scrollTo(0,sy),0)}catch(e){showToast('失败: '+e.message,'error')}}
function renderUpstreamTable(){const list=document.getElementById('upstreamList');const names=Object.keys(upstreamData).sort();list.innerHTML=names.length?names.map(name=>upstreamCardHtml(name,upstreamData[name],false)).join(''):'<div class="upstream-empty">暂无上游配置，请先添加一个上游。</div>';}
function addUpstreamRow(){collectUpstreams();const list=document.getElementById('upstreamList');const empty=list.querySelector('.upstream-empty');if(empty)empty.remove();list.insertAdjacentHTML('beforeend',upstreamCardHtml('',{api_type:'openai'},true));const cards=list.querySelectorAll('.upstream-item');const input=cards.length?cards[cards.length-1].querySelector('[data-field="name"]'):null;if(input)input.focus()}
function delUpstream(btn){collectAliases();const card=btn.closest('.upstream-item');if(card)card.remove();collectUpstreams();modelListByUpstream=buildModelListByUpstreamFromCustomModels();const list=document.getElementById('upstreamList');if(!list.querySelector('.upstream-item'))list.innerHTML='<div class="upstream-empty">暂无上游配置，请先添加一个上游。</div>';renderAliasTable()}
function collectUpstreams(){const r={};document.querySelectorAll('#upstreamList .upstream-item').forEach(card=>{const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';if(!name||!baseURL)return;const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value?.trim()||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const customRaw=(card.querySelector('[data-field="custom_models"]')||{}).value?.trim()||'';const reasoningFormat=(card.querySelector('[data-field="responses_reasoning_format"]')||{}).value||'';const up={base_url:baseURL,api_type:apiType};if(apiKey&&apiType!=='cloudflare-workers-ai')up.api_key=apiKey;if(apiType==='cloudflare-workers-ai'){up.cloudflare_credentials=[...card.querySelectorAll('[data-cf-rows] tr')].map(tr=>({id:tr.dataset.cfId||'',account_id:(tr.querySelector('[data-cf="account"]')||{}).value?.trim()||'',api_token:(tr.querySelector('[data-cf="token"]')||{}).value?.trim()||'',enabled:!!(tr.querySelector('[data-cf="enabled"]')||{}).checked})).filter(c=>c.account_id)}if(customRaw)up.custom_models=customRaw.split(',').map(s=>s.trim()).filter(Boolean);if(apiType==='openai-responses'&&reasoningFormat)up.responses_reasoning_format=reasoningFormat;r[name]=up;card.dataset.originalName=name});upstreamData=r;return r}
function updateUpstreamCardSummary(el){const card=el.closest('.upstream-item');if(!card)return;const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value||'';const customRaw=(card.querySelector('[data-field="custom_models"]')||{}).value||'';card.querySelector('.upstream-summary-name').textContent=name||'未命名上游';card.querySelector('.upstream-summary-url').textContent=baseURL||'尚未配置 Base URL';card.querySelector('.upstream-type-badge').textContent=upstreamTypeLabel(apiType);card.querySelector('.upstream-summary-meta').textContent=nonEmptyLineCount(apiKey)+' Key · '+customModelCount(customRaw)+' 模型'}
function onUpstreamTypeChange(sel){const card=sel.closest('.upstream-item');if(!card)return;card.querySelector('.responses-format-field').style.display=sel.value==='openai-responses'?'':'none';card.querySelector('.generic-key-field').style.display=sel.value==='cloudflare-workers-ai'?'none':'';card.querySelector('.cf-credentials-field').style.display=sel.value==='cloudflare-workers-ai'?'':'none';if(sel.value==='cloudflare-workers-ai'&&!card.querySelector('[data-field="base_url"]').value.trim())card.querySelector('[data-field="base_url"]').value='https://api.cloudflare.com/client/v4';updateUpstreamCardSummary(sel)}
function addCFCredential(btn){btn.closest('.cf-credentials-field').querySelector('[data-cf-rows]').insertAdjacentHTML('beforeend',cfCredentialRows([{id:'',account_id:'',enabled:true}]))}
async function retryCFCredential(btn){const id=btn.closest('tr').dataset.cfId;if(!id)return;const r=await fetch('/api/cloudflare/credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});if(r.ok){showToast('已重置隔离状态','success');loadCFHealth()}}
async function loadCFHealth(){try{const r=await fetch('/api/cloudflare/credentials');const d=await r.json();for(const card of document.querySelectorAll('.upstream-item')){const name=(card.querySelector('[data-field="name"]')||{}).value||'';const views=(d.upstreams||{})[name]||[];const byId=Object.fromEntries(views.map(v=>[v.id,v]));for(const tr of card.querySelectorAll('[data-cf-rows] tr')){const v=byId[tr.dataset.cfId];if(v){tr.querySelector('[data-cf="status"]').textContent=v.status+(v.last_error_code?' · '+v.last_error_code:'')+(v.token_suffix?' · '+v.token_suffix:'')}}}}catch(e){}}
async function importCFCredentials(){const source=prompt('粘贴四段格式（邮箱、密码、Account ID、API Token）；邮箱和密码不会保存：');if(!source)return;const r=await fetch('/api/cloudflare/credentials/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source})});if(!r.ok){showToast('导入失败','error');return}const d=await r.json();showToast('已导入 '+d.added+' 组，共 '+d.total+' 组','success');loadConfig()}
function syncUpstreamOptions(){collectAliases();collectUpstreams();modelListByUpstream=buildModelListByUpstreamFromCustomModels();renderAliasTable()}function fetchUpstreamModels(btn){const card=btn.closest('.upstream-item');if(!card)return;const name=(card.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(card.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';if(!baseURL){alert('请先填写 Base URL');return}const apiKey=(card.querySelector('[data-field="api_key"]')||{}).value||'';const apiType=(card.querySelector('[data-field="api_type"]')||{}).value||'openai';const input=card.querySelector('[data-field="custom_models"]');const body={base_url:baseURL,api_type:apiType};if(apiKey)body.api_key=apiKey;const orig=btn.textContent;btn.disabled=true;btn.textContent='获取中…';const options=apiType==='cloudflare-workers-ai'?{method:'GET'}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};fetch('/api/upstream/models?name='+encodeURIComponent(name),options).then(r=>{if(!r.ok){return r.text().then(t=>{throw new Error(t||('HTTP '+r.status))})}return r.json()}).then(d=>{const arr=Array.isArray(d.models)?d.models:[];if(arr.length===0){alert('上游未返回任何模型');return}input.value=arr.join(', ');updateUpstreamCardSummary(input);syncUpstreamOptions();btn.textContent='已填充 '+arr.length+' 个'}).catch(e=>{alert('获取失败: '+(e&&e.message?e.message:e))}).finally(()=>{btn.disabled=false;btn.textContent=orig})}

function modelsForUpstream(name){const resolved=(name||'').trim();return modelListByUpstream[resolved]||[]}
function upstreamSelectHtml(selected){const names=Object.keys(upstreamData).sort();if(names.length===0)return '<select data-field="upstream" class="m-select" disabled><option value="">（未配置上游）</option></select>';let h='<select data-field="upstream" class="m-select" onchange="onAliasUpstreamChange(this)">';for(const name of names){h+='<option value="'+esc(name)+'"'+(selected===name?' selected':'')+'>'+esc(name)+'</option>'}h+='</select>';return h}
function modelSelectHtml(selected,upstreamName){const models=modelsForUpstream(upstreamName);if(models.length===0)return '<select data-field="val" class="m-select" disabled><option value="">（未配置模型）</option></select>';let h='<select data-field="val" class="m-select">';let found=!selected;for(const m of models){if(selected===m)found=true;h+='<option value="'+esc(m)+'"'+(selected===m?' selected':'')+'>'+esc(m)+'</option>'}if(selected&&!found)h+='<option value="'+esc(selected)+'" selected>'+esc(selected)+' (自定义)</option>';h+='</select>';return h}
function socks5SelectHtml(selected){let h='<select data-field="socks5_proxy" class="m-select"><option value="">直连</option>';let found=!selected;for(const p of socks5Data){if(!p||!p.addr)continue;const addr=String(p.addr).trim();if(!addr)continue;if(selected===addr)found=true;const label=p.name?String(p.name)+' ('+addr+')':addr;h+='<option value="'+esc(addr)+'"'+(selected===addr?' selected':'')+'>'+esc(label)+'</option>'}if(selected&&!found)h+='<option value="'+esc(selected)+'" selected>'+esc(selected)+' (已失效)</option>';h+='</select>';return h}
function renderAliasTable(){const tb=document.querySelector('#aliasTable tbody');const ks=Object.keys(aliasData);if(!ks.length){tb.innerHTML='<tr><td colspan="8" class="empty-hint">暂无别名配置</td></tr>';return}const sortedUpstreams=Object.keys(upstreamData).sort();const defaultUp=(sortedUpstreams.length&&sortedUpstreams[0])||'';tb.innerHTML=ks.map(k=>{const entry=aliasData[k]||{target_model:'',upstream:'',socks5_proxy:'',with_reasoning:false,reasoning_format:'',accepted_efforts:''};const upName=entry.upstream||defaultUp;return '<tr><td><input value="'+esc(k)+'" data-field="key"></td><td>'+upstreamSelectHtml(upName)+'</td><td data-model-cell="1">'+modelSelectHtml(entry.target_model||'',upName)+'</td><td>'+socks5SelectHtml(entry.socks5_proxy||'')+'</td><td><input type="checkbox" data-field="with_reasoning" title="将历史 assistant 消息中的 reasoning_content 回传给上游"'+(entry.with_reasoning?' checked':'')+'></td><td>'+aliasReasoningFormatHtml(entry.reasoning_format||'')+'</td><td><input value="'+esc(esc(entry.accepted_efforts||''))+'" data-field="accepted_efforts" placeholder="none,low,medium,high,xhigh,max" title="该上游可接受的 effort 档集合，逗号分隔；空=不限制"></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>'}).join('')}
function onAliasUpstreamChange(sel){const row=sel.closest('tr');const holder=row.querySelector('[data-model-cell]');const current=row.querySelector('[data-field="val"]');const currentVal=current?current.value.trim():'';holder.innerHTML=modelSelectHtml(currentVal,sel.value)}
function addAliasRow(){collectUpstreams();collectSocks5();const tb=document.querySelector('#aliasTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';const sortedUpstreams=Object.keys(upstreamData).sort();const defaultUp=(sortedUpstreams.length&&sortedUpstreams[0])||'';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: gpt-5.5" data-field="key"></td><td>'+upstreamSelectHtml(defaultUp)+'</td><td data-model-cell="1">'+modelSelectHtml('', defaultUp)+'</td><td>'+socks5SelectHtml('')+'</td><td><input type="checkbox" data-field="with_reasoning" title="将历史 assistant 消息中的 reasoning_content 回传给上游"></td><td>'+aliasReasoningFormatHtml('')+'</td><td><input value="" data-field="accepted_efforts" placeholder="none,low,medium,high,xhigh,max" title="该上游可接受的 effort 档集合，逗号分隔；空=不限制"></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>')}
function delAlias(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&aliasData[ki.value])delete aliasData[ki.value];row.remove();if(!Object.keys(aliasData).length)document.querySelector('#aliasTable tbody').innerHTML='<tr><td colspan="8" class="empty-hint">暂无别名配置</td></tr>'}
function collectAliases(){const r={};document.querySelectorAll('#aliasTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),u=tr.querySelector('[data-field="upstream"]'),v=tr.querySelector('[data-field="val"]'),p=tr.querySelector('[data-field="socks5_proxy"]'),w=tr.querySelector('[data-field="with_reasoning"]'),rf=tr.querySelector('[data-field="reasoning_format"]'),ae=tr.querySelector('[data-field="accepted_efforts"]');if(k&&k.value.trim()){const aliasKey=k.value.trim();let targetModel=v?v.value.trim():'';const upstreamName=u?u.value.trim():'';const socks5Proxy=p?p.value.trim():'';const withReasoning=w?w.checked:false;const reasoningFormat=rf?rf.value.trim():'';const acceptedEfforts=ae?ae.value.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean):[];const acceptedDedup=Array.from(new Set(acceptedEfforts));if(!targetModel&&(upstreamName||socks5Proxy||withReasoning||reasoningFormat||acceptedDedup.length))targetModel=aliasKey;if(targetModel||upstreamName||socks5Proxy||withReasoning||reasoningFormat||acceptedDedup.length){r[aliasKey]={target_model:targetModel,upstream:upstreamName,socks5_proxy:socks5Proxy,with_reasoning:withReasoning};if(reasoningFormat)r[aliasKey].reasoning_format=reasoningFormat;if(acceptedDedup.length)r[aliasKey].accepted_efforts=acceptedDedup}}});aliasData=r;return r}






function effortRowHtml(key,val){return '<div class="effort-row"><input value="'+esc(key||'')+'" data-field="key" placeholder="例如: low"><span class="effort-arrow">→</span><input value="'+esc(val||'')+'" data-field="val" placeholder="例如: high"><button class="btn btn-danger" onclick="delEffort(this)">删除</button></div>'}
function updateEffortSummary(){const el=document.getElementById('effortSummary');if(!el)return;const count=Object.keys(effortData||{}).length;el.textContent=count?count+' 条映射':'未配置 · 原值透传'}
function renderEffortTable(){const list=document.getElementById('effortList');const ks=Object.keys(effortData);list.innerHTML=ks.length?ks.map(k=>effortRowHtml(k,effortData[k])).join(''):'<div class="effort-empty">未配置，reasoning_effort 将按原值透传</div>';updateEffortSummary()}
function addEffortRow(){collectEfforts();const details=document.getElementById('reasoningEffortDetails');details.open=true;const list=document.getElementById('effortList');const empty=list.querySelector('.effort-empty');if(empty)empty.remove();list.insertAdjacentHTML('beforeend',effortRowHtml('',''));const rows=list.querySelectorAll('.effort-row');const input=rows.length?rows[rows.length-1].querySelector('[data-field="key"]'):null;if(input)input.focus()}
function delEffort(btn){const row=btn.closest('.effort-row');if(row)row.remove();collectEfforts();renderEffortTable()}
function collectEfforts(){const r={};document.querySelectorAll('#effortList .effort-row').forEach(row=>{const k=row.querySelector('[data-field="key"]'),v=row.querySelector('[data-field="val"]');if(k&&k.value.trim())r[k.value.trim()]=v?v.value.trim():''});effortData=r;updateEffortSummary();return r}
function renderSocks5Table(){const tb=document.querySelector('#socks5Table tbody');if(!socks5Data.length){tb.innerHTML='<tr><td colspan="5" class="empty-hint">暂无代理配置</td></tr>';return}tb.innerHTML=socks5Data.map((p,i)=>'<tr><td><input value="'+esc(p.name||'')+'" data-field="name" onchange="syncSocks5AliasOptions()"></td><td><input value="'+esc(p.addr)+'" data-field="addr" placeholder="例如: 127.0.0.1:1080" onchange="syncSocks5AliasOptions()"></td><td><input value="'+esc(p.username||'')+'" data-field="username"></td><td><input value="'+esc(p.password||'')+'" data-field="password" type="password"></td><td><button class="btn btn-danger" onclick="delSocks5('+i+')">删除</button></td></tr>').join('')}
function addSocks5Row(){collectSocks5();socks5Data.push({addr:'',name:''});renderSocks5Table()}
function delSocks5(i){collectAliases();const rows=document.querySelectorAll('#socks5Table tbody tr');if(rows[i])rows[i].remove();collectSocks5();renderSocks5Table();renderAliasTable()}
function collectSocks5(){const r=[];document.querySelectorAll('#socks5Table tbody tr').forEach(tr=>{const a=tr.querySelector('[data-field="addr"]');if(a&&a.value.trim())r.push({addr:a.value.trim(),name:(tr.querySelector('[data-field="name"]')||{}).value?.trim()||'',username:(tr.querySelector('[data-field="username"]')||{}).value?.trim()||'',password:(tr.querySelector('[data-field="password"]')||{}).value?.trim()||''})});socks5Data=r;return r}
function syncSocks5AliasOptions(){collectAliases();collectSocks5();renderAliasTable()}
async function saveConfig(section){const aliasRows=[...document.querySelectorAll('#aliasTable tbody tr')];if(aliasRows.some(tr=>{const k=tr.querySelector('[data-field="key"]');return k&&!k.value.trim()})){showToast('存在别名（请求名）为空的行，请填写后再保存','error');return}const dupCheck={};for(const tr of aliasRows){const k=tr.querySelector('[data-field="key"]');const key=k?k.value.trim():'';if(key){if(dupCheck[key]){showToast('存在重复的别名「'+key+'」，请修改后再保存','error');return}dupCheck[key]=true}}collectAliases();collectUpstreams();collectEfforts();collectSocks5();const cfg={model_alias:aliasData,reasoning_effort_map:effortData,socks5_proxies:socks5Data,upstreams:upstreamData};const label=section||'配置';try{const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});if(!r.ok)throw new Error(await r.text());showToast(label+'已保存','success');loadConfig()}catch(e){showToast(label+'保存失败: '+e.message,'error')}}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML.replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
function showToast(msg,t){const e=document.getElementById('toast');e.textContent=msg;e.className=t+' show';clearTimeout(e._tid);e._tid=setTimeout(()=>e.classList.remove('show'),2500)}
async function resetStats(){if(!confirm('确认清空所有 Token 统计？\n此操作不可撤销。'))return;const s=document.getElementById('resetStatus');s.textContent='清空中...';try{const r=await fetch('/api/stats',{method:'DELETE'});if(!r.ok)throw new Error(await r.text());document.getElementById('statsContent').innerHTML='<div class="empty-hint">暂无数据</div>';s.textContent='已清空';setTimeout(()=>s.textContent='',2000)}catch(e){s.textContent='失败: '+e.message}}
async function loadStats(){try{const r=await fetch('/api/stats');const d=await r.json();const ms=d.models||{};const ks=Object.keys(ms);const dm=d.daily?d.daily.models||{}:{};const dk=Object.keys(dm);let h='';if(d.daily&&d.daily.date){h+='<div style="margin-bottom:16px;padding:10px 14px;background:var(--accent);color:#fff;border-radius:8px;font-size:13px">📊 今日统计 ('+esc(d.daily.date)+')：请求 '+fmt(d.daily.total_requests)+' 次</div>'}if(dk.length>0){h+='<h3 style="font-size:14px;font-weight:600;margin:0 0 8px">今日模型用量</h3><table class="tbl" id="dailyTable"><thead><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总计 Token</th></tr></thead><tbody>';let dr=0,dp=0,dc=0,dt=0;for(const k of dk){const m=dm[k];if(!m)continue;h+='<tr><td>'+esc(k)+'</td><td>'+fmt(m.request_count)+'</td><td>'+fmt(m.prompt_tokens)+'</td><td>'+fmt(m.completion_tokens)+'</td><td>'+fmt(m.total_tokens)+'</td></tr>';dr+=m.request_count;dp+=m.prompt_tokens;dc+=m.completion_tokens;dt+=m.total_tokens}h+='<tr style="font-weight:600"><td>今日合计</td><td>'+fmt(dr)+'</td><td>'+fmt(dp)+'</td><td>'+fmt(dc)+'</td><td>'+fmt(dt)+'</td></tr>';h+='</tbody></table><hr style="border:none;border-top:1px solid var(--border);margin:20px 0">'}h+='<h3 style="font-size:14px;font-weight:600;margin:0 0 8px">累计统计</h3><table class="tbl" id="statsTable"><thead><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总计 Token</th></tr></thead><tbody>';if(!ks.length){h+='<tr><td colspan="5" class="empty-hint">暂无数据</td></tr>'}else{let tr=0,pt=0,ct=0,tt=0;for(const k of ks){const m=ms[k];h+='<tr><td>'+esc(k)+'</td><td>'+fmt(m.request_count)+'</td><td>'+fmt(m.prompt_tokens)+'</td><td>'+fmt(m.completion_tokens)+'</td><td>'+fmt(m.total_tokens)+'</td></tr>';tr+=m.request_count;pt+=m.prompt_tokens;ct+=m.completion_tokens;tt+=m.total_tokens}h+='<tr style="font-weight:600"><td>累计总计</td><td>'+fmt(tr)+'</td><td>'+fmt(pt)+'</td><td>'+fmt(ct)+'</td><td>'+fmt(tt)+'</td></tr>'}h+='</tbody></table>';document.getElementById('statsContent').innerHTML=h}catch(e){document.getElementById('statsContent').innerHTML='<div class="empty-hint">加载失败</div>'}}
function fmt(n){return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g,',')}window.onload=function(){loadConfig();loadStats()};setInterval(loadStats,5000);document.addEventListener('visibilitychange',function(){if(!document.hidden)loadStats()});
</script>
</body>
</html>`

// ======================== Main ========================

func main() {
	flag.StringVar(&port, "port", "8000", "服务端口；纯端口(如 8000)监听所有网卡，含冒号(如 100.89.104.82:8000)则只监听该 IP")
	flag.StringVar(&configPath, "config", "config.json", "配置文件路径")
	flag.StringVar(&adminPassword, "password", "", "管理面板密码（留空则不启用登录验证）")
	flag.StringVar(&cloudflareImportPath, "import-cloudflare-credentials", "", "从四段格式文件导入 Cloudflare 凭据后退出")
	flag.BoolVar(&cloudflareVerify, "verify-cloudflare-credentials", false, "使用模型搜索逐一验证 Cloudflare 凭据后退出")
	flag.BoolVar(&debugMode, "debug", false, "启用调试日志")
	flag.Parse()
	if cloudflareImportPath != "" {
		data, err := os.ReadFile(cloudflareImportPath)
		if err != nil {
			log.Fatalf("Cloudflare 凭据文件读取失败: %v", err)
		}
		credentials, err := parseCloudflareCredentialSource(data)
		if err != nil {
			log.Fatalf("Cloudflare 凭据格式无效: %v", err)
		}
		cfg := loadConfig(configPath)
		upstream := cfg.Upstreams["cloudflare-workers-ai"]
		if upstream == nil {
			upstream = &UpstreamConfig{BaseURL: cloudflareDefaultBaseURL, APIType: UpstreamCloudflareWorkersAI}
			cfg.Upstreams["cloudflare-workers-ai"] = upstream
		}
		if upstream.APIType != UpstreamCloudflareWorkersAI {
			log.Fatal("cloudflare-workers-ai 名称已被其他上游类型占用")
		}
		existing := map[string]struct{}{}
		for _, c := range upstream.CloudflareCredentials {
			existing[c.AccountID+"\x00"+c.APIToken] = struct{}{}
		}
		added := 0
		for _, c := range credentials {
			key := c.AccountID + "\x00" + c.APIToken
			if _, ok := existing[key]; ok {
				continue
			}
			existing[key] = struct{}{}
			upstream.CloudflareCredentials = append(upstream.CloudflareCredentials, c)
			added++
		}
		if err := saveConfig(configPath, cfg); err != nil {
			log.Fatalf("Cloudflare 凭据保存失败: %v", err)
		}
		log.Printf("Cloudflare 凭据导入完成: parsed=%d added=%d total=%d", len(credentials), added, len(upstream.CloudflareCredentials))
		return
	}
	if cloudflareVerify {
		cfg := loadConfig(configPath)
		upstream := cfg.Upstreams["cloudflare-workers-ai"]
		if upstream == nil {
			log.Fatal("未配置 cloudflare-workers-ai 上游")
		}
		report := verifyCloudflareCredentials(context.Background(), upstream)
		log.Printf("Cloudflare 凭据验证完成: total=%d success=%d failed=%d statuses=%v codes=%v", report.Total, report.Success, report.Failed, report.Statuses, report.Codes)
		if report.Failed > 0 {
			os.Exit(1)
		}
		return
	}

	cfg := loadConfig(configPath)
	applyConfig(cfg)
	if err := saveConfig(configPath, cfg); err != nil {
		log.Printf("警告: 无法保存配置: %v", err)
	}

	loadTokenStats()
	log.Printf("配置已从 %s 加载", configPath)
	log.Printf("LLM Gateway")
	log.Printf("===================")
	log.Printf("端口:     %s", port)
	log.Printf("上游:     %d 个", getConfiguredUpstreamCount())
	log.Printf("模型：  %d 个自定义模型", countConfiguredModels())
	log.Printf("别名：  %d", len(modelAlias))

	if adminPassword != "" {
		log.Printf("管理面板: http://localhost:%s/ （密码认证已启用）", port)
	} else {
		log.Printf("管理面板: http://localhost:%s/ （无密码）", port)
	}
	log.Printf("===================")
	http.HandleFunc("/v1/chat/completions", chatCompletionsHandler)
	http.HandleFunc("/v1/responses", responsesHandler)
	http.HandleFunc("/v1/messages", anthropicMessagesHandler)
	http.HandleFunc("/v1/messages/count_tokens", anthropicCountTokensHandler)
	http.HandleFunc("/v1/models", listModelsHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/api/config", requireAuth(adminConfigHandler))
	http.HandleFunc("/api/stats", requireAuth(adminStatsHandler))
	http.HandleFunc("/api/reload", requireAuth(reloadHandler))
	http.HandleFunc("/api/upstream/models", requireAuth(upstreamModelsHandler))
	http.HandleFunc("/api/cloudflare/credentials", requireAuth(cloudflareCredentialsHandler))
	http.HandleFunc("/api/cloudflare/credentials/import", requireAuth(cloudflareCredentialImportHandler))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			requireAuth(adminPageHandler)(w, r)
			return
		}
		http.NotFound(w, r)
	})
	// -port 已含冒号(如 "100.89.104.82:8000")则视为完整监听地址，否则仅端口号，监听所有网卡。
	addr := port
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	log.Printf("服务器启动在 %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
