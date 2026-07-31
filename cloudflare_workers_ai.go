package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cloudflareDefaultBaseURL = "https://api.cloudflare.com/client/v4"
	cloudflareAttemptBudget  = 30 * time.Second
	cloudflareModelTimeout   = 5 * time.Second
)

// CloudflareCredential deliberately binds an account to its token. APIKey is
// not used for this upstream type because rotating either half independently is
// invalid.
type CloudflareCredential struct {
	ID        string `json:"id"`
	AccountID string `json:"account_id"`
	APIToken  string `json:"api_token,omitempty"`
	Enabled   bool   `json:"enabled"`
}

type cloudflareCredentialState struct {
	InFlight       int
	CooldownUntil  time.Time
	Quarantined    bool
	AccountBlocked bool
	ModelBlocked   map[string]bool
	LastStatus     int
	LastCode       int
	LastError      string
}

type cloudflarePoolState struct {
	mu     sync.Mutex
	cursor map[string]int
	state  map[string]*cloudflareCredentialState
	now    func() time.Time
}

var cloudflarePool = &cloudflarePoolState{
	cursor: map[string]int{},
	state:  map[string]*cloudflareCredentialState{},
	now:    time.Now,
}

func stableCloudflareCredentialID(accountID, token string) string {
	sum := sha256.Sum256([]byte(accountID + "\x00" + token))
	return "cf_" + hex.EncodeToString(sum[:8])
}

func normalizeCloudflareCredential(c CloudflareCredential) (CloudflareCredential, bool) {
	c.ID = strings.TrimSpace(c.ID)
	c.AccountID = strings.TrimSpace(c.AccountID)
	c.APIToken = strings.TrimSpace(c.APIToken)
	if c.ID == "" && c.AccountID != "" && c.APIToken != "" {
		c.ID = stableCloudflareCredentialID(c.AccountID, c.APIToken)
	}
	return c, c.ID != "" && c.AccountID != ""
}

func cloneCloudflareCredentials(in []CloudflareCredential) []CloudflareCredential {
	return append([]CloudflareCredential(nil), in...)
}

// parseCloudflareCredentialSource accepts the agreed four-line record format:
// email, password, account id, API token. Only the final two fields are ever
// returned. Blank lines may separate records; malformed records fail closed.
func parseCloudflareCredentialSource(data []byte) ([]CloudflareCredential, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("credential source is empty")
	}
	records := make([][4]string, 0)
	// The generated source format is one record per line, separated by four
	// hyphens, and may contain a short human-readable preamble. Also accept the
	// equivalent four-lines-per-record form for manual imports.
	delimited := false
	for _, line := range lines {
		if strings.Contains(line, "----") {
			delimited = true
			break
		}
	}
	if delimited {
		started := false
		for _, line := range lines {
			parts := strings.Split(line, "----")
			validShape := len(parts) == 4 && len(strings.TrimSpace(parts[2])) >= 20 && len(strings.TrimSpace(parts[3])) >= 20
			if !validShape {
				if started {
					return nil, fmt.Errorf("malformed record after credential data")
				}
				continue
			}
			started = true
			var record [4]string
			for i := range parts {
				record[i] = strings.TrimSpace(parts[i])
			}
			records = append(records, record)
		}
	} else {
		if len(lines)%4 != 0 {
			return nil, fmt.Errorf("credential source must contain complete four-line records")
		}
		for i := 0; i < len(lines); i += 4 {
			records = append(records, [4]string{lines[i], lines[i+1], lines[i+2], lines[i+3]})
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("credential source contains no records")
	}
	seen := map[string]struct{}{}
	result := make([]CloudflareCredential, 0, len(records))
	for i, record := range records {
		accountID, token := record[2], record[3]
		if len(accountID) < 20 || strings.ContainsAny(accountID, " \t/") {
			return nil, fmt.Errorf("record %d has an invalid account id", i+1)
		}
		if len(token) < 20 || strings.ContainsAny(token, " \t\r\n") {
			return nil, fmt.Errorf("record %d has an invalid API token", i+1)
		}
		key := accountID + "\x00" + token
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, CloudflareCredential{
			ID: stableCloudflareCredentialID(accountID, token), AccountID: accountID,
			APIToken: token, Enabled: true,
		})
	}
	return result, nil
}

func mergeCloudflareCredentials(old, incoming []CloudflareCredential) ([]CloudflareCredential, error) {
	oldByID := make(map[string]CloudflareCredential, len(old))
	for _, c := range old {
		oldByID[c.ID] = c
	}
	seen := map[string]struct{}{}
	out := make([]CloudflareCredential, 0, len(incoming))
	for _, raw := range incoming {
		c, ok := normalizeCloudflareCredential(raw)
		if !ok {
			return nil, fmt.Errorf("cloudflare credential requires id and account_id")
		}
		if previous, exists := oldByID[c.ID]; exists && c.APIToken == "" {
			c.APIToken = previous.APIToken
		}
		if c.APIToken == "" {
			return nil, fmt.Errorf("new cloudflare credential %q requires api_token", c.ID)
		}
		if _, exists := seen[c.ID]; exists {
			return nil, fmt.Errorf("duplicate cloudflare credential id %q", c.ID)
		}
		seen[c.ID] = struct{}{}
		out = append(out, c)
	}
	return out, nil
}

func maskCloudflareToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if len(token) <= 4 {
		return "****"
	}
	return "****" + token[len(token)-4:]
}

func nextUTCReset(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
}

func parseRetryAfter(value string, now time.Time) time.Time {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when
	}
	return now.Add(time.Second)
}

func cloudflareErrorCode(body []byte) (int, string) {
	var envelope struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &envelope) == nil && len(envelope.Errors) > 0 {
		return envelope.Errors[0].Code, envelope.Errors[0].Message
	}
	var direct struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &direct) == nil {
		return direct.Error.Code, direct.Error.Message
	}
	return 0, ""
}

func sanitizeCloudflareText(text string, credentials []CloudflareCredential) string {
	for _, c := range credentials {
		if c.APIToken != "" {
			text = strings.ReplaceAll(text, c.APIToken, "[REDACTED]")
		}
	}
	if len(text) > 1024 {
		text = text[:1024]
	}
	return text
}

func (p *cloudflarePoolState) selectCredential(upstreamName, model string, cfg *UpstreamConfig, tried map[string]bool) (CloudflareCredential, bool, time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	credentials := cfg.CloudflareCredentials
	if len(credentials) == 0 {
		return CloudflareCredential{}, false, time.Time{}, false
	}
	start := p.cursor[upstreamName] % len(credentials)
	earliest := time.Time{}
	bestIndex := -1
	busy := false
	for offset := 0; offset < len(credentials); offset++ {
		i := (start + offset) % len(credentials)
		c := credentials[i]
		if !c.Enabled || c.APIToken == "" || tried[c.ID] {
			continue
		}
		s := p.state[c.ID]
		if s == nil {
			s = &cloudflareCredentialState{ModelBlocked: map[string]bool{}}
			p.state[c.ID] = s
		}
		if s.Quarantined || s.AccountBlocked || s.ModelBlocked[model] {
			continue
		}
		if s.InFlight > 0 {
			busy = true
			continue
		}
		if s.CooldownUntil.After(now) {
			if earliest.IsZero() || s.CooldownUntil.Before(earliest) {
				earliest = s.CooldownUntil
			}
			continue
		}
		bestIndex = i
		break
	}
	if bestIndex < 0 {
		return CloudflareCredential{}, false, earliest, busy
	}
	c := credentials[bestIndex]
	s := p.state[c.ID]
	s.InFlight++
	p.cursor[upstreamName] = (bestIndex + 1) % len(credentials)
	return c, true, earliest, busy
}

func (p *cloudflarePoolState) finish(c CloudflareCredential, model string, status, code int, message string, retryAfter string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.state[c.ID]
	if s == nil {
		s = &cloudflareCredentialState{ModelBlocked: map[string]bool{}}
		p.state[c.ID] = s
	}
	if s.InFlight > 0 {
		s.InFlight--
	}
	s.LastStatus, s.LastCode, s.LastError = status, code, message
	now := p.now()
	switch {
	case status >= 200 && status < 300:
		s.LastError = ""
	case status == http.StatusTooManyRequests && code == 3036:
		s.CooldownUntil = nextUTCReset(now)
	case status == http.StatusUnauthorized || (status == http.StatusForbidden && code != 3023 && code != 5016 && code != 5018 && code != 3041 && code != 5035):
		s.Quarantined = true
	case status == http.StatusForbidden && code == 3023:
		s.AccountBlocked = true
	case code == 5016 || code == 5018 || code == 3041 || code == 5035:
		s.ModelBlocked[model] = true
	case status == http.StatusTooManyRequests && code != 3040:
		s.CooldownUntil = parseRetryAfter(retryAfter, now)
	}
}

func resetCloudflareCredentialState(id string) bool {
	cloudflarePool.mu.Lock()
	defer cloudflarePool.mu.Unlock()
	if _, ok := cloudflarePool.state[id]; !ok {
		return false
	}
	delete(cloudflarePool.state, id)
	return true
}

func resetCloudflarePoolState() {
	cloudflarePool.mu.Lock()
	defer cloudflarePool.mu.Unlock()
	cloudflarePool.state = map[string]*cloudflareCredentialState{}
	cloudflarePool.cursor = map[string]int{}
}

func cloudflareEndpoint(cfg *UpstreamConfig, c CloudflareCredential) string {
	base := strings.TrimRight(cfg.BaseURL, "/")
	return base + "/accounts/" + url.PathEscape(c.AccountID) + "/ai/v1/chat/completions"
}

func cloudflareRetryable(status, code int) (retry bool, platformCapacity bool) {
	if status == http.StatusRequestTimeout || status >= 500 {
		return true, false
	}
	if status == http.StatusTooManyRequests {
		return true, code == 3040
	}
	if status == http.StatusUnauthorized {
		return true, false
	}
	if status == http.StatusForbidden {
		switch code {
		case 3023, 5016, 5018, 3041, 5035:
			return true, false
		}
	}
	return false, false
}

func cloudflareUnavailableBody(message string, status int, retry time.Time) ([]byte, int, http.Header, error) {
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	h := make(http.Header)
	if !retry.IsZero() {
		seconds := int(time.Until(retry).Seconds())
		if seconds < 0 {
			seconds = 0
		}
		h.Set("Retry-After", strconv.Itoa(seconds))
	}
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"message": message, "type": "upstream_error"}})
	return b, status, h, fmt.Errorf("cloudflare workers ai: %s", message)
}

func cloudflareCompatibleRequestBody(body []byte) []byte {
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return body
	}
	if _, hasLegacy := request["max_tokens"]; hasLegacy {
		return body
	}
	maxCompletionTokens, ok := request["max_completion_tokens"]
	if !ok || maxCompletionTokens == nil {
		return body
	}
	request["max_tokens"] = maxCompletionTokens
	compatible, err := json.Marshal(request)
	if err != nil {
		return body
	}
	return compatible
}

func callCloudflarePrepared(ctx context.Context, body []byte, upstreamName, modelID, clientAPI string, cfg *UpstreamConfig, proxyAddr string, stream bool) (io.ReadCloser, []byte, int, http.Header, error) {
	body = cloudflareCompatibleRequestBody(body)
	budgetCtx, cancel := context.WithTimeout(ctx, cloudflareAttemptBudget)
	defer cancel()
	tried := map[string]bool{}
	capacityRetried := false
	var lastStatus int
	var lastHeader http.Header
	var earliest time.Time
	for {
		credential, ok, recovery, busy := cloudflarePool.selectCredential(upstreamName, modelID, cfg, tried)
		if !recovery.IsZero() && (earliest.IsZero() || recovery.Before(earliest)) {
			earliest = recovery
		}
		if !ok {
			if busy {
				if err := waitForRetry(budgetCtx, 10*time.Millisecond); err != nil {
					return nil, nil, 0, nil, err
				}
				continue
			}
			status := http.StatusServiceUnavailable
			message := "no usable Cloudflare credentials"
			if !earliest.IsZero() {
				status, message = http.StatusTooManyRequests, "all Cloudflare accounts are cooling down"
			}
			if lastStatus != 0 {
				message += fmt.Sprintf("; last upstream status %d", lastStatus)
			}
			b, s, h, err := cloudflareUnavailableBody(message, status, earliest)
			if lastHeader != nil {
				for k, values := range lastHeader {
					if h.Get(k) == "" && strings.EqualFold(k, "Retry-After") {
						h[k] = append([]string(nil), values...)
					}
				}
			}
			return nil, b, s, h, err
		}
		tried[credential.ID] = true
		requestCtx := budgetCtx
		var streamCancel context.CancelFunc
		var headerTimer *time.Timer
		if stream {
			// The attempt budget only governs establishing the upstream response.
			// Once headers arrive, the SSE body must remain readable for the full
			// client-request lifetime instead of inheriting the 30-second deadline.
			requestCtx, streamCancel = context.WithCancel(ctx)
			remaining := cloudflareAttemptBudget
			if deadline, ok := budgetCtx.Deadline(); ok {
				remaining = time.Until(deadline)
			}
			headerTimer = time.AfterFunc(remaining, streamCancel)
		}
		req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, cloudflareEndpoint(cfg, credential), bytes.NewReader(body))
		if err != nil {
			if headerTimer != nil {
				headerTimer.Stop()
			}
			if streamCancel != nil {
				streamCancel()
			}
			cloudflarePool.finish(credential, modelID, 0, 0, err.Error(), "")
			continue
		}
		req.Header.Set("Authorization", "Bearer "+credential.APIToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		client, _ := getModelHTTPClient(proxyAddr, stream)
		resp, err := client.Do(req)
		if headerTimer != nil {
			headerTimer.Stop()
		}
		if err != nil {
			if streamCancel != nil {
				streamCancel()
			}
			cloudflarePool.finish(credential, modelID, 0, 0, "network error", "")
			if budgetCtx.Err() != nil {
				return nil, nil, 0, nil, budgetCtx.Err()
			}
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if stream {
				return &cloudflareSuccessfulStream{ReadCloser: resp.Body, credential: credential, model: modelID, status: resp.StatusCode, cancel: streamCancel}, nil, resp.StatusCode, resp.Header.Clone(), nil
			}
			payload, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			cloudflarePool.finish(credential, modelID, resp.StatusCode, 0, "", "")
			return nil, payload, resp.StatusCode, resp.Header.Clone(), readErr
		}
		payload, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if streamCancel != nil {
			streamCancel()
		}
		code, message := cloudflareErrorCode(payload)
		message = sanitizeCloudflareText(message, cfg.CloudflareCredentials)
		cloudflarePool.finish(credential, modelID, resp.StatusCode, code, message, resp.Header.Get("Retry-After"))
		payload = []byte(sanitizeCloudflareText(string(payload), cfg.CloudflareCredentials))
		lastStatus, lastHeader = resp.StatusCode, resp.Header.Clone()
		retryable, capacity := cloudflareRetryable(resp.StatusCode, code)
		if !retryable {
			return nil, payload, resp.StatusCode, lastHeader, fmt.Errorf("cloudflare workers ai upstream error")
		}
		if capacity && !capacityRetried {
			capacityRetried = true
			if err := waitForRetry(budgetCtx, 250*time.Millisecond); err != nil {
				return nil, payload, resp.StatusCode, lastHeader, err
			}
		}
	}
}

type cloudflareSuccessfulStream struct {
	io.ReadCloser
	credential CloudflareCredential
	model      string
	status     int
	cancel     context.CancelFunc
	once       sync.Once
}

func (s *cloudflareSuccessfulStream) Close() error {
	err := s.ReadCloser.Close()
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		cloudflarePool.finish(s.credential, s.model, s.status, 0, "", "")
	})
	return err
}

func callCloudflareNonStream(ctx context.Context, body []byte, upstreamName, modelID, clientAPI string, cfg *UpstreamConfig, proxyAddr string) ([]byte, int, http.Header, error) {
	_, payload, status, header, err := callCloudflarePrepared(ctx, body, upstreamName, modelID, clientAPI, cfg, proxyAddr, false)
	return payload, status, header, err
}

func callCloudflareStream(ctx context.Context, body []byte, upstreamName, modelID, clientAPI string, cfg *UpstreamConfig, proxyAddr string) (io.ReadCloser, int, http.Header, error) {
	reader, payload, status, header, err := callCloudflarePrepared(ctx, body, upstreamName, modelID, clientAPI, cfg, proxyAddr, true)
	if reader == nil && len(payload) > 0 {
		reader = io.NopCloser(bytes.NewReader(payload))
	}
	return reader, status, header, err
}

func fetchCloudflareModels(name string, cfg *UpstreamConfig) ([]ModelInfo, error) {
	credentials := cfg.CloudflareCredentials
	if len(credentials) == 0 {
		return nil, fmt.Errorf("no Cloudflare credentials configured")
	}
	start := nextUpstreamAPIKeyIndex(name+":cloudflare-models", len(credentials))
	budgetCtx, cancelBudget := context.WithTimeout(context.Background(), cloudflareAttemptBudget)
	defer cancelBudget()
	var lastErr error
	for offset := 0; offset < len(credentials); offset++ {
		if budgetCtx.Err() != nil {
			break
		}
		credential := credentials[(start+offset)%len(credentials)]
		if !credential.Enabled || credential.APIToken == "" {
			continue
		}
		models := []ModelInfo{}
		seen := map[string]struct{}{}
		for page := 1; page <= 100; page++ {
			query := url.Values{}
			query.Set("task", "Text Generation")
			query.Set("per_page", "50")
			query.Set("page", strconv.Itoa(page))
			endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/accounts/" + url.PathEscape(credential.AccountID) + "/ai/models/search?" + query.Encode()
			requestCtx, cancelRequest := context.WithTimeout(budgetCtx, cloudflareModelTimeout)
			req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
			if err != nil {
				cancelRequest()
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+credential.APIToken)
			req.Header.Set("Accept-Encoding", "identity")
			resp, err := httpClient.Do(req)
			if err != nil {
				cancelRequest()
				lastErr = fmt.Errorf("Cloudflare model search failed")
				break
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancelRequest()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				code, message := cloudflareErrorCode(body)
				cloudflarePool.finish(credential, "", resp.StatusCode, code, sanitizeCloudflareText(message, credentials), resp.Header.Get("Retry-After"))
				lastErr = fmt.Errorf("Cloudflare model search status %d code %d", resp.StatusCode, code)
				break
			}
			var envelope struct {
				Success    bool             `json:"success"`
				Result     []map[string]any `json:"result"`
				ResultInfo struct {
					Page       int `json:"page"`
					PerPage    int `json:"per_page"`
					TotalPages int `json:"total_pages"`
					Count      int `json:"count"`
					TotalCount int `json:"total_count"`
				} `json:"result_info"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil || !envelope.Success {
				lastErr = fmt.Errorf("invalid Cloudflare model search response")
				break
			}
			for _, raw := range envelope.Result {
				id := stringField(raw, "name", "id", "model")
				task := cloudflareModelTask(raw)
				if id == "" || (task != "" && task != "text-generation" && task != "text generation") {
					continue
				}
				if _, exists := seen[id]; exists {
					continue
				}
				seen[id] = struct{}{}
				models = append(models, ModelInfo{ID: id, Object: "model", Created: time.Now().Unix(), OwnedBy: effectiveUpstreamName(name)})
			}
			if len(envelope.Result) == 0 ||
				(envelope.ResultInfo.PerPage > 0 && envelope.ResultInfo.Count < envelope.ResultInfo.PerPage) ||
				(envelope.ResultInfo.TotalPages > 0 && page >= envelope.ResultInfo.TotalPages) ||
				(envelope.ResultInfo.TotalCount > 0 && page*max(envelope.ResultInfo.PerPage, len(envelope.Result)) >= envelope.ResultInfo.TotalCount) {
				break
			}
		}
		if len(models) > 0 {
			return models, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no enabled Cloudflare credentials")
	}
	return nil, lastErr
}

func cloudflareModelTask(raw map[string]any) string {
	if task := strings.ToLower(stringField(raw, "task", "task_name")); task != "" {
		return task
	}
	if task, ok := raw["task"].(map[string]any); ok {
		return strings.ToLower(stringField(task, "name", "id"))
	}
	return ""
}

func stringField(raw map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := raw[name].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type cloudflareCredentialView struct {
	ID             string     `json:"id"`
	AccountID      string     `json:"account_id"`
	TokenSuffix    string     `json:"token_suffix"`
	Enabled        bool       `json:"enabled"`
	Status         string     `json:"status"`
	LastHTTPStatus int        `json:"last_http_status,omitempty"`
	LastErrorCode  int        `json:"last_error_code,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	NextRecovery   *time.Time `json:"next_recovery,omitempty"`
}

func cloudflareCredentialViews() map[string][]cloudflareCredentialView {
	configMu.RLock()
	configured := make(map[string][]CloudflareCredential)
	for name, cfg := range upstreamCfgs {
		if cfg != nil && cfg.APIType == UpstreamCloudflareWorkersAI {
			configured[name] = cloneCloudflareCredentials(cfg.CloudflareCredentials)
		}
	}
	configMu.RUnlock()
	cloudflarePool.mu.Lock()
	defer cloudflarePool.mu.Unlock()
	now := cloudflarePool.now()
	result := make(map[string][]cloudflareCredentialView, len(configured))
	for name, credentials := range configured {
		for _, c := range credentials {
			view := cloudflareCredentialView{ID: c.ID, AccountID: c.AccountID, TokenSuffix: maskCloudflareToken(c.APIToken), Enabled: c.Enabled, Status: "ready"}
			s := cloudflarePool.state[c.ID]
			switch {
			case !c.Enabled:
				view.Status = "disabled"
			case s != nil && s.Quarantined:
				view.Status = "quarantined"
			case s != nil && s.AccountBlocked:
				view.Status = "account_blocked"
			case s != nil && s.CooldownUntil.After(now):
				view.Status = "cooldown"
				recovery := s.CooldownUntil
				view.NextRecovery = &recovery
			case s != nil && s.InFlight > 0:
				view.Status = "in_flight"
			}
			if s != nil {
				view.LastHTTPStatus = s.LastStatus
				view.LastErrorCode = s.LastCode
				view.LastError = s.LastError
			}
			result[name] = append(result[name], view)
		}
	}
	return result
}

func cloudflareCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"upstreams": cloudflareCredentialViews()})
	case http.MethodPost:
		var request struct {
			ID string `json:"id"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil || strings.TrimSpace(request.ID) == "" {
			http.Error(w, `{"error":"id is required"}`, http.StatusBadRequest)
			return
		}
		resetCloudflareCredentialState(strings.TrimSpace(request.ID))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// This endpoint atomically imports records into the fixed Cloudflare upstream.
// It returns counts only; neither source fields nor tokens leave the handler.
func cloudflareCredentialImportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		http.Error(w, `{"error":"failed to read source"}`, http.StatusBadRequest)
		return
	}
	var request struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(data, &request) != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}
	credentials, err := parseCloudflareCredentialSource([]byte(request.Source))
	if err != nil {
		http.Error(w, `{"error":"invalid four-line credential source"}`, http.StatusBadRequest)
		return
	}
	configMu.RLock()
	cfg := AppConfig{ModelAlias: map[string]ModelAlias{}, ReasoningEffortMap: map[string]string{}, Upstreams: map[string]*UpstreamConfig{}, CPATranslator: cpaTranslatorCfg, ClaudeCompat: claudeCompatCfg}
	for k, v := range modelAlias {
		cfg.ModelAlias[k] = v
	}
	for k, v := range reasoningEffortMap {
		cfg.ReasoningEffortMap[k] = v
	}
	for k, v := range upstreamCfgs {
		cfg.Upstreams[k] = cloneUpstreamConfig(v)
	}
	configMu.RUnlock()
	socks5Mu.RLock()
	cfg.Socks5Proxies = append([]Socks5Proxy(nil), socks5Proxies...)
	socks5Mu.RUnlock()
	upstream := cfg.Upstreams["cloudflare-workers-ai"]
	if upstream == nil {
		upstream = &UpstreamConfig{BaseURL: cloudflareDefaultBaseURL, APIType: UpstreamCloudflareWorkersAI}
		cfg.Upstreams["cloudflare-workers-ai"] = upstream
	}
	if upstream.APIType != UpstreamCloudflareWorkersAI {
		http.Error(w, `{"error":"upstream name already uses another type"}`, http.StatusConflict)
		return
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
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}
	applyConfig(cfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "parsed": len(credentials), "added": added, "total": len(upstream.CloudflareCredentials)})
}

type cloudflareVerificationReport struct {
	Total, Success, Failed int
	Statuses               map[int]int
	Codes                  map[int]int
}

func verifyCloudflareCredentials(ctx context.Context, cfg *UpstreamConfig) cloudflareVerificationReport {
	report := cloudflareVerificationReport{Total: len(cfg.CloudflareCredentials), Statuses: map[int]int{}, Codes: map[int]int{}}
	type outcome struct {
		status, code int
		ok           bool
	}
	outcomes := make(chan outcome, len(cfg.CloudflareCredentials))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, credential := range cfg.CloudflareCredentials {
		if !credential.Enabled {
			outcomes <- outcome{}
			continue
		}
		wg.Add(1)
		go func(c CloudflareCredential) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/accounts/" + url.PathEscape(c.AccountID) + "/ai/models/search?task=text-generation&per_page=1&page=1"
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				outcomes <- outcome{}
				return
			}
			req.Header.Set("Authorization", "Bearer "+c.APIToken)
			resp, err := httpClient.Do(req)
			if err != nil {
				outcomes <- outcome{}
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			code, _ := cloudflareErrorCode(body)
			ok := resp.StatusCode >= 200 && resp.StatusCode < 300
			if ok {
				var envelope struct {
					Success bool `json:"success"`
				}
				ok = json.Unmarshal(body, &envelope) == nil && envelope.Success
			}
			outcomes <- outcome{status: resp.StatusCode, code: code, ok: ok}
		}(credential)
	}
	wg.Wait()
	close(outcomes)
	for result := range outcomes {
		report.Statuses[result.status]++
		if result.code != 0 {
			report.Codes[result.code]++
		}
		if result.ok {
			report.Success++
		} else {
			report.Failed++
		}
	}
	return report
}
