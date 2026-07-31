package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func resetCloudflarePoolForTest(now time.Time) {
	cloudflarePool.mu.Lock()
	defer cloudflarePool.mu.Unlock()
	cloudflarePool.cursor = map[string]int{}
	cloudflarePool.state = map[string]*cloudflareCredentialState{}
	cloudflarePool.now = func() time.Time { return now }
	testingCleanupNow = func() { cloudflarePool.mu.Lock(); cloudflarePool.now = time.Now; cloudflarePool.mu.Unlock() }
}

var testingCleanupNow = func() {}

func cfCredential(id, account, token string) CloudflareCredential {
	return CloudflareCredential{ID: id, AccountID: account, APIToken: token, Enabled: true}
}

func TestParseCloudflareCredentialSourceStrictDeduplicated(t *testing.T) {
	source := "person@example.invalid\npassword-do-not-keep\naccount-00000000000000000001\ntoken-0000000000000000000001\n\n" +
		"other@example.invalid\nother-password\naccount-00000000000000000001\ntoken-0000000000000000000001\n"
	got, err := parseCloudflareCredentialSource([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d credentials, want 1", len(got))
	}
	encoded, _ := json.Marshal(got)
	for _, secret := range []string{"person@example.invalid", "password-do-not-keep", "other@example.invalid", "other-password"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("discarded source field leaked: %q", secret)
		}
	}
	if _, err := parseCloudflareCredentialSource([]byte("email\npassword\naccount-only")); err == nil {
		t.Fatal("incomplete record accepted")
	}
}

func TestParseCloudflareCredentialSourceDelimitedWithPreamble(t *testing.T) {
	source := "generated credential export\ncount: 2\n----\n" +
		"mail@example.invalid----password-value----account-00000000000000000001----token-0000000000000000000001\n" +
		"mail2@example.invalid----password-value2----account-00000000000000000002----token-0000000000000000000002\n"
	got, err := parseCloudflareCredentialSource([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records", len(got))
	}
}

func TestMergeCloudflareCredentialsBlankKeepsToken(t *testing.T) {
	old := []CloudflareCredential{cfCredential("stable", "account-00000000000000000001", "old-secret-token-0000000001")}
	in := []CloudflareCredential{{ID: "stable", AccountID: old[0].AccountID, Enabled: false}}
	got, err := mergeCloudflareCredentials(old, in)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].APIToken != old[0].APIToken || got[0].Enabled {
		t.Fatalf("merge result = %#v", got[0])
	}
}

func TestSaveConfigUses0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := saveConfig(path, AppConfig{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestCloudflareFailoverBuildsBoundPathAndBearer(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	resetCloudflarePoolForTest(now)
	t.Cleanup(testingCleanupNow)
	var mu sync.Mutex
	var paths, auth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		if strings.Contains(r.URL.Path, "account-one") {
			w.WriteHeader(429)
			io.WriteString(w, `{"errors":[{"code":3036,"message":"daily limit"}]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"ok","choices":[]}`)
	}))
	defer server.Close()
	cfg := &UpstreamConfig{BaseURL: server.URL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{
		cfCredential("one", "account-one-000000000000000", "token-one-000000000000000000"),
		cfCredential("two", "account-two-000000000000000", "token-two-000000000000000000"),
	}}
	body, status, _, err := callCloudflareNonStream(context.Background(), []byte(`{"model":"@cf/test","messages":[]}`), "cf", "@cf/test", "chat", cfg, "")
	if err != nil || status != 200 || !strings.Contains(string(body), `"id":"ok"`) {
		t.Fatalf("status=%d err=%v body=%s", status, err, body)
	}
	wantPaths := []string{"/accounts/account-one-000000000000000/ai/v1/chat/completions", "/accounts/account-two-000000000000000/ai/v1/chat/completions"}
	for i := range wantPaths {
		if paths[i] != wantPaths[i] {
			t.Fatalf("path[%d]=%q", i, paths[i])
		}
	}
	if auth[0] != "Bearer token-one-000000000000000000" || auth[1] != "Bearer token-two-000000000000000000" {
		t.Fatalf("unexpected auth headers")
	}
	cloudflarePool.mu.Lock()
	until := cloudflarePool.state["one"].CooldownUntil
	cloudflarePool.mu.Unlock()
	if want := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC); !until.Equal(want) {
		t.Fatalf("cooldown=%s want=%s", until, want)
	}
}

func TestCloudflareRequestErrorDoesNotConsumeOtherAccounts(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(400)
		io.WriteString(w, `{"errors":[{"code":5007,"message":"no model"}]}`)
	}))
	defer server.Close()
	cfg := &UpstreamConfig{BaseURL: server.URL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{cfCredential("1", "account-11111111111111111111", "token-111111111111111111111"), cfCredential("2", "account-22222222222222222222", "token-222222222222222222222")}}
	_, status, _, err := callCloudflareNonStream(context.Background(), []byte(`{}`), "cf", "bad-model", "chat", cfg, "")
	if status != 400 || err == nil || requests != 1 {
		t.Fatalf("status=%d err=%v requests=%d", status, err, requests)
	}
}

func TestCloudflareAuthFailureQuarantinesOnlyCredential(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bad-account") {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, `{"choices":[]}`)
	}))
	defer server.Close()
	cfg := &UpstreamConfig{BaseURL: server.URL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{cfCredential("bad", "bad-account-0000000000000000", "bad-token-000000000000000000"), cfCredential("good", "good-account-000000000000000", "good-token-00000000000000000")}}
	_, status, _, err := callCloudflareNonStream(context.Background(), []byte(`{}`), "cf", "model", "chat", cfg, "")
	if status != 200 || err != nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
	cloudflarePool.mu.Lock()
	bad := cloudflarePool.state["bad"]
	good := cloudflarePool.state["good"]
	cloudflarePool.mu.Unlock()
	if !bad.Quarantined || good.Quarantined {
		t.Fatalf("bad=%#v good=%#v", bad, good)
	}
}

func TestCloudflareStreamRetriesOnlyBeforeReturningBody(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "first-account") {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[]}\n\n")
	}))
	defer server.Close()
	cfg := &UpstreamConfig{BaseURL: server.URL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{cfCredential("first", "first-account-0000000000000", "first-token-0000000000000000"), cfCredential("second", "second-account-000000000000", "second-token-000000000000000")}}
	body, status, _, err := callCloudflareStream(context.Background(), []byte(`{"stream":true}`), "cf", "model", "chat", cfg, "")
	if err != nil || status != 200 {
		t.Fatalf("status=%d err=%v", status, err)
	}
	defer body.Close()
	data, _ := io.ReadAll(body)
	if !strings.HasPrefix(string(data), "data:") {
		t.Fatalf("stream=%q", data)
	}
}

func TestChatCompletionsCloudflareStreamRemainsReadableAfterHeaders(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(25 * time.Millisecond)
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"second\"}}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	configMu.Lock()
	oldAliases, oldUpstreams := modelAlias, upstreamCfgs
	modelAlias = map[string]ModelAlias{"cf-stream": {TargetModel: "@cf/test", Upstream: "cloudflare-workers-ai"}}
	upstreamCfgs = map[string]*UpstreamConfig{"cloudflare-workers-ai": {
		BaseURL:               upstream.URL,
		APIType:               UpstreamCloudflareWorkersAI,
		CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", "token-0000000000000000000001")},
	}}
	configMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		modelAlias, upstreamCfgs = oldAliases, oldUpstreams
		configMu.Unlock()
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"cf-stream","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	rec := httptest.NewRecorder()
	chatCompletionsHandler(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, `"error":"stream read error"`) {
		t.Fatalf("gateway exposed stream read error: %s", body)
	}
	for _, want := range []string{"first", "second", "data: [DONE]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in stream: %s", want, body)
		}
	}
}

func TestChatCompletionsCloudflareStreamReadFailureUsesOpenAIErrorShape(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker := w.(http.Hijacker)
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		// Advertise a chunk larger than the bytes actually sent so the gateway
		// sees an unexpected EOF after a valid first SSE event.
		fmt.Fprint(rw, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		fmt.Fprint(rw, "80\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
		rw.Flush()
	}))
	defer upstream.Close()

	configMu.Lock()
	oldAliases, oldUpstreams := modelAlias, upstreamCfgs
	modelAlias = map[string]ModelAlias{"cf-broken-stream": {TargetModel: "@cf/test", Upstream: "cloudflare-workers-ai"}}
	upstreamCfgs = map[string]*UpstreamConfig{"cloudflare-workers-ai": {
		BaseURL:               upstream.URL,
		APIType:               UpstreamCloudflareWorkersAI,
		CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", "token-0000000000000000000001")},
	}}
	configMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		modelAlias, upstreamCfgs = oldAliases, oldUpstreams
		configMu.Unlock()
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"cf-broken-stream","messages":[{"role":"user","content":"hi"}],"stream":true}`))
	rec := httptest.NewRecorder()
	chatCompletionsHandler(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, `{"error":"stream read error"}`) {
		t.Fatalf("gateway emitted invalid OpenAI error shape: %s", body)
	}
	if !strings.Contains(body, `{"error":{"message":"upstream stream read error","type":"upstream_error"}}`) {
		t.Fatalf("missing OpenAI-compatible stream error: %s", body)
	}
}

func TestChatCompletionsCloudflareForwardsMaxCompletionTokens(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	var received map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	defer upstream.Close()

	configMu.Lock()
	oldAliases, oldUpstreams := modelAlias, upstreamCfgs
	modelAlias = map[string]ModelAlias{"cf-max-tokens": {TargetModel: "@cf/test", Upstream: "cloudflare-workers-ai"}}
	upstreamCfgs = map[string]*UpstreamConfig{"cloudflare-workers-ai": {
		BaseURL:               upstream.URL,
		APIType:               UpstreamCloudflareWorkersAI,
		CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", "token-0000000000000000000001")},
	}}
	configMu.Unlock()
	t.Cleanup(func() {
		configMu.Lock()
		modelAlias, upstreamCfgs = oldAliases, oldUpstreams
		configMu.Unlock()
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"cf-max-tokens","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":2048}`))
	rec := httptest.NewRecorder()
	chatCompletionsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := received["max_completion_tokens"]; got != float64(2048) {
		t.Fatalf("upstream max_completion_tokens=%v, want 2048; request=%v", got, received)
	}
	if got := received["max_tokens"]; got != float64(2048) {
		t.Fatalf("upstream max_tokens=%v, want compatibility value 2048; request=%v", got, received)
	}
}

func TestCloudflareSelectorDoesNotChooseInFlightCredentialTwice(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	cfg := &UpstreamConfig{CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", "token-0000000000000000000001"), cfCredential("two", "account-00000000000000000002", "token-0000000000000000000002")}}
	first, ok, _, _ := cloudflarePool.selectCredential("cf", "model", cfg, map[string]bool{})
	if !ok {
		t.Fatal("first selection failed")
	}
	second, ok, _, _ := cloudflarePool.selectCredential("cf", "model", cfg, map[string]bool{})
	if !ok {
		t.Fatal("second selection failed")
	}
	if first.ID == second.ID {
		t.Fatal("selected an in-flight credential twice")
	}
	_, ok, _, busy := cloudflarePool.selectCredential("cf", "model", cfg, map[string]bool{})
	if ok || !busy {
		t.Fatalf("third selection ok=%v busy=%v", ok, busy)
	}
	cloudflarePool.finish(first, "model", 200, 0, "", "")
	cloudflarePool.finish(second, "model", 200, 0, "", "")
}

func TestCloudflareSanitizesErrorToken(t *testing.T) {
	resetCloudflarePoolForTest(time.Now())
	t.Cleanup(testingCleanupNow)
	token := "sensitive-token-000000000000000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"errors":[{"code":5004,"message":"bad `+token+`"}]}`)
	}))
	defer server.Close()
	cfg := &UpstreamConfig{BaseURL: server.URL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", token)}}
	body, _, _, _ := callCloudflareNonStream(context.Background(), []byte(`{}`), "cf", "model", "chat", cfg, "")
	if strings.Contains(string(body), token) || !strings.Contains(string(body), "[REDACTED]") {
		t.Fatalf("unsanitized body: %s", body)
	}
}

func TestCloudflareManagementAPINeverReturnsStoredToken(t *testing.T) {
	token := "stored-token-must-not-be-returned-0001"
	configMu.Lock()
	previous := upstreamCfgs
	upstreamCfgs = map[string]*UpstreamConfig{"cloudflare-workers-ai": {BaseURL: cloudflareDefaultBaseURL, APIType: UpstreamCloudflareWorkersAI, CloudflareCredentials: []CloudflareCredential{cfCredential("one", "account-00000000000000000001", token)}}}
	configMu.Unlock()
	t.Cleanup(func() { configMu.Lock(); upstreamCfgs = previous; configMu.Unlock() })
	for _, handler := range []http.HandlerFunc{adminConfigHandler, cloudflareCredentialsHandler} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != 200 {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), token) {
			t.Fatalf("management response leaked token")
		}
	}
	views := cloudflareCredentialViews()["cloudflare-workers-ai"]
	if len(views) != 1 || views[0].TokenSuffix != "****0001" {
		t.Fatalf("unexpected masked view: %#v", views)
	}
}

func TestCloudflareCredentialsHandlerShowsUnusedEnabledCredentialReady(t *testing.T) {
	resetCloudflarePoolForTest(time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC))
	t.Cleanup(testingCleanupNow)
	configMu.Lock()
	previous := upstreamCfgs
	upstreamCfgs = map[string]*UpstreamConfig{"cloudflare-workers-ai": {
		BaseURL: cloudflareDefaultBaseURL,
		APIType: UpstreamCloudflareWorkersAI,
		CloudflareCredentials: []CloudflareCredential{
			cfCredential("unused", "account-00000000000000000001", "unused-token-000000000000000001"),
		},
	}}
	configMu.Unlock()
	t.Cleanup(func() { configMu.Lock(); upstreamCfgs = previous; configMu.Unlock() })

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/credentials", nil)
	rec := httptest.NewRecorder()
	cloudflareCredentialsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Upstreams map[string][]cloudflareCredentialView `json:"upstreams"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	views := response.Upstreams["cloudflare-workers-ai"]
	if len(views) != 1 || views[0].Status != "ready" {
		t.Fatalf("unused enabled credential should be ready, got %#v", views)
	}
}

func TestUpstreamModelsHandlerParsesCurrentCloudflareModelSearchResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("task"); got != "Text Generation" {
			http.Error(w, "unexpected task filter: "+got, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"errors":[],"result":[`+
			`{"name":"@cf/current-text-model","task":{"id":"c329a1f9-323d-4e91-b2aa-582dd4188d34","name":"Text Generation"}},`+
			`{"name":"@cf/image-model","task":{"id":"83dd4a42-50ca-4bd1-a3e7-36c4b15953aa","name":"Text-to-Image"}}`+
			`],"result_info":{"count":2,"page":1,"per_page":50,"total_count":2}}`)
	}))
	defer server.Close()

	body := fmt.Sprintf(`{"base_url":%q,"api_type":"cloudflare-workers-ai","cloudflare_credentials":[{"id":"one","account_id":"account-00000000000000000001","api_token":"token-00000000000000000001","enabled":true}]}`, server.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/upstream/models?name=cloudflare-workers-ai", strings.NewReader(body))
	rec := httptest.NewRecorder()
	upstreamModelsHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Models []string `json:"models"`
		Count  int      `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Count != 1 || len(response.Models) != 1 || response.Models[0] != "@cf/current-text-model" {
		t.Fatalf("unexpected models response: %#v", response)
	}
}

func TestAdminConfigBlankCloudflareTokenKeepsStoredValue(t *testing.T) {
	token := "write-only-token-000000000000000001"
	configMu.Lock()
	oldUpstreams := upstreamCfgs
	oldAliases := modelAlias
	oldEfforts := reasoningEffortMap
	upstreamCfgs = map[string]*UpstreamConfig{"old-name": {BaseURL: cloudflareDefaultBaseURL, APIType: UpstreamCloudflareWorkersAI, CustomModels: []string{"@cf/test"}, CloudflareCredentials: []CloudflareCredential{cfCredential("stable", "account-00000000000000000001", token)}}}
	modelAlias = map[string]ModelAlias{}
	reasoningEffortMap = map[string]string{}
	configMu.Unlock()
	oldPath := configPath
	configPath = filepath.Join(t.TempDir(), "config.json")
	t.Cleanup(func() {
		configMu.Lock()
		upstreamCfgs = oldUpstreams
		modelAlias = oldAliases
		reasoningEffortMap = oldEfforts
		configMu.Unlock()
		configPath = oldPath
	})
	payload := `{"model_alias":{},"reasoning_effort_map":{},"upstreams":{"renamed":{"base_url":"https://api.cloudflare.com/client/v4","api_type":"cloudflare-workers-ai","custom_models":["@cf/test"],"cloudflare_credentials":[{"id":"stable","account_id":"account-00000000000000000001","api_token":"","enabled":true}]}}}`
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	adminConfigHandler(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved := loadConfig(configPath)
	got := saved.Upstreams["renamed"].CloudflareCredentials[0].APIToken
	if got != token {
		t.Fatalf("stored token was not preserved")
	}
}
