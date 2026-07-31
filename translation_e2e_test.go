package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const e2EClaudeResponse = `{"id":"msg_x","type":"message","role":"assistant","model":"M","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`

type e2EAnthropicMock struct {
	mu      sync.Mutex
	body    []byte
	headers http.Header
}

func (m *e2EAnthropicMock) handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.body = append([]byte(nil), body...)
	m.headers = r.Header.Clone()
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(e2EClaudeResponse))
}

func (m *e2EAnthropicMock) request() ([]byte, http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.body...), m.headers.Clone()
}

func e2EChatServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", chatCompletionsHandler)
	return httptest.NewServer(mux)
}

func applyE2EConfig(t *testing.T, upstreamURL string, cpa CPATranslatorConfig) {
	t.Helper()
	applyConfig(AppConfig{
		ModelAlias: map[string]ModelAlias{
			"chat-claude": {TargetModel: "M", Upstream: "up-anthropic"},
		},
		Upstreams: map[string]*UpstreamConfig{
			"up-anthropic": {BaseURL: upstreamURL, APIKey: "k", APIType: UpstreamAnthropic},
		},
		CPATranslator: cpa,
	})
	t.Cleanup(func() {
		// Use non-nil empty maps so applyConfig also clears the alias map between tests.
		applyConfig(AppConfig{
			ModelAlias: map[string]ModelAlias{},
			Upstreams:  map[string]*UpstreamConfig{},
		})
	})
}

func postE2EChat(t *testing.T, serverURL string) (int, []byte) {
	t.Helper()
	body := []byte(`{"model":"chat-claude","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high","max_tokens":100}`)
	resp, err := http.Post(serverURL+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST chat completions: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read chat response: %v", err)
	}
	return resp.StatusCode, got
}

func decodeE2EJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("invalid JSON %q: %v", body, err)
	}
	return obj
}

func assertE2EClaudeRequest(t *testing.T, body []byte, headers http.Header) map[string]any {
	t.Helper()
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("mock upstream received invalid JSON %q: %v", body, err)
	}
	t.Logf("mock Anthropic request: %s", body)
	if headers.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", headers.Get("Content-Type"))
	}
	if got := headers.Get("x-api-key"); got != "k" {
		t.Errorf("x-api-key = %q, want k", got)
	}
	if got := headers.Get("Authorization"); got != "" {
		t.Errorf("unexpected Authorization header %q for Anthropic upstream", got)
	}
	if _, ok := req["messages"]; !ok {
		t.Errorf("Anthropic request has no messages: %s", body)
	}
	if _, ok := req["max_tokens"]; !ok {
		t.Errorf("Anthropic request has no max_tokens: %s", body)
	}
	if _, ok := req["object"]; ok {
		t.Errorf("Anthropic request unexpectedly has OpenAI object: %s", body)
	}
	if _, ok := req["reasoning_effort"]; ok {
		t.Errorf("Anthropic request unexpectedly has top-level reasoning_effort: %s", body)
	}
	return req
}

func assertE2EChatResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("gateway status = %d, body = %s", status, body)
	}
	obj := decodeE2EJSON(t, body)
	if obj["object"] != "chat.completion" {
		t.Errorf("response object = %v, want chat.completion; body=%s", obj["object"], body)
	}
	choices, ok := obj["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("response has no choices: %s", body)
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("response choices[0] has unexpected shape: %s", body)
	}
	message, ok := choice["message"].(map[string]any)
	if !ok || message["content"] != "hello" {
		t.Errorf("response choices[0].message.content = %v, want hello; body=%s", choice["message"], body)
	}
}

func TestE2EChatCPAPathAnthropicUpstream(t *testing.T) {
	mock := new(e2EAnthropicMock)
	upstream := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer upstream.Close()
	applyE2EConfig(t, upstream.URL, CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true})

	gateway := e2EChatServer()
	defer gateway.Close()
	status, responseBody := postE2EChat(t, gateway.URL)
	assertE2EChatResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	req := assertE2EClaudeRequest(t, requestBody, headers)
	if metadata, ok := req["metadata"]; ok {
		if metadataObj, ok := metadata.(map[string]any); ok {
			if _, hasUserID := metadataObj["user_id"]; hasUserID {
				t.Errorf("CPA metadata.user_id was not stripped: %v; body=%s", metadata, requestBody)
			}
		} else {
			t.Errorf("metadata has unexpected shape %T: %v", metadata, metadata)
		}
	}
	thinking, ok := req["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("CPA Claude request has no thinking block; body=%s", requestBody)
	}
	if budget, ok := thinking["budget_tokens"].(float64); !ok || int(budget) != 32000 {
		t.Errorf("thinking.budget_tokens = %v, want 32000; body=%s", thinking["budget_tokens"], requestBody)
	}
}

func TestE2EChatCPADisabledFallsBackToHandwritten(t *testing.T) {
	mock := new(e2EAnthropicMock)
	upstream := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer upstream.Close()
	applyE2EConfig(t, upstream.URL, CPATranslatorConfig{Enabled: false})

	gateway := e2EChatServer()
	defer gateway.Close()
	status, responseBody := postE2EChat(t, gateway.URL)
	assertE2EChatResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	assertE2EClaudeRequest(t, requestBody, headers)
	// The disabled path is the existing handwritten conversion. Keep this check
	// deliberately broad: the compatibility contract is Claude-shaped request +
	// successful Chat-shaped response, not CPA-specific metadata behavior.
	if !strings.Contains(string(requestBody), `"messages"`) {
		t.Errorf("handwritten request does not contain messages: %s", requestBody)
	}
}

func TestE2EChatCPARequestOnlyThenHandwrittenResponse(t *testing.T) {
	mock := new(e2EAnthropicMock)
	upstream := httptest.NewServer(http.HandlerFunc(mock.handler))
	defer upstream.Close()
	applyE2EConfig(t, upstream.URL, CPATranslatorConfig{Enabled: true, Requests: true})

	gateway := e2EChatServer()
	defer gateway.Close()
	status, responseBody := postE2EChat(t, gateway.URL)
	requestBody, headers := mock.request()
	t.Logf("request-only mock Anthropic request: %s", requestBody)
	t.Logf("request-only gateway response status=%d body=%s", status, responseBody)
	assertE2EClaudeRequest(t, requestBody, headers)

	// With CPA response translation disabled, the handler intentionally feeds the
	// raw Claude response to handwritten convertResponse. This assertion records
	// whether that existing mixed path is compatible rather than masking a bug.
	assertE2EChatResponse(t, status, responseBody)
}

// e2EJSONMock records an upstream request and returns a fixed JSON response.
// It is deliberately separate from e2EAnthropicMock because these tests exercise
// non-Anthropic upstreams and need to inspect their wire shape and auth header.
type e2EJSONMock struct {
	mu       sync.Mutex
	body     []byte
	headers  http.Header
	response []byte
}

func (m *e2EJSONMock) handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.body = append([]byte(nil), body...)
	m.headers = r.Header.Clone()
	response := append([]byte(nil), m.response...)
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func (m *e2EJSONMock) request() ([]byte, http.Header) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.body...), m.headers.Clone()
}

func postE2EAnthropicMessages(t *testing.T, serverURL, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(serverURL+"/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST messages: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read messages response: %v", err)
	}
	return resp.StatusCode, got
}

func e2EAnthropicMessagesServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", anthropicMessagesHandler)
	return httptest.NewServer(mux)
}

func assertE2EClaudeMessageResponse(t *testing.T, status int, body []byte) map[string]any {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("gateway messages status = %d, body = %s", status, body)
	}
	obj := decodeE2EJSON(t, body)
	if obj["type"] != "message" {
		t.Fatalf("response type = %v, want message; body=%s", obj["type"], body)
	}
	content, ok := obj["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("response has no Claude content blocks: %s", body)
	}
	block, ok := content[0].(map[string]any)
	if !ok || block["type"] != "text" || block["text"] != "hello" {
		t.Fatalf("response content[0] = %v, want text hello; body=%s", content[0], body)
	}
	usage, ok := obj["usage"].(map[string]any)
	if !ok {
		t.Fatalf("response has no usage object: %s", body)
	}
	if usage["input_tokens"] != float64(3) || usage["output_tokens"] != float64(2) {
		t.Fatalf("response usage = %v, want input_tokens=3 output_tokens=2; body=%s", usage, body)
	}
	return obj
}

func assertE2EOpenAIAuth(t *testing.T, headers http.Header) {
	t.Helper()
	if headers.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", headers.Get("Content-Type"))
	}
	if got := headers.Get("Authorization"); got != "Bearer k" {
		t.Errorf("Authorization = %q, want Bearer k", got)
	}
	if got := headers.Get("x-api-key"); got != "" {
		t.Errorf("unexpected x-api-key header %q", got)
	}
}

func assertE2EChatWireRequest(t *testing.T, body []byte, headers http.Header) map[string]any {
	t.Helper()
	req := decodeE2EJSON(t, body)
	t.Logf("mock Chat upstream request: %s", body)
	assertE2EOpenAIAuth(t, headers)
	if req["model"] != "M" {
		t.Errorf("Chat upstream model = %v, want M; body=%s", req["model"], body)
	}
	messages, ok := req["messages"].([]any)
	if !ok || len(messages) == 0 {
		t.Fatalf("Chat upstream has no messages: %s", body)
	}
	first, ok := messages[0].(map[string]any)
	if !ok || first["role"] != "user" {
		t.Fatalf("Chat upstream messages[0] = %v, want user message; body=%s", messages[0], body)
	}
	if _, isAnthropicArray := first["content"].([]any); isAnthropicArray {
		t.Fatalf("Chat upstream received Anthropic content blocks instead of Chat wire: %s", body)
	}
	if first["content"] != "hi" {
		t.Errorf("Chat upstream messages[0].content = %v, want hi; body=%s", first["content"], body)
	}
	return req
}

func assertE2EResponsesWireRequest(t *testing.T, body []byte, headers http.Header) map[string]any {
	t.Helper()
	req := decodeE2EJSON(t, body)
	t.Logf("mock Responses upstream request: %s", body)
	assertE2EOpenAIAuth(t, headers)
	if req["model"] != "M" {
		t.Errorf("Responses upstream model = %v, want M; body=%s", req["model"], body)
	}
	if _, ok := req["messages"]; ok {
		t.Errorf("Responses upstream unexpectedly has Chat messages: %s", body)
	}
	input, ok := req["input"].([]any)
	if !ok || len(input) == 0 {
		t.Fatalf("Responses upstream has no input: %s", body)
	}
	first, ok := input[0].(map[string]any)
	if !ok || first["role"] != "user" || first["content"] != "hi" {
		t.Errorf("Responses upstream input[0] = %v, want role=user content=hi; body=%s", input[0], body)
	}
	if req["max_output_tokens"] != float64(100) {
		t.Errorf("Responses upstream max_output_tokens = %v, want 100; body=%s", req["max_output_tokens"], body)
	}
	return req
}

func TestE2EAnthropicCPAPathChatUpstream(t *testing.T) {
	const anthropicBody = `{"model":"anth-chat","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`
	const chatResponse = `{"id":"chatcmpl-x","object":"chat.completion","model":"M","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`

	for _, tc := range []struct {
		name string
		cpa  CPATranslatorConfig
	}{
		{name: "CPA enabled", cpa: CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true}},
		{name: "CPA disabled", cpa: CPATranslatorConfig{Enabled: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &e2EJSONMock{response: []byte(chatResponse)}
			mux := http.NewServeMux()
			mux.HandleFunc("/chat/completions", mock.handler)
			upstream := httptest.NewServer(mux)
			defer upstream.Close()
			applyConfig(AppConfig{
				ModelAlias: map[string]ModelAlias{"anth-chat": {TargetModel: "M", Upstream: "up-chat"}},
				Upstreams: map[string]*UpstreamConfig{
					"up-chat": {BaseURL: upstream.URL, APIKey: "k", APIType: UpstreamOpenAI},
				},
				CPATranslator: tc.cpa,
			})
			t.Cleanup(func() {
				applyConfig(AppConfig{ModelAlias: map[string]ModelAlias{}, Upstreams: map[string]*UpstreamConfig{}})
			})

			gateway := e2EAnthropicMessagesServer()
			defer gateway.Close()
			status, responseBody := postE2EAnthropicMessages(t, gateway.URL, anthropicBody)
			t.Logf("gateway Claude response: %s", responseBody)
			response := assertE2EClaudeMessageResponse(t, status, responseBody)
			if tc.cpa.Enabled {
				if response["id"] != "chatcmpl-x" {
					t.Errorf("CPA-enabled response id = %v, want upstream Chat id chatcmpl-x; body=%s", response["id"], responseBody)
				}
			} else if id, ok := response["id"].(string); !ok || !strings.HasPrefix(id, "msg_") {
				t.Errorf("CPA-disabled response id = %v, want handwritten msg_ id; body=%s", response["id"], responseBody)
			}

			requestBody, headers := mock.request()
			assertE2EChatWireRequest(t, requestBody, headers)
		})
	}
}

func TestE2EAnthropicCPAPathWithReasoningEffort(t *testing.T) {
	const anthropicBody = `{"model":"anth-chat","max_tokens":100,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"enabled","budget_tokens":8000}}`
	const chatResponse = `{"id":"chatcmpl-x","object":"chat.completion","model":"M","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	mock := &e2EJSONMock{response: []byte(chatResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", mock.handler)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	applyConfig(AppConfig{
		ModelAlias: map[string]ModelAlias{"anth-chat": {TargetModel: "M", Upstream: "up-chat"}},
		Upstreams: map[string]*UpstreamConfig{
			"up-chat": {BaseURL: upstream.URL, APIKey: "k", APIType: UpstreamOpenAI},
		},
		CPATranslator: CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true},
	})
	t.Cleanup(func() {
		applyConfig(AppConfig{ModelAlias: map[string]ModelAlias{}, Upstreams: map[string]*UpstreamConfig{}})
	})

	gateway := e2EAnthropicMessagesServer()
	defer gateway.Close()
	status, responseBody := postE2EAnthropicMessages(t, gateway.URL, anthropicBody)
	t.Logf("reasoning gateway Claude response: %s", responseBody)
	assertE2EClaudeMessageResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	req := assertE2EChatWireRequest(t, requestBody, headers)
	reasoningEffort, hasReasoningEffort := req["reasoning_effort"].(string)
	thinking, hasThinking := req["thinking"]
	if !hasReasoningEffort && !hasThinking {
		t.Fatalf("Chat upstream request lost Anthropic thinking signal: %s", requestBody)
	}
	if hasReasoningEffort && reasoningEffort == "" {
		t.Errorf("Chat upstream reasoning_effort is empty: %s", requestBody)
	}
	t.Logf("reasoning signal: reasoning_effort=%q thinking=%v", reasoningEffort, thinking)
}

func TestE2EAnthropicCPAResponsesUpstreamFallsBack(t *testing.T) {
	const anthropicBody = `{"model":"anth-resp","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`
	const responsesResponse = `{"id":"resp-x","object":"response","status":"completed","model":"M","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}],"usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}`
	mock := &e2EJSONMock{response: []byte(responsesResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/responses", mock.handler)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	applyConfig(AppConfig{
		ModelAlias: map[string]ModelAlias{"anth-resp": {TargetModel: "M", Upstream: "up-resp"}},
		Upstreams: map[string]*UpstreamConfig{
			"up-resp": {BaseURL: upstream.URL, APIKey: "k", APIType: UpstreamResponses},
		},
		CPATranslator: CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true},
	})
	t.Cleanup(func() {
		applyConfig(AppConfig{ModelAlias: map[string]ModelAlias{}, Upstreams: map[string]*UpstreamConfig{}})
	})

	gateway := e2EAnthropicMessagesServer()
	defer gateway.Close()
	status, responseBody := postE2EAnthropicMessages(t, gateway.URL, anthropicBody)
	t.Logf("Responses fallback gateway Claude response: %s", responseBody)
	assertE2EClaudeMessageResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	assertE2EResponsesWireRequest(t, requestBody, headers)
}

func postE2EResponses(t *testing.T, serverURL, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(serverURL+"/v1/responses", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST responses: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read responses response: %v", err)
	}
	return resp.StatusCode, got
}

func e2EResponsesServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/responses", responsesHandler)
	return httptest.NewServer(mux)
}

func assertE2EResponsesResponse(t *testing.T, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("gateway responses status = %d, body = %s", status, body)
	}
	obj := decodeE2EJSON(t, body)
	if obj["object"] != "response" {
		t.Fatalf("response object = %v, want response; body=%s", obj["object"], body)
	}
	output, ok := obj["output"].([]any)
	if !ok || len(output) == 0 {
		t.Fatalf("response has no output: %s", body)
	}
	message, ok := output[0].(map[string]any)
	if !ok {
		t.Fatalf("response output[0] has unexpected shape: %s", body)
	}
	content, ok := message["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("response output[0] has no content: %s", body)
	}
	text, ok := content[0].(map[string]any)
	if !ok || text["type"] != "output_text" || text["text"] != "hello" {
		t.Fatalf("response output[0].content[0] = %v, want output_text hello; body=%s", content[0], body)
	}
	usage, ok := obj["usage"].(map[string]any)
	if !ok {
		t.Fatalf("response has no usage: %s", body)
	}
	if usage["input_tokens"] != float64(3) || usage["output_tokens"] != float64(2) || usage["total_tokens"] != float64(5) {
		t.Fatalf("response usage = %v, want input=3 output=2 total=5; body=%s", usage, body)
	}
}

func configureResponsesE2E(t *testing.T, alias, upstreamURL string, upstreamType UpstreamType, cpa CPATranslatorConfig) {
	t.Helper()
	applyConfig(AppConfig{
		ModelAlias: map[string]ModelAlias{alias: {TargetModel: "M", Upstream: "up"}},
		Upstreams: map[string]*UpstreamConfig{
			"up": {BaseURL: upstreamURL, APIKey: "k", APIType: upstreamType},
		},
		CPATranslator: cpa,
	})
	t.Cleanup(func() {
		applyConfig(AppConfig{ModelAlias: map[string]ModelAlias{}, Upstreams: map[string]*UpstreamConfig{}})
	})
}
func TestE2EResponsesCPAPathChatUpstream(t *testing.T) {
	const chatResponse = `{"id":"chatcmpl-x","object":"chat.completion","model":"M","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	for _, tc := range []struct {
		name string
		cpa  CPATranslatorConfig
	}{
		{name: "CPA enabled", cpa: CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true}},
		{name: "CPA disabled", cpa: CPATranslatorConfig{Enabled: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &e2EJSONMock{response: []byte(chatResponse)}
			mux := http.NewServeMux()
			mux.HandleFunc("/chat/completions", mock.handler)
			upstream := httptest.NewServer(mux)
			defer upstream.Close()
			configureResponsesE2E(t, "resp-chat", upstream.URL, UpstreamOpenAI, tc.cpa)
			gateway := e2EResponsesServer()
			defer gateway.Close()

			body := `{"model":"resp-chat","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_output_tokens":100}`
			status, responseBody := postE2EResponses(t, gateway.URL, body)
			t.Logf("gateway Responses response: %s", responseBody)
			assertE2EResponsesResponse(t, status, responseBody)

			requestBody, headers := mock.request()
			if tc.cpa.Enabled {
				req := decodeE2EJSON(t, requestBody)
				t.Logf("mock Chat upstream request: %s", requestBody)
				assertE2EOpenAIAuth(t, headers)
				if req["model"] != "M" {
					t.Errorf("Chat upstream model = %v, want M; body=%s", req["model"], requestBody)
				}
				messages := req["messages"].([]any)
				first := messages[0].(map[string]any)
				if first["role"] != "user" {
					t.Errorf("Chat upstream messages[0].role = %v, want user; body=%s", first["role"], requestBody)
				}
				content := first["content"].([]any)
				block := content[0].(map[string]any)
				if block["type"] != "text" || block["text"] != "hi" {
					t.Errorf("CPA Chat content block = %v, want text hi; body=%s", block, requestBody)
				}
			} else {
				assertE2EChatWireRequest(t, requestBody, headers)
			}
		})
	}
}

func TestE2EResponsesCPAPathAnthropicUpstream(t *testing.T) {
	const claudeResponse = `{"id":"msg_x","type":"message","role":"assistant","model":"M","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}`
	mock := &e2EJSONMock{response: []byte(claudeResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/messages", mock.handler)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	configureResponsesE2E(t, "resp-claude", upstream.URL, UpstreamAnthropic, CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true})
	gateway := e2EResponsesServer()
	defer gateway.Close()

	body := `{"model":"resp-claude","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"max_output_tokens":100}`
	status, responseBody := postE2EResponses(t, gateway.URL, body)
	t.Logf("gateway Responses response: %s", responseBody)
	assertE2EResponsesResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	req := assertE2EClaudeRequest(t, requestBody, headers)
	if req["model"] != "M" {
		t.Errorf("Claude upstream model = %v, want M; body=%s", req["model"], requestBody)
	}
	messages := req["messages"].([]any)
	if messages[0].(map[string]any)["content"] != "hi" {
		t.Errorf("Claude upstream content = %v, want hi; body=%s", messages[0], requestBody)
	}
	if metadata, ok := req["metadata"].(map[string]any); ok {
		if _, hasUserID := metadata["user_id"]; hasUserID {
			t.Errorf("CPA metadata.user_id was not stripped: %v; body=%s", metadata, requestBody)
		}
	}
}

func TestE2EResponsesCPAPathWithReasoning(t *testing.T) {
	const chatResponse = `{"id":"chatcmpl-x","object":"chat.completion","model":"M","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	mock := &e2EJSONMock{response: []byte(chatResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", mock.handler)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	configureResponsesE2E(t, "resp-chat", upstream.URL, UpstreamOpenAI, CPATranslatorConfig{Enabled: true, Requests: true, NonStreamResponses: true})
	gateway := e2EResponsesServer()
	defer gateway.Close()

	body := `{"model":"resp-chat","input":"hi","max_output_tokens":100,"reasoning":{"effort":"high"}}`
	status, responseBody := postE2EResponses(t, gateway.URL, body)
	t.Logf("reasoning gateway Responses response: %s", responseBody)
	assertE2EResponsesResponse(t, status, responseBody)

	requestBody, headers := mock.request()
	req := assertE2EChatWireRequest(t, requestBody, headers)
	if got, ok := req["reasoning_effort"].(string); !ok || got != "high" {
		t.Errorf("Chat upstream reasoning_effort = %v, want high; body=%s", req["reasoning_effort"], requestBody)
	}
}
