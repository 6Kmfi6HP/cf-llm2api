package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConvertChatToResponsesReasoningContent(t *testing.T) {
	chat := []byte(`{"id":"chatcmpl-reasoning","created":1710000000,"choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"思考全文...","content":"最终答案"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	body := convertChatToResponses(chat, "M", nil, nil, nil)
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("convertChatToResponses returned invalid JSON: %v; body=%s", err, body)
	}
	output, ok := response["output"].([]any)
	if !ok || len(output) != 2 {
		t.Fatalf("response.output = %v, want reasoning and message items; body=%s", response["output"], body)
	}

	reasoning, ok := output[0].(map[string]any)
	if !ok {
		t.Fatalf("response.output[0] has unexpected shape: %v", output[0])
	}
	if reasoning["type"] != "reasoning" {
		t.Errorf("response.output[0].type = %v, want reasoning", reasoning["type"])
	}
	content, ok := reasoning["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("reasoning.content = %v, want one reasoning_text part", reasoning["content"])
	}
	part, ok := content[0].(map[string]any)
	if !ok || part["type"] != "reasoning_text" || part["text"] != "思考全文..." {
		t.Errorf("reasoning.content[0] = %v, want reasoning_text 思考全文...", content[0])
	}
	summary, ok := reasoning["summary"].([]any)
	if !ok || len(summary) != 1 {
		t.Fatalf("reasoning.summary = %v, want one summary_text part", reasoning["summary"])
	}
	summaryPart, ok := summary[0].(map[string]any)
	if !ok || summaryPart["type"] != "summary_text" || summaryPart["text"] != "思考全文..." {
		t.Errorf("reasoning.summary[0] = %v, want summary_text 思考全文...", summary[0])
	}

	message, ok := output[1].(map[string]any)
	if !ok || message["type"] != "message" {
		t.Fatalf("response.output[1] = %v, want message item", output[1])
	}
	messageContent, ok := message["content"].([]any)
	if !ok || len(messageContent) != 1 {
		t.Fatalf("message.content = %v, want one output_text part", message["content"])
	}
	textPart, ok := messageContent[0].(map[string]any)
	if !ok || textPart["type"] != "output_text" || textPart["text"] != "最终答案" {
		t.Errorf("message.content[0] = %v, want output_text 最终答案", messageContent[0])
	}
}

func TestResponsesStreamReasoningUsesTextEvents(t *testing.T) {
	const streamBody = "data: {\"id\":\"chatcmpl-stream-reasoning\",\"object\":\"chat.completion.chunk\",\"created\":1710000000,\"model\":\"M\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"思考片段一\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-stream-reasoning\",\"object\":\"chat.completion.chunk\",\"created\":1710000000,\"model\":\"M\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"思考片段二\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-stream-reasoning\",\"object\":\"chat.completion.chunk\",\"created\":1710000000,\"model\":\"M\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"最终答案\"},\"finish_reason\":null}]}\n\n" +
		"data: {\"id\":\"chatcmpl-stream-reasoning\",\"object\":\"chat.completion.chunk\",\"created\":1710000000,\"model\":\"M\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, streamBody)
	}))
	defer upstream.Close()
	configureResponsesE2E(t, "resp-stream-reasoning", upstream.URL, UpstreamOpenAI, CPATranslatorConfig{Enabled: false})
	gateway := e2EResponsesServer()
	defer gateway.Close()

	body := `{"model":"resp-stream-reasoning","input":"hi","stream":true,"max_output_tokens":100,"reasoning":{"effort":"high"}}`
	status, responseBody := postE2EResponses(t, gateway.URL, body)
	if status != http.StatusOK {
		t.Fatalf("gateway stream status = %d, body=%s", status, responseBody)
	}
	if !strings.HasPrefix(string(responseBody), "event: ") {
		t.Fatalf("gateway response is not SSE: %s", responseBody)
	}

	events := parseResponsesSSE(t, responseBody)
	wantEvents := []string{
		"response.output_item.added",
		"response.reasoning_text.delta",
		"response.reasoning_text.delta",
		"response.reasoning_text.done",
		"response.output_item.done",
		"response.output_item.added",
		"response.output_text.delta",
	}
	positions := map[string]int{}
	for i, event := range events {
		if _, ok := positions[event.name]; !ok {
			positions[event.name] = i
		}
		if strings.Contains(event.name, "reasoning_summary") {
			t.Errorf("unexpected summary reasoning event %q: %s", event.name, event.data)
		}
	}
	for _, name := range wantEvents {
		if _, ok := positions[name]; !ok {
			t.Errorf("missing SSE event %q; events=%v", name, eventNames(events))
		}
	}
	if positions["response.reasoning_text.delta"] >= positions["response.output_text.delta"] {
		t.Errorf("reasoning delta should precede output text delta; events=%v", eventNames(events))
	}
	// There are two output_item.added events; compare reasoning completion against
	// the message item specifically, not the first (reasoning) item.
	messageAdded := findSSEEvent(t, events, "response.output_item.added", func(data map[string]any) bool {
		item, _ := data["item"].(map[string]any)
		return item["type"] == "message"
	})
	if messageAdded < 0 {
		t.Fatalf("missing message output_item.added; events=%v", eventNames(events))
	}
	if positions["response.reasoning_text.done"] >= messageAdded {
		t.Errorf("reasoning done should precede message added; events=%v", eventNames(events))
	}

	textDone := findSSEEventData(t, events, "response.reasoning_text.done", nil)
	if textDone["text"] != "思考片段一思考片段二" {
		t.Errorf("reasoning text done = %v, want full reasoning", textDone["text"])
	}

	added := findSSEEventData(t, events, "response.reasoning_text.delta", nil)
	if added["delta"] != "思考片段一" {
		t.Errorf("first reasoning delta = %v, want 思考片段一", added["delta"])
	}
	reasoningDone := findSSEEventData(t, events, "response.output_item.done", func(data map[string]any) bool {
		item, _ := data["item"].(map[string]any)
		return item["type"] == "reasoning"
	})
	item, _ := reasoningDone["item"].(map[string]any)
	if summary, ok := item["summary"].([]any); !ok || len(summary) != 0 {
		t.Errorf("completed reasoning item.summary = %v, want empty array", item["summary"])
	}
	content, ok := item["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("completed reasoning item.content = %v, want one part", item["content"])
	}
	completedPart, _ := content[0].(map[string]any)
	if completedPart["type"] != "reasoning_text" || completedPart["text"] != "思考片段一思考片段二" {
		t.Errorf("completed reasoning content = %v, want full reasoning_text", content)
	}
}

type responsesSSE struct {
	name string
	data map[string]any
}

func parseResponsesSSE(t *testing.T, body []byte) []responsesSSE {
	t.Helper()
	var events []responsesSSE
	scanner := bufio.NewScanner(bytes.NewReader(body))
	var name string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: ") && name != "":
			var data map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &data); err != nil {
				t.Fatalf("invalid SSE data for %s: %v", name, err)
			}
			events = append(events, responsesSSE{name: name, data: data})
			name = ""
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan SSE response: %v", err)
	}
	return events
}

func eventNames(events []responsesSSE) []string {
	names := make([]string, 0, len(events))
	for _, event := range events {
		names = append(names, event.name)
	}
	return names
}

func findSSEEvent(t *testing.T, events []responsesSSE, name string, match func(map[string]any) bool) int {
	t.Helper()
	for i, event := range events {
		if event.name == name && (match == nil || match(event.data)) {
			return i
		}
	}
	return -1
}

func findSSEEventData(t *testing.T, events []responsesSSE, name string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	idx := findSSEEvent(t, events, name, match)
	if idx < 0 {
		t.Fatalf("missing SSE event %q; events=%v", name, eventNames(events))
	}
	return events[idx].data
}

func TestResponsesReasoningSummaryAccepted(t *testing.T) {
	const chatResponse = `{"id":"chatcmpl-summary","object":"chat.completion","model":"M","choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"思考全文","content":"答案"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	mock := &e2EJSONMock{response: []byte(chatResponse)}
	mux := http.NewServeMux()
	mux.HandleFunc("/chat/completions", mock.handler)
	upstream := httptest.NewServer(mux)
	defer upstream.Close()
	configureResponsesE2E(t, "resp-summary", upstream.URL, UpstreamOpenAI, CPATranslatorConfig{Enabled: false})
	gateway := e2EResponsesServer()
	defer gateway.Close()

	body := `{"model":"resp-summary","input":"hi","max_output_tokens":100,"reasoning":{"effort":"high","summary":"detailed"}}`
	status, responseBody := postE2EResponses(t, gateway.URL, body)
	if status != http.StatusOK {
		t.Fatalf("gateway status = %d, body=%s", status, responseBody)
	}
	response := decodeE2EJSON(t, responseBody)
	output, ok := response["output"].([]any)
	if !ok || len(output) < 1 {
		t.Fatalf("response output = %v, body=%s", response["output"], responseBody)
	}
	reasoning, _ := output[0].(map[string]any)
	if reasoning["type"] != "reasoning" {
		t.Errorf("response output[0].type = %v, want reasoning", reasoning["type"])
	}
	requestBody, headers := mock.request()
	req := assertE2EChatWireRequest(t, requestBody, headers)
	if got, ok := req["reasoning_effort"].(string); !ok || got != "high" {
		t.Errorf("Chat upstream reasoning_effort = %v, want high; body=%s", req["reasoning_effort"], requestBody)
	}
	// summary 是输出偏好，不应被转发给 Chat 上游 body
	if _, present := req["reasoning"]; present {
		if rmap, ok := req["reasoning"].(map[string]any); ok {
			if _, has := rmap["summary"]; has {
				t.Errorf("reasoning.summary leaked to Chat upstream body: %s", requestBody)
			}
		}
	}
	if _, present := req["summary"]; present {
		t.Errorf("top-level summary leaked to Chat upstream body: %s", requestBody)
	}
}

func TestResponsesReasoningSummaryInvalidRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid reasoning.summary must be rejected before calling upstream")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	configureResponsesE2E(t, "resp-summary-invalid", upstream.URL, UpstreamOpenAI, CPATranslatorConfig{Enabled: false})
	gateway := e2EResponsesServer()
	defer gateway.Close()

	body := `{"model":"resp-summary-invalid","input":"hi","max_output_tokens":100,"reasoning":{"effort":"high","summary":"THIS_IS_INVALID"}}`
	status, responseBody := postE2EResponses(t, gateway.URL, body)
	if status != http.StatusBadRequest {
		t.Fatalf("gateway status = %d, want 400; body=%s", status, responseBody)
	}
	errObj := decodeE2EJSON(t, responseBody)
	errField, ok := errObj["error"].(map[string]any)
	if !ok {
		t.Fatalf("response body has no error object: %s", responseBody)
	}
	if errField["type"] != "invalid_request_error" {
		t.Errorf("error.type = %v, want invalid_request_error", errField["type"])
	}
	if errField["code"] != "unsupported_value" {
		t.Errorf("error.code = %v, want unsupported_value", errField["code"])
	}
	if errField["param"] != "reasoning.summary" {
		t.Errorf("error.param = %v, want reasoning.summary", errField["param"])
	}
}
