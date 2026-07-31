package main

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// sseEvent 是从 anthropicStreamHandler 输出里解析出来的一个事件。
type sseEvent struct {
	name string
	data map[string]any
}

func parseAnthropicEvents(t *testing.T, raw string) []sseEvent {
	t.Helper()
	var events []sseEvent
	var current string
	for _, line := range strings.Split(raw, "\n") {
		switch {
		case strings.HasPrefix(line, "event: "):
			current = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			var payload map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &payload); err != nil {
				t.Fatalf("事件 %q 的 data 不是合法 JSON: %v", current, err)
			}
			events = append(events, sseEvent{name: current, data: payload})
		}
	}
	return events
}

// runAnthropicStream 把一段 OpenAI Chat SSE 喂给 anthropicStreamHandler，返回解析后的事件序列。
func runAnthropicStream(t *testing.T, upstreamSSE string) []sseEvent {
	t.Helper()
	rec := httptest.NewRecorder()
	anthropicStreamHandler(rec, io.NopCloser(strings.NewReader(upstreamSSE)), "test-model")
	return parseAnthropicEvents(t, rec.Body.String())
}

func eventIndex(e sseEvent) int {
	if v, ok := e.data["index"].(float64); ok {
		return int(v)
	}
	return -1
}

// TestAnthropicStreamInterleavedToolCallsKeepBlockIndex 覆盖并行工具调用的串块 bug：
// 上游交错推送两个 tool_call 的 arguments 分片时，每个 input_json_delta 必须落在自己的块上。
// 旧实现用 blockIndex-1 推断索引，后到的分片会全部写到最后一个块。
func TestAnthropicStreamInterleavedToolCallsKeepBlockIndex(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"alpha","arguments":"{\"a\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"beta","arguments":"{\"b\":"}}]}}]}`,
		// 回到工具 0 —— 关键：这一片必须落在工具 0 的块上，而不是最后开的工具 1。
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"2}"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14}}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	// 记录每个工具名对应的块索引。
	blockOfTool := map[string]int{}
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] != "tool_use" {
			continue
		}
		blockOfTool[cb["name"].(string)] = eventIndex(e)
	}
	if len(blockOfTool) != 2 || blockOfTool["alpha"] == blockOfTool["beta"] {
		t.Fatalf("两个工具应各占一个块: %v", blockOfTool)
	}

	// 按块索引累积 partial_json，还原每个工具的完整 arguments。
	argsOfBlock := map[int]string{}
	for _, e := range events {
		if e.name != "content_block_delta" {
			continue
		}
		delta, _ := e.data["delta"].(map[string]any)
		if delta["type"] != "input_json_delta" {
			continue
		}
		argsOfBlock[eventIndex(e)] += delta["partial_json"].(string)
	}

	if got := argsOfBlock[blockOfTool["alpha"]]; got != `{"a":1}` {
		t.Errorf("alpha 的 arguments 串块了: got %q want %q", got, `{"a":1}`)
	}
	if got := argsOfBlock[blockOfTool["beta"]]; got != `{"b":2}` {
		t.Errorf("beta 的 arguments 串块了: got %q want %q", got, `{"b":2}`)
	}

	// content_block_stop 必须覆盖两个工具块，且是官方形状（只有 type + index，无 content_block）。
	stopped := map[int]bool{}
	for _, e := range events {
		if e.name != "content_block_stop" {
			continue
		}
		if _, extra := e.data["content_block"]; extra {
			t.Errorf("content_block_stop 携带了非标准的 content_block 字段: %v", e.data)
		}
		stopped[eventIndex(e)] = true
	}
	for name, idx := range blockOfTool {
		if !stopped[idx] {
			t.Errorf("工具 %s 的块(index=%d)没有收到 content_block_stop", name, idx)
		}
	}
}

// TestAnthropicStreamDefersToolBlockUntilNameArrives 覆盖上游"先发 id、后发 name"的分片形态。
// content_block_start 一旦发出就无法修正，若在 name 到达前就建块，客户端会收到 name:"" 的
// tool_use 并报 unknown tool。正确行为是推迟建块、期间把 arguments 缓冲下来，建块后一次补发。
func TestAnthropicStreamDefersToolBlockUntilNameArrives(t *testing.T) {
	upstream := strings.Join([]string{
		// 第一片只有 id，没有 function.name
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_x","function":{"arguments":"{\"q\":"}}]}}]}`,
		// name 到这一片才出现
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"search","arguments":"\"go\"}"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	starts := 0
	blockIdx := -1
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] != "tool_use" {
			continue
		}
		starts++
		if name, _ := cb["name"].(string); name != "search" {
			t.Errorf("tool_use 块的 name 应为 search，得到 %q（提前建块了）", name)
		}
		if id, _ := cb["id"].(string); id != "call_x" {
			t.Errorf("先到的 id 丢失: %q", id)
		}
		blockIdx = eventIndex(e)
	}
	if starts != 1 {
		t.Fatalf("应恰好建一个 tool_use 块，实际 %d 个", starts)
	}

	// name 到达前缓冲的参数必须一字不差地补发出来。
	args := ""
	for _, e := range events {
		if e.name != "content_block_delta" || eventIndex(e) != blockIdx {
			continue
		}
		delta, _ := e.data["delta"].(map[string]any)
		if delta["type"] == "input_json_delta" {
			args += delta["partial_json"].(string)
		}
	}
	if args != `{"q":"go"}` {
		t.Errorf("缓冲的 arguments 丢失或错序: got %q want %q", args, `{"q":"go"}`)
	}
}

// TestAnthropicStreamDropsNamelessToolAndDowngradesStopReason：上游报了 tool_calls
// 却始终没给 function.name 时，宁可丢掉这个不完整的工具调用，也不能回 stop_reason=tool_use
// ——那会让客户端阻塞等待一个永远不会来的工具结果。
func TestAnthropicStreamDropsNamelessToolAndDowngradesStopReason(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"我来查一下"}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_y","function":{"arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		if cb, _ := e.data["content_block"].(map[string]any); cb["type"] == "tool_use" {
			t.Errorf("不该宣告没有 name 的 tool_use 块: %v", cb)
		}
	}

	sawDelta := false
	for _, e := range events {
		if e.name != "message_delta" {
			continue
		}
		sawDelta = true
		delta, _ := e.data["delta"].(map[string]any)
		if delta["stop_reason"] != "end_turn" {
			t.Errorf("没有成形的工具块时 stop_reason 应降级为 end_turn，得到 %v", delta["stop_reason"])
		}
	}
	if !sawDelta {
		t.Fatal("缺少 message_delta")
	}
}

// TestAnthropicStreamRejectsTruncatedToolStream：流在 finish_reason 之前断开时，
// 缓冲中的 tool arguments 可能只是半截 JSON，不能把它宣告成可执行 tool_use，更不能伪装成
// 正常 end_turn。正确行为是发流内 error，且不发 message_delta/message_stop。
func TestAnthropicStreamRejectsTruncatedToolStream(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_z","function":{"name":"read","arguments":"{\"p\":1"}}]}}]}`,
		// 没有 finish_reason，也没有 [DONE]——上游断了
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	sawError := false
	for _, e := range events {
		switch e.name {
		case "content_block_start":
			if cb, _ := e.data["content_block"].(map[string]any); cb["type"] == "tool_use" {
				t.Errorf("截断流不应宣告可能不完整的 tool_use: %v", cb)
			}
		case "message_delta", "message_stop":
			t.Errorf("截断流不能伪装成正常完成，出现了 %s", e.name)
		case "error":
			sawError = true
		}
	}
	if !sawError {
		t.Fatal("截断流缺少 error 事件")
	}
}

// TestAnthropicStreamThinkingSignatureDelta 验证 thinking 块按官方协议在关闭前收到 signature_delta，
// 且 content_block_start 带 signature 字段——这是多轮回放闭环的签发端。
func TestAnthropicStreamThinkingSignatureDelta(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"reasoning_content":"想一想"}}]}`,
		`data: {"choices":[{"delta":{"content":"答案"}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	var thinkingIdx = -1
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] == "thinking" {
			thinkingIdx = eventIndex(e)
			if _, ok := cb["signature"]; !ok {
				t.Errorf("thinking 块的 content_block_start 缺少 signature 字段: %v", cb)
			}
		}
	}
	if thinkingIdx < 0 {
		t.Fatal("没有产生 thinking 块")
	}

	// signature_delta 必须出现在该块的 content_block_stop 之前。
	sawSignature := false
	for _, e := range events {
		if e.name == "content_block_delta" && eventIndex(e) == thinkingIdx {
			if delta, _ := e.data["delta"].(map[string]any); delta["type"] == "signature_delta" {
				sig, _ := delta["signature"].(string)
				if !thinkingSignatureUsable(sig) {
					t.Errorf("signature_delta 的签名不可用: %q", sig)
				}
				sawSignature = true
			}
		}
		if e.name == "content_block_stop" && eventIndex(e) == thinkingIdx {
			if !sawSignature {
				t.Fatal("content_block_stop 先于 signature_delta 到达")
			}
			break
		}
	}
	if !sawSignature {
		t.Error("thinking 块没有收到 signature_delta")
	}
}

func assertContentBlocksStrictlySerial(t *testing.T, events []sseEvent) {
	t.Helper()
	open := -1
	for i, e := range events {
		switch e.name {
		case "content_block_start":
			if open >= 0 {
				t.Fatalf("事件 %d 在 block %d 尚未 stop 时又 start block %d", i, open, eventIndex(e))
			}
			open = eventIndex(e)
		case "content_block_delta":
			if eventIndex(e) != open {
				t.Fatalf("事件 %d 的 delta index=%d 不属于当前打开块 %d", i, eventIndex(e), open)
			}
		case "content_block_stop":
			if eventIndex(e) != open {
				t.Fatalf("事件 %d 的 stop index=%d 不匹配当前打开块 %d", i, eventIndex(e), open)
			}
			open = -1
		}
	}
	if open >= 0 {
		t.Fatalf("流结束时 block %d 仍未关闭", open)
	}
}

func finalMessageStopReason(events []sseEvent) string {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].name != "message_delta" {
			continue
		}
		delta, _ := events[i].data["delta"].(map[string]any)
		reason, _ := delta["stop_reason"].(string)
		return reason
	}
	return ""
}

func TestAnthropicStreamToolBlocksAreStrictlySerial(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"alpha","arguments":"{\"a\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"beta","arguments":"{\"b\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":2,"id":"c","function":{"name":"gamma","arguments":"{\"c\":"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":2,"function":{"arguments":"3}"}},{"index":0,"function":{"arguments":"1}"}},{"index":1,"function":{"arguments":"2}"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)
	assertContentBlocksStrictlySerial(t, events)

	var sequence []string
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] == "tool_use" {
			sequence = append(sequence, cb["name"].(string))
		}
	}
	if got := strings.Join(sequence, ","); got != "alpha,beta,gamma" {
		t.Fatalf("工具块顺序错误: got %q", got)
	}
}

func TestAnthropicStreamToolAfterTextRemainsSerial(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"alpha","arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{"content":"先给说明"}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)
	assertContentBlocksStrictlySerial(t, events)
	if got := finalMessageStopReason(events); got != "tool_use" {
		t.Fatalf("存在成形 tool_use 时必须校正 stop_reason，got %q", got)
	}
}

func TestAnthropicStreamNamelessOnlyToolGetsVisibleFallback(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"bad","function":{"arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)
	assertContentBlocksStrictlySerial(t, events)
	text := ""
	for _, e := range events {
		if e.name != "content_block_delta" {
			continue
		}
		delta, _ := e.data["delta"].(map[string]any)
		if delta["type"] == "text_delta" {
			text += delta["text"].(string)
		}
	}
	if text == "" {
		t.Fatal("唯一工具不完整时不应返回空 content")
	}
	if got := finalMessageStopReason(events); got != "end_turn" {
		t.Fatalf("未发出 tool_use 时应降级为 end_turn，got %q", got)
	}
}

func TestAnthropicStreamIgnoresContentAfterFinish(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"done"}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"late","function":{"name":"late_tool","arguments":"{}"}}]}}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] == "tool_use" {
			t.Fatalf("finish 后的 tool delta 不应产出块: %v", cb)
		}
	}
	if len(events) == 0 || events[len(events)-1].name != "message_stop" {
		t.Fatalf("正常流最后一个事件必须是 message_stop: %#v", events)
	}
}

func TestAnthropicStreamLengthDropsPartialTool(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"partial","function":{"name":"write","arguments":"{\"x\":"}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"length"}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)
	for _, e := range events {
		if e.name != "content_block_start" {
			continue
		}
		cb, _ := e.data["content_block"].(map[string]any)
		if cb["type"] == "tool_use" {
			t.Fatalf("length 截断的工具参数不能执行: %v", cb)
		}
	}
	if got := finalMessageStopReason(events); got != "max_tokens" {
		t.Fatalf("length 应映射为 max_tokens，got %q", got)
	}
}

func TestResponsesToAnthropicStreamToolPipeline(t *testing.T) {
	responsesSSE := strings.Join([]string{
		`event: response.output_item.added`,
		`data: {"type":"response.output_item.added","item":{"type":"function_call","id":"item_1","call_id":"call_1","name":"lookup"}}`,
		``,
		`event: response.function_call_arguments.delta`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"item_1","delta":"{\"q\":"}`,
		``,
		`event: response.function_call_arguments.delta`,
		`data: {"type":"response.function_call_arguments.delta","item_id":"item_1","delta":"\"go\"}"}`,
		``,
		`event: response.completed`,
		`data: {"type":"response.completed","response":{"usage":{"input_tokens":9,"output_tokens":2,"total_tokens":11}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")

	pr, pw := io.Pipe()
	go func() {
		chatW := &pipeResponseWriter{w: pw}
		responsesStreamToChatHandler(chatW, io.NopCloser(strings.NewReader(responsesSSE)), "test-model", false)
		_ = pw.Close()
	}()

	rec := httptest.NewRecorder()
	anthropicStreamHandler(rec, io.NopCloser(pr), "test-model")
	events := parseAnthropicEvents(t, rec.Body.String())
	assertContentBlocksStrictlySerial(t, events)

	toolArgs := ""
	for _, e := range events {
		if e.name != "content_block_delta" {
			continue
		}
		delta, _ := e.data["delta"].(map[string]any)
		if delta["type"] == "input_json_delta" {
			toolArgs += delta["partial_json"].(string)
		}
	}
	if toolArgs != `{"q":"go"}` {
		t.Fatalf("Responses→Chat→Anthropic 工具参数丢失: %q", toolArgs)
	}
	if got := finalMessageStopReason(events); got != "tool_use" {
		t.Fatalf("Responses 工具链路 stop_reason 错误: %q", got)
	}
}

// TestAnthropicStreamUsageCacheFields 验证 message_delta 的 usage 带上 Anthropic 恒有的 cache_* 字段，
// 且缓存命中部分从 input_tokens 里拆出来（与上游总量口径一致）。
func TestAnthropicStreamUsageCacheFields(t *testing.T) {
	upstream := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"hi"}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":7,"total_tokens":107,"prompt_tokens_details":{"cached_tokens":40}}}`,
		`data: [DONE]`,
		"",
	}, "\n")

	events := runAnthropicStream(t, upstream)

	for _, e := range events {
		if e.name != "message_delta" {
			continue
		}
		usage, _ := e.data["usage"].(map[string]any)
		if usage["input_tokens"] != float64(60) {
			t.Errorf("input_tokens 应扣除缓存命中部分: %v", usage["input_tokens"])
		}
		if usage["cache_read_input_tokens"] != float64(40) {
			t.Errorf("cache_read_input_tokens 错误: %v", usage["cache_read_input_tokens"])
		}
		if _, ok := usage["cache_creation_input_tokens"]; !ok {
			t.Errorf("缺少 cache_creation_input_tokens: %v", usage)
		}
		return
	}
	t.Fatal("没有 message_delta 事件")
}
