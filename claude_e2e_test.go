package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withFakeChatUpstream 起一个假的 OpenAI Chat 上游，把网关实际发出的请求体交给 capture，
// 并返回一个固定的 Chat 响应。同时注入 alias/upstream 配置并在测试结束后恢复。
func withFakeChatUpstream(t *testing.T, cpaEnabled bool, capture *[]byte) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读取上游请求体失败: %v", err)
		}
		*capture = buf
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id":"chatcmpl-1","model":"upstream-model","choices":[{
				"message":{"content":"最终答案","reasoning_content":"推理过程"},
				"finish_reason":"stop"
			}],
			"usage":{"prompt_tokens":100,"completion_tokens":8,"total_tokens":108,
			         "prompt_tokens_details":{"cached_tokens":30}}
		}`))
	}))
	t.Cleanup(srv.Close)

	configMu.RLock()
	prevAlias, prevUpstreams, prevCPA, prevCompat := modelAlias, upstreamCfgs, cpaTranslatorCfg, claudeCompatCfg
	configMu.RUnlock()
	t.Cleanup(func() {
		configMu.Lock()
		modelAlias, upstreamCfgs, cpaTranslatorCfg, claudeCompatCfg = prevAlias, prevUpstreams, prevCPA, prevCompat
		configMu.Unlock()
	})

	applyConfig(AppConfig{
		ModelAlias: map[string]ModelAlias{
			"test-alias": {TargetModel: "upstream-model", Upstream: "fake"},
		},
		Upstreams: map[string]*UpstreamConfig{
			"fake": {BaseURL: srv.URL, APIType: UpstreamOpenAI, APIKey: "k"},
		},
		CPATranslator: CPATranslatorConfig{Enabled: cpaEnabled, Requests: cpaEnabled, NonStreamResponses: cpaEnabled},
	})
	return srv
}

// richClaudeRequest 是一条"什么都带一点"的 Claude 请求：上一轮的思考、失败的工具结果、
// 文档、以及 Claude 独有的顶层参数。这些结构在改造前会被整段丢弃或让上游 400。
func richClaudeRequest() string {
	return `{
		"model":"test-alias",
		"max_tokens":1024,
		"temperature":0.5,
		"top_p":0.9,
		"stop_sequences":["</done>"],
		"system":"你是助手",
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"看下这份文档"},
				{"type":"document","title":"规范","source":{"type":"text","media_type":"text/plain","data":"第三条 必须重试"}}
			]},
			{"role":"assistant","content":[
				{"type":"thinking","thinking":"先查文件再决定"},
				{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"path":"/tmp/a"}}
			]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_1","is_error":true,"content":"permission denied"}
			]}
		]
	}`
}

func postClaudeMessages(t *testing.T, bodyJSON string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(bodyJSON))
	rec := httptest.NewRecorder()
	anthropicMessagesHandler(rec, req)
	return rec
}

// TestClaudeInboundEndToEndWithCPA 端到端验证：Claude 入站 → L1 降级 → CPA 翻译 → patch → 上游。
// 逐项断言"改造前会丢/会 400"的东西现在都到了上游。
func TestClaudeInboundEndToEndWithCPA(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, true, &upstreamBody)

	rec := postClaudeMessages(t, richClaudeRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d，响应: %s", rec.Code, rec.Body.String())
	}

	var sent map[string]any
	if err := json.Unmarshal(upstreamBody, &sent); err != nil {
		t.Fatalf("上游收到的不是合法 JSON: %v\n%s", err, upstreamBody)
	}
	flat := string(upstreamBody)

	t.Run("stop_sequences 到达上游", func(t *testing.T) {
		if sent["stop"] != "</done>" {
			t.Errorf("stop 缺失或错误: %v", sent["stop"])
		}
	})

	t.Run("temperature 与 top_p 同时保留", func(t *testing.T) {
		if sent["temperature"] != 0.5 {
			t.Errorf("temperature 丢失: %v", sent["temperature"])
		}
		if sent["top_p"] != 0.9 {
			t.Errorf("top_p 被 CPA 的互斥分支吃掉了: %v", sent["top_p"])
		}
	})

	t.Run("document 正文降级成文本后仍到达模型", func(t *testing.T) {
		if !strings.Contains(flat, "第三条 必须重试") {
			t.Errorf("document 正文丢失:\n%s", flat)
		}
	})

	t.Run("历史思考经 signature 闭环保留", func(t *testing.T) {
		if !strings.Contains(flat, "先查文件再决定") {
			t.Errorf("assistant 的历史 thinking 被丢弃（signature 门禁未通过）:\n%s", flat)
		}
		msgs, _ := sent["messages"].([]any)
		found := false
		for _, m := range msgs {
			msg, _ := m.(map[string]any)
			if rc, ok := msg["reasoning_content"].(string); ok && strings.Contains(rc, "先查文件再决定") {
				found = true
			}
		}
		if !found {
			t.Errorf("思考内容没有落在 reasoning_content 字段上:\n%s", flat)
		}
	})

	t.Run("工具失败标记保留", func(t *testing.T) {
		if !strings.Contains(flat, "[error] permission denied") {
			t.Errorf("tool_result 的 is_error 丢失，模型无法区分成败:\n%s", flat)
		}
	})

	t.Run("客户端响应补全 signature 与 usage", func(t *testing.T) {
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("响应不是合法 JSON: %v", err)
		}
		blocks, _ := resp["content"].([]any)
		sawSignedThinking := false
		for _, b := range blocks {
			block, _ := b.(map[string]any)
			if block["type"] != "thinking" {
				continue
			}
			if sig, _ := block["signature"].(string); thinkingSignatureUsable(sig) {
				sawSignedThinking = true
			}
		}
		if !sawSignedThinking {
			t.Errorf("响应里的 thinking 块没有可用 signature: %s", rec.Body.String())
		}
		usage, _ := resp["usage"].(map[string]any)
		if _, ok := usage["cache_read_input_tokens"]; !ok {
			t.Errorf("usage 缺少 cache_read_input_tokens: %v", usage)
		}
	})
}

// TestClaudeNonStreamUsageCachePropagation 覆盖 PR#2 comment 2：非流式 OpenAI→Anthropic 响应必须
// 把 prompt_tokens_details.cached_tokens 传播成 cache_read_input_tokens，并从 input_tokens 中扣除
// 缓存命中部分（与流式路径算法一致）。假上游固定回 cached_tokens=30。CPA 开关两条都断言数值，
// 否则两条翻译路径只要任一漏传就会把缓存统计报告为 0。
func TestClaudeNonStreamUsageCachePropagation(t *testing.T) {
	for _, cpa := range []bool{true, false} {
		t.Run(fmt.Sprintf("cpa=%v", cpa), func(t *testing.T) {
			var upstreamBody []byte
			withFakeChatUpstream(t, cpa, &upstreamBody)

			rec := postClaudeMessages(t, `{"model":"test-alias","max_tokens":1024,"messages":[{"role":"user","content":"hi"}]}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
			}

			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("响应不是合法 JSON: %v\n%s", err, rec.Body.String())
			}
			usage, ok := resp["usage"].(map[string]any)
			if !ok {
				t.Fatalf("响应缺少 usage: %s", rec.Body.String())
			}
			// 假上游回 prompt_tokens=100, cached_tokens=30；按流式口径 input_tokens 应为 100-30=70。
			if cacheRead, _ := usage["cache_read_input_tokens"].(float64); cacheRead != 30 {
				t.Errorf("cache_read_input_tokens 应为 30，得到 %v（usage=%v）", cacheRead, usage)
			}
			if inputTokens, _ := usage["input_tokens"].(float64); inputTokens != 70 {
				t.Errorf("input_tokens 应扣除缓存命中(100-30=70)，得到 %v（usage=%v）", inputTokens, usage)
			}
			if cacheCreate, ok := usage["cache_creation_input_tokens"]; !ok {
				t.Errorf("缺少 cache_creation_input_tokens: %v", usage)
			} else if cacheCreate.(float64) != 0 {
				t.Errorf("上游无 cache creation 量，cache_creation_input_tokens 应为 0，得到 %v", cacheCreate)
			}
		})
	}
}

// TestClaudeInboundEndToEndHandwritten 验证手写 fallback 路径同样受益于 L1 降级与上游补丁
// （CPA 灰度关时不能出现能力回退）。手写翻译不产出 reasoning_content，故此处不断言思考回放。
func TestClaudeInboundEndToEndHandwritten(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, false, &upstreamBody)

	rec := postClaudeMessages(t, richClaudeRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d，响应: %s", rec.Code, rec.Body.String())
	}

	var sent map[string]any
	if err := json.Unmarshal(upstreamBody, &sent); err != nil {
		t.Fatalf("上游收到的不是合法 JSON: %v\n%s", err, upstreamBody)
	}
	flat := string(upstreamBody)

	if sent["stop"] != "</done>" {
		t.Errorf("手写路径 stop 缺失: %v", sent["stop"])
	}
	if !strings.Contains(flat, "第三条 必须重试") {
		t.Errorf("手写路径 document 正文丢失:\n%s", flat)
	}
	if !strings.Contains(flat, "[error] permission denied") {
		t.Errorf("手写路径 is_error 丢失:\n%s", flat)
	}
}

// TestClaudeInboundHandwrittenImageOnlyToolResult 覆盖 PR#2 comment 1：CPA 关闭走手写 fallback 时，
// 成功且只含 image 子块的 tool_result 不能被吞成空 tool message。改造前手写转换器只取 text 子块，
// image-only 结果会让上游 tool message 内容为空，模型看不见工具结果。
func TestClaudeInboundHandwrittenImageOnlyToolResult(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, false, &upstreamBody)

	rec := postClaudeMessages(t, `{
		"model":"test-alias","max_tokens":1024,
		"messages":[
			{"role":"assistant","content":[{"type":"tool_use","id":"toolu_img","name":"screenshot","input":{}}]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_img","content":[
					{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0"}}
				]}
			]}
		]
	}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}

	var sent map[string]any
	if err := json.Unmarshal(upstreamBody, &sent); err != nil {
		t.Fatalf("上游收到的不是合法 JSON: %v\n%s", err, upstreamBody)
	}
	msgs, _ := sent["messages"].([]any)

	// 找出 role=tool 且 ToolCallIDable 对应 toolu_img 的 message。
	var toolContent string
	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg["role"] != "tool" {
			continue
		}
		if tcID, _ := msg["tool_call_id"].(string); tcID == "toolu_img" {
			if s, ok := msg["content"].(string); ok {
				toolContent = s
			}
			break
		}
	}
	if strings.TrimSpace(toolContent) == "" {
		t.Errorf("image-only tool_result 被吞成空 tool message，上游应至少收到可读占位:\n%s", upstreamBody)
	}
}

// TestClaudeMaxTokensZeroNotSentUpstream 覆盖"我们发出的请求让上游 400"这一类：
// max_tokens:0 是 Claude 的合法预热语义，但 OpenAI 系上游要求 >=1。
func TestClaudeMaxTokensZeroNotSentUpstream(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, true, &upstreamBody)

	rec := postClaudeMessages(t, `{"model":"test-alias","max_tokens":0,"messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	if bodyHasField(upstreamBody, "max_tokens") {
		t.Errorf("max_tokens:0 被发给上游，会导致 400: %s", upstreamBody)
	}
}

// TestCountTokensEndpoint 验证 count_tokens 返回 200 而不是 404。
func TestCountTokensEndpoint(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, false, &upstreamBody)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens",
		strings.NewReader(`{"model":"test-alias","messages":[{"role":"user","content":"数一数这段文字有多少 token"}]}`))
	rec := httptest.NewRecorder()
	anthropicCountTokensHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		InputTokens int `json:"input_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if resp.InputTokens < 1 {
		t.Errorf("input_tokens 应 >=1: %d", resp.InputTokens)
	}
}

// TestClaudeCompatDisabledFallsBackToOldBehaviour 验证回退开关：claude_compat 两层全关 +
// CPA 全关时，上游 body 回到改造前的形态（不降级、无 [error] 前缀），响应也不再补 signature。
// 这是出问题时的逃生门，必须真的能逃。
func TestClaudeCompatDisabledFallsBackToOldBehaviour(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, false, &upstreamBody)

	off := false
	configMu.Lock()
	claudeCompatCfg = ClaudeCompatConfig{InboundNormalize: &off, OutboundEnrich: &off}
	configMu.Unlock()

	rec := postClaudeMessages(t, richClaudeRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", rec.Code, rec.Body.String())
	}

	flat := string(upstreamBody)
	if strings.Contains(flat, "第三条 必须重试") {
		t.Errorf("开关关闭后 document 仍被降级注入:\n%s", flat)
	}
	if strings.Contains(flat, "[error]") {
		t.Errorf("开关关闭后仍写入 is_error 前缀:\n%s", flat)
	}

	var resp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &resp)
	blocks, _ := resp["content"].([]any)
	for _, b := range blocks {
		block, _ := b.(map[string]any)
		if block["type"] != "thinking" {
			continue
		}
		if sig, _ := block["signature"].(string); sig != "" {
			t.Errorf("开关关闭后仍签发 signature: %q", sig)
		}
	}
}

// TestUnsupportedBlocksNeverCause400 是这轮改造的底线：任何本网关无法表达的结构都只降级，
// 绝不回 400。
func TestUnsupportedBlocksNeverCause400(t *testing.T) {
	var upstreamBody []byte
	withFakeChatUpstream(t, true, &upstreamBody)

	weird := `{
		"model":"test-alias","max_tokens":100,
		"messages":[{"role":"user","content":[
			{"type":"some_future_block","payload":{"deep":{"nested":true}}},
			{"type":"container_upload","file_id":"f1"},
			{"type":"redacted_thinking","data":"xxx"},
			{"type":"text","text":"还在吗"}
		]}]
	}`
	rec := postClaudeMessages(t, weird)
	if rec.Code != http.StatusOK {
		t.Fatalf("未知块导致非 200：%d %s", rec.Code, rec.Body.String())
	}
	flat := string(upstreamBody)
	if !strings.Contains(flat, "some_future_block") {
		t.Errorf("未知块内容被静默丢弃:\n%s", flat)
	}
	if !strings.Contains(flat, "还在吗") {
		t.Errorf("正常文本丢失:\n%s", flat)
	}
}
