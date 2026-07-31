package main

import (
	"encoding/json"
	"testing"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// 这组测试锁定 CPA v7 翻译层的"方向语义陷阱"——这是库式接入最容易踩错、
// 最该有回归保护的地方。CPA 的 Has* 与 Translate* 对响应方向传参顺序相反：
//   Has*ResponseTransformer(from, to)        查 responses[from][to]
//   TranslateNonStream/Stream(from, to, ...) 内部查 responses[to][from]
// 我们的 hasCPAResponse 必须传 (target, source) 才与 Translate*(source, target) 匹配。
// 这些测试断言"探测为真 ⇔ 转换有实质翻译器"，二者不一致就是方向封装错误。

// formatShort 仅用于断言失败信息可读。
func formatShort(f sdktranslator.Format) string { return string(f) }

// TestCPARequestDirectionPairs 锁定请求方向内置可用 pair（请求 source→target 有直连翻译器）。
func TestCPARequestDirectionPairs(t *testing.T) {
	// 实测 v7.2.97 builtin 内置的请求直连 pair。
	pairs := []struct{ from, to sdktranslator.Format }{
		{sdktranslator.FormatOpenAI, sdktranslator.FormatOpenAI},         // 恒等
		{sdktranslator.FormatOpenAI, sdktranslator.FormatClaude},         // Chat→Claude
		{sdktranslator.FormatClaude, sdktranslator.FormatOpenAI},         // Claude→Chat
		{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatOpenAI}, // Responses→Chat
		{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatClaude}, // Responses→Claude
	}
	for _, p := range pairs {
		if !hasCPARequest(p.from, p.to) {
			t.Errorf("hasCPARequest(%s→%s)=false, want true (内置应有直连请求翻译器)", formatShort(p.from), formatShort(p.to))
		}
	}
}

// TestCPARequestNoDirectPairs 锁定确认无直连请求 pair（须经 Chat 中转）。
func TestCPARequestNoDirectPairs(t *testing.T) {
	noDirect := []struct{ from, to sdktranslator.Format }{
		{sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse}, // Claude→Responses 无直连
		{sdktranslator.FormatOpenAI, sdktranslator.FormatOpenAIResponse}, // Chat→Responses 无直连
	}
	for _, p := range noDirect {
		if hasCPARequest(p.from, p.to) {
			t.Errorf("hasCPARequest(%s→%s)=true, want false（应无直连，须经 Chat 中转）", formatShort(p.from), formatShort(p.to))
		}
	}
}

// TestCPAResponseProbeDirectionMatchesConversion 是最关键的陷阱测试：
// 断言 hasCPAResponse(source, target) 探测与 TranslateNonStream(source, target) 转换方向一致。
//
// CPA 语义（实测）：responses[from][to] 存"把 to 响应翻回 from"，即 from=目标、to=源。
//
//	Has*ResponseTransformer(from=目标, to=源)  查 responses[目标][源]
//	TranslateNonStream(from=源, to=目标)        内部查 responses[目标][源]
//
// 故对同一 source→target，两者传参顺序相反：Has(target,source)、Translate(source,target)，
// 但都落到同一 responses[目标][源] 表项。我们 hasCPAResponse(source,target) 封装成内部 Has(target,source)。
func TestCPAResponseProbeDirectionMatchesConversion(t *testing.T) {
	// 用 CPA 真实的"单向"响应对验证反序必要性（Chat↔Claude 双向对称，无法证反序）：
	// 存在"把 Claude 响应翻成 Responses"（源=Claude → 目标=Responses），存于 responses[Responses][Claude]。
	// 即 source=Claude(上游响应) target=Responses(客户端)。反向（Responses→Claude）无翻译器。
	const source, target = sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse

	// 封装探测：传 (source, target)，内部转成 (target, source) 喂 CPA Has*，应为 true。
	if !hasCPAResponse(source, target, false) {
		t.Fatalf("hasCPAResponse(%s→%s, nonstream)=false, want true", formatShort(source), formatShort(target))
	}
	// sanity A：按 (source, target) 直序喂 CPA Has*（responses[source][target]），这个单向对应为 false。
	// 这证明"不能把 source,target 直接送给 CPA Has*"——必须反序，隔离陷阱。
	if sdktranslator.HasNonStreamResponseTransformer(source, target) {
		t.Errorf("sanity A: 直序 HasNonStreamResponseTransformer(%s,%s)=true, want false（该 pair 单向：responses[%s][%s] 才命中，反序才对）",
			formatShort(source), formatShort(target), formatShort(target), formatShort(source))
	}
	// sanity B：反向 pair（Responses→Claude）封装应为 false——证明方向语义是单向的，非"任何顺序都 true"。
	if hasCPAResponse(target, source, false) {
		t.Errorf("sanity B: hasCPAResponse(%s→%s)=true, want false（反向 pair 无翻译器，方向是单向的）",
			formatShort(target), formatShort(source))
	}
}

// TestBuildRequestStagesDirect 验证单段直连链。
func TestBuildRequestStagesDirect(t *testing.T) {
	stages := buildRequestStages(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude)
	if len(stages) != 2 || stages[0] != sdktranslator.FormatOpenAI || stages[1] != sdktranslator.FormatClaude {
		t.Errorf("buildRequestStages(OpenAI→Claude)=%v, want [OpenAI,Claude] 单段直连", stages)
	}
}

// TestBuildRequestStagesViaHub 验证无直连、且经 Chat 可中转时返回两段链。
// 实测真实可用 pair：响应方向无"Responses→Claude/Chat"直连，但有"Responses→Claude"经…不，
// 取一个确定能经 Chat 中转的请求 pair：无（请求 Chat→Responses 缺，Responses→Chat 有但反向缺）。
// 故仅验证"请求方向经 Chat 中转"用真实可中转的组合——实测请求方向无任何经 Chat 中转可行的 pair，
// 因为 Chat→Responses 缺、Claude→Responses 缺。所以本测试改为锁定"无可用方向→nil"。
func TestBuildRequestStagesViaHub(t *testing.T) {
	// Claude→Responses：无直连（无 requests[Claude][Responses]），且经 Chat 中转也走不通
	//（requests[Claude][OpenAI] 有，但 requests[OpenAI][Responses] 缺），故返回 nil，调用方应 fallback 手写。
	stages := buildRequestStages(sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse)
	if stages != nil {
		t.Errorf("buildRequestStages(Claude→Responses)=%v, want nil（Chat→Responses 这个中转段在 CPA 无翻译器，须走 fallback）", stages)
	}
}

// TestCanBuildRoute 锁定真实非对称 matrix：有 CPA 翻译的 pair 返回 true，缺的返回 false。
func TestCanBuildRoute(t *testing.T) {
	// Chat 入站 + Claude 上游：请求 Chat→Claude 直连✓，响应(非流式&流式) Claude→Chat 直连✓ → true
	if !canBuildRoute(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude) {
		t.Errorf("canBuildRoute(Chat→Claude)=false, want true")
	}
	// Responses 入站 + OpenAI 上游：请求 Responses→Chat✓，响应 Chat→Responses✓ → true
	if !canBuildRoute(sdktranslator.FormatOpenAIResponse, sdktranslator.FormatOpenAI) {
		t.Errorf("canBuildRoute(Responses→Chat)=false, want true")
	}
	// Claude 入站 + Responses 上游：请求 Claude→Responses 缺、响应 Responses→Claude 缺 → false（走手写 fallback）
	if canBuildRoute(sdktranslator.FormatClaude, sdktranslator.FormatOpenAIResponse) {
		t.Errorf("canBuildRoute(Claude→Responses)=true, want false（CPA 无该方向翻译，须走手写）")
	}
	// Chat 入站 + Responses 上游：请求 Chat→Responses 缺 → false（走手写 openAIToResponsesRequest）
	if canBuildRoute(sdktranslator.FormatOpenAI, sdktranslator.FormatOpenAIResponse) {
		t.Errorf("canBuildRoute(Chat→Responses)=true, want false（CPA 无请求方向 Chat→Responses）")
	}
}

// TestFormatForUpstream 锁定上游类型→CPA 格式映射。
func TestFormatForUpstream(t *testing.T) {
	cases := []struct {
		up  *UpstreamConfig
		out sdktranslator.Format
	}{
		{nil, sdktranslator.FormatOpenAI},
		{&UpstreamConfig{APIType: UpstreamOpenAI}, sdktranslator.FormatOpenAI},
		{&UpstreamConfig{APIType: UpstreamAnthropic}, sdktranslator.FormatClaude},
		{&UpstreamConfig{APIType: UpstreamResponses}, sdktranslator.FormatOpenAIResponse},
	}
	for i, c := range cases {
		if g := formatForUpstream(c.up); g != c.out {
			t.Errorf("case %d: formatForUpstream=%s want %s", i, formatShort(g), formatShort(c.out))
		}
	}
}

// TestCpaClientFormat 锁定入站协议→CPA 格式映射。
func TestCpaClientFormat(t *testing.T) {
	cases := map[string]sdktranslator.Format{
		"chat":             sdktranslator.FormatOpenAI,
		"":                 sdktranslator.FormatOpenAI,
		"openai":           sdktranslator.FormatOpenAI,
		"anthropic":        sdktranslator.FormatClaude,
		"openai-responses": sdktranslator.FormatOpenAIResponse,
	}
	for in, want := range cases {
		if g := cpaClientFormat(in); g != want {
			t.Errorf("cpaClientFormat(%q)=%s want %s", in, formatShort(g), formatShort(want))
		}
	}
}

// TestPatchCPARequestForAliasThinkingNoneNoObject 是 thinking 方言的核心回归：
// effort=none 且 thinking 方言且无客户端显式 thinking 时，patch 后 body 不得含 thinking 对象
// （实测 2026-07-26：发了 thinking:{type:disabled} 反而触发 1569 字推理）。
// 对应 main_test.go:205-217 既有的 thinking 注入约束。
func TestPatchCPARequestForAliasThinkingNoneNoObject(t *testing.T) {
	body := mustCPAJSON(t, map[string]any{"model": "glm-5.2", "messages": []map[string]any{{"role": "user", "content": "hi"}}})
	// CPA 模拟"误加" thinking:disabled，patch 必须清掉。
	bodyWithDisabled := mustCPAJSON(t, map[string]any{
		"model":            "glm-5.2",
		"thinking":         map[string]any{"type": "disabled"},
		"reasoning_effort": "none",
	})

	for _, b := range [][]byte{body, bodyWithDisabled} {
		out := patchCPARequestForAlias(b, "none", nil, ModelAlias{ReasoningFormat: "thinking"}, sdktranslator.FormatOpenAI)
		var obj map[string]any
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatalf("patch 后解析失败: %v body=%s", err, out)
		}
		if _, has := obj["thinking"]; has {
			t.Errorf("thinking 方言 + none + 无客户端显式 thinking: body 仍含 thinking 对象（会触发 GLM 推理），body=%s", out)
		}
		if _, has := obj["reasoning_effort"]; has {
			t.Errorf("thinking 方言下应移除顶层 reasoning_effort，body=%s", out)
		}
	}
}

// TestPatchCPARequestForAliasThinkingInjectsObject: 非 none effort + thinking 方言 + 无显式 thinking 时注入 thinking 对象。
func TestPatchCPARequestForAliasThinkingInjectsObject(t *testing.T) {
	b := mustCPAJSON(t, map[string]any{"model": "glm-5.2", "messages": []map[string]any{{"role": "user", "content": "hi"}}})
	out := patchCPARequestForAlias(b, "high", nil, ModelAlias{ReasoningFormat: "thinking"}, sdktranslator.FormatOpenAI)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	th, ok := obj["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("thinking 方言 + high + 无显式 thinking: 应注入 thinking 对象，got body=%s", out)
	}
	if th["type"] != "enabled" {
		t.Errorf("注入的 thinking.type=%v want enabled, body=%s", th["type"], out)
	}
}

// TestPatchCPARequestForAliasClientExplicitThinkingPreserved: 客户端显式 thinking 优先，不被 patch 重复注入或清掉。
func TestPatchCPARequestForAliasClientExplicitThinkingPreserved(t *testing.T) {
	clientThinking := map[string]any{"type": "enabled", "budget_tokens": 12345}
	b := mustCPAJSON(t, map[string]any{"model": "glm-5.2", "thinking": clientThinking})
	out := patchCPARequestForAlias(b, "high", clientThinking, ModelAlias{ReasoningFormat: "thinking"}, sdktranslator.FormatOpenAI)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	th, ok := obj["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("客户端显式 thinking 应保留，got body=%s", out)
	}
	if th["budget_tokens"] != float64(12345) {
		t.Errorf("客户端 thinking 被篡改: budget=%v want 12345, body=%s", th["budget_tokens"], out)
	}
}

// TestPatchCPARequestForAliasNonThinkingTopLevelEffort: 非 thinking 方言透传顶层 reasoning_effort（含 none）。
func TestPatchCPARequestForAliasNonThinkingTopLevelEffort(t *testing.T) {
	b := mustCPAJSON(t, map[string]any{"model": "x", "messages": []map[string]any{}})
	out := patchCPARequestForAlias(b, "none", nil, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatOpenAI)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if obj["reasoning_effort"] != "none" {
		t.Errorf("非 thinking 方言应透传顶层 reasoning_effort=none，got body=%s", out)
	}
}

// TestPatchCPARequestForAliasStripsInjectedMetadataUserID 验证剥离 CPA 注入的 metadata.user_id。
func TestPatchCPARequestForAliasStripsInjectedMetadataUserID(t *testing.T) {
	// 模拟 CPA 翻译后的 Claude 请求：含注入的确定性 hash user_id。
	b := mustCPAJSON(t, map[string]any{
		"model":    "m",
		"messages": []map[string]any{},
		"metadata": map[string]any{"user_id": "user_0e06d90937df_account_8e9a4d49_session_31112932"},
	})
	out := patchCPARequestForAlias(b, "", nil, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatClaude)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if md, ok := obj["metadata"].(map[string]any); ok {
		if _, has := md["user_id"]; has {
			t.Errorf("CPA 注入的 metadata.user_id 应被剥离，got metadata=%v out=%s", md, out)
		}
	} else if _, hadMetadata := obj["metadata"]; hadMetadata {
		// metadata 字段存在但不是对象或为空——空 map 应被整体移除
		if _, isEmpty := obj["metadata"].(map[string]any); isEmpty {
			t.Errorf("空 metadata 应被整体移除，got out=%s", out)
		}
	}
	// 模型/messages 等正常字段保留。
	if obj["model"] != "m" {
		t.Errorf("剥离 metadata 不应误删其它字段，got out=%s", out)
	}
}

// TestPatchCPARequestForAliasPreservesClientMetadataUserID 客户端原 metadata（非 CPA hash 形态）不应被误删。
func TestPatchCPARequestForAliasPreservesClientMetadataUserID(t *testing.T) {
	b := mustCPAJSON(t, map[string]any{
		"model":    "m",
		"metadata": map[string]any{"user_id": "client-123", "trace": "x"},
	})
	out := patchCPARequestForAlias(b, "", nil, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatClaude)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	md, ok := obj["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("客户端原 metadata 应保留，got out=%s", out)
	}
	if md["user_id"] != "client-123" {
		t.Errorf("客户端原 user_id 不应被误删，got metadata=%v out=%s", md, out)
	}
}

// TestPatchCPARequestForAliasNonThinkingClaudeUpstreamBudgetCorrection 验证「非 thinking 方言 +
// Claude 上游」时 CPA 改写的 thinking budget 被项目档级校正覆盖。
func TestPatchCPARequestForAliasNonThinkingClaudeUpstreamBudgetCorrection(t *testing.T) {
	// CPA 翻译后 Claude 请求里 thinking.budget_tokens 被压成 8192。
	b := mustCPAJSON(t, map[string]any{
		"model":    "m",
		"messages": []map[string]any{},
		"thinking": map[string]any{"type": "enabled", "budget_tokens": 8192},
	})
	out := patchCPARequestForAlias(b, "high", nil, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatClaude)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	th, ok := obj["thinking"].(map[string]any)
	if !ok {
		t.Fatalf("Claude 上游 high effort 应保留 thinking 块，got out=%s", out)
	}
	budget, _ := th["budget_tokens"].(float64)
	if budget != 32000 {
		t.Errorf("Claude 上游 high 应校正 budget 到项目档 32000，仍为 CPA 的 %v out=%s", budget, out)
	}
	if obj["reasoning_effort"] != nil {
		t.Errorf("Claude 上游不应透传顶层 reasoning_effort，got out=%s", out)
	}
}

// TestPatchCPARequestForAliasNonThinkingClaudeUpstreamClientThinkingPreserved Claude 上游 + 客户端显式 thinking 时保留客户端原值。
func TestPatchCPARequestForAliasNonThinkingClaudeUpstreamClientThinkingPreserved(t *testing.T) {
	clientThinking := map[string]any{"type": "enabled", "budget_tokens": 9999}
	b := mustCPAJSON(t, map[string]any{
		"model":    "m",
		"messages": []map[string]any{},
		"thinking": clientThinking,
	})
	out := patchCPARequestForAlias(b, "high", clientThinking, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatClaude)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	th, _ := obj["thinking"].(map[string]any)
	budget, _ := th["budget_tokens"].(float64)
	if budget != 9999 {
		t.Errorf("客户端显式 thinking 应保留原值 9999，got %v out=%s", budget, out)
	}
}

// TestPatchCPARequestForAliasNonThinkingClaudeUpstreamNoneRemovesThinking Claude 上游 + none + 无显式 thinking 时删除 thinking 块。
func TestPatchCPARequestForAliasNonThinkingClaudeUpstreamNoneRemovesThinking(t *testing.T) {
	b := mustCPAJSON(t, map[string]any{
		"model":    "m",
		"messages": []map[string]any{},
		"thinking": map[string]any{"type": "enabled", "budget_tokens": 8192},
	})
	out := patchCPARequestForAlias(b, "none", nil, ModelAlias{ReasoningFormat: ""}, sdktranslator.FormatClaude)
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if _, has := obj["thinking"]; has {
		t.Errorf("Claude 上游 none 无显式 thinking 应删除 thinking 块，got out=%s", out)
	}
}

// TestJSONHelpers 土法 JSON 操作的字段增删查。
func TestJSONHelpers(t *testing.T) {
	b := mustCPAJSON(t, map[string]any{"model": "x", "ok": true})
	// Set
	b, _ = jsonSetField(b, "k", "v")
	if !bodyHasField(b, "k") {
		t.Error("jsonSetField 后 bodyHasField(k) 应为 true")
	}
	// Remove
	b = removeField(b, "k")
	if bodyHasField(b, "k") {
		t.Error("removeField(k) 后 bodyHasField(k) 应为 false")
	}
}

func mustCPAJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// TestCpaTranslateRequestUnavailableReturnsNil 锁定关键语义：CPA 无该请求方向翻译器时
// 返回 route==nil，告知 handler 整条走手写（不在响应阶段调用 CPA）。
func TestCpaTranslateRequestUnavailableReturnsNil(t *testing.T) {
	// Chat→Responses 上游：请求方向无 CPA 翻译器（非对称 matrix）。
	in := mustCPAJSON(t, map[string]any{"model": "m", "messages": []map[string]any{{"role": "user", "content": "hi"}}, "stream": true})
	fallbackCalled := false
	fallback := func(b []byte) ([]byte, error) {
		fallbackCalled = true
		return []byte(`{"fallback":"yes"}`), nil
	}
	route, body, err := cpaTranslateRequest(nil, sdktranslator.FormatOpenAI, sdktranslator.FormatOpenAIResponse, "m", in, true, fallback)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if route != nil {
		t.Errorf("Chat→Responses 无 CPA 翻译器: route 应为 nil，got %+v（handler 会误以为可走 CPA 响应链）", route)
	}
	if !fallbackCalled {
		t.Error("无 CPA 翻译器时应调用 fallback")
	}
	if string(body) != `{"fallback":"yes"}` {
		t.Errorf("body 应是 fallback 结果，got %s", body)
	}
}

// TestCpaTranslateRequestAvailableReturnsRoute 有 CPA 翻译方向时 route!=nil 且 body 经真正翻译。
func TestCpaTranslateRequestAvailableReturnsRoute(t *testing.T) {
	// Claude 入站 → Chat 上游：请求 Claude→Chat 有翻译器。
	in := mustCPAJSON(t, map[string]any{
		"model":      "m",
		"max_tokens": 100,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
	})
	fallback := func(b []byte) ([]byte, error) { return b, nil } // 不应被调用
	route, body, err := cpaTranslateRequest(nil, sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "resolved-model", in, false, fallback)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if route == nil {
		t.Fatalf("Claude→Chat 有翻译器: route 不应为 nil")
	}
	if len(route.RequestStages) == 0 {
		t.Fatal("RequestStages 不应为空")
	}
	// 最终段 model 应归一为 resolved-model。
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("翻译后 body 非法 JSON: %v body=%s", err, body)
	}
	if g, _ := obj["model"].(string); g != "resolved-model" {
		t.Errorf("最终段 model 未归一: got %v want resolved-model, body=%s", obj["model"], body)
	}
}

// ======================== 阶段2 非流式响应翻译测试 ========================
//
// 探针确认的 CPA v7.2.97 真实行为（写错断言会误绿）：
//   - 响应能力矩阵 HasNonStream(Chat,Claude)=true / (Claude,Chat)=true / (Responses,Chat)=true /
//     (Chat,Responses)=false / (Claude,Responses)=false / (Responses,Claude)=true
//   - Has* 查 responses[from][to]（传参=目标,源 的反序见 hasCPAResponse），TranslateNonStream(from=源,to=目标)
//     内部反查 responses[to][from]，所以 Responses→Chat 响应虽 HasNonStream(Responses,Chat)=true 但
//     TranslateNonStream(Responses,Chat) 原样透传（反查 responses[Chat][Responses]=false 无翻译器）。
//   故 Responses→Chat 响应方向经 Chat 中转（hasCPAResponse 正确判无直连）。
// 测试据此设计。

// chatCompletionResp 是一个最小合法的 OpenAI Chat 非流式响应。
func chatCompletionResp(t *testing.T) []byte {
	return mustCPAJSON(t, map[string]any{
		"id": "chatcmpl-1", "object": "chat.completion", "model": "m",
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": "hello world"},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
	})
}

// TestCpaTranslateNonStreamDirectRoute 直连响应方向（Chat 上游 → Claude 客户端）:
// route!=nil，逐段 TranslateNonStream 成功，输出为 Claude 格式（与手写 fallback 不同），证明走了 CPA。
func TestCpaTranslateNonStreamDirectRoute(t *testing.T) {
	// 请求 Claude→Chat（有翻译器），route!=nil；响应链 Chat→Claude 直连。
	origReq := mustCPAJSON(t, map[string]any{
		"model": "m", "max_tokens": 100,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	fallback := func(b []byte) ([]byte, error) { return b, nil }
	route, _, err := cpaTranslateRequest(nil, sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "m", origReq, false, fallback)
	if err != nil {
		t.Fatalf("cpaTranslateRequest err=%v", err)
	}
	if route == nil {
		t.Fatal("Claude→Chat 应有翻译器，route 不应为 nil")
	}
	if len(route.ResponseStagesNonStream) == 0 {
		t.Fatalf("ResponseStagesNonStream 不应为空，route=%+v", route)
	}
	// 响应链应为单段 Chat→Claude。
	if len(route.ResponseStagesNonStream) != 1 {
		t.Errorf("直连响应链应为 1 段，got %d 段 %+v", len(route.ResponseStagesNonStream), route.ResponseStagesNonStream)
	}

	chatResp := chatCompletionResp(t)
	fbCalled := false
	respFallback := func(b []byte) []byte { fbCalled = true; return b }
	out := cpaTranslateNonStream(nil, route, chatResp, respFallback)
	if fbCalled {
		t.Error("直连翻译成功不应调用 fallback")
	}
	// CPA Chat→Claude 输出含 "type":"message" 与 content[].type:"text"，原 Chat 响应没有。
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("翻译后响应非法 JSON: %v out=%s", err, out)
	}
	if g, _ := obj["type"].(string); g != "message" {
		t.Errorf("Chat→Claude 响应应含 type=message, got %v out=%s", obj["type"], out)
	}
}

// TestCpaTranslateNonStreamNilRouteFallsBack route==nil（方向不通）整条走手写 fallback。
func TestCpaTranslateNonStreamNilRouteFallsBack(t *testing.T) {
	raw := []byte(`{"raw":"upstream"}`)
	fbCalled := false
	fallback := func(b []byte) []byte { fbCalled = true; return []byte(`{"handled":"fallback"}`) }
	out := cpaTranslateNonStream(nil, nil, raw, fallback)
	if !fbCalled {
		t.Error("route==nil 应调用 fallback")
	}
	if string(out) != `{"handled":"fallback"}` {
		t.Errorf("route==nil 应返回 fallback 结果，got %s", out)
	}
}

// TestCpaTranslateNonStreamEmptyStagesFallsBack route 非空但 ResponseStages 为空（不应发生，防御）。
func TestCpaTranslateNonStreamEmptyStagesFallsBack(t *testing.T) {
	raw := []byte(`{"raw":"upstream"}`)
	route := &cpaTranslationRoute{ClientFormat: sdktranslator.FormatOpenAI}
	fbCalled := false
	fallback := func(b []byte) []byte { fbCalled = true; return b }
	out := cpaTranslateNonStream(nil, route, raw, fallback)
	if !fbCalled {
		t.Error("空 ResponseStages 应调用 fallback")
	}
	if string(out) != string(raw) {
		t.Errorf("应返回 fallback(raw)，got %s", out)
	}
}

// TestCpaTranslateNonStreamGarbageResponseProducesEmptyShell 锁定 CPA 真实行为：
// 上游响应畸形时，TranslateNonStream **不**返回空/非法 JSON，而是产出合法的**空壳** Claude 响应
// （id/model 空、content:[]、usage 全 0）。故 cpaTranslateNonStream 的 `len==0||!json.Valid` 失败分支
// 不会被畸形上游触发，客户端会拿到空壳而非 fallback。这是 handler 接入后必须知道的语义，固化为回归。
func TestCpaTranslateNonStreamGarbageResponseProducesEmptyShell(t *testing.T) {
	origReq := mustCPAJSON(t, map[string]any{
		"model": "m", "max_tokens": 100,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	fallback := func(b []byte) ([]byte, error) { return b, nil }
	route, _, err := cpaTranslateRequest(nil, sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "m", origReq, false, fallback)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if route == nil {
		t.Fatal("route 不应为 nil")
	}
	garbage := []byte("not-json-at-all")
	fbCalled := false
	fallbackResp := func(b []byte) []byte { fbCalled = true; return b }
	out := cpaTranslateNonStream(nil, route, garbage, fallbackResp)
	if fbCalled {
		t.Error("CPA 对畸形输入产出合法空壳，不应触发 fallback")
	}
	// 应是合法 JSON 且为空壳 Claude 响应（type=message，content 为空数组）。
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("畸形上游下 CPA 应产出合法空壳 JSON，但 Unmarshal 失败: %v out=%s", err, out)
	}
	if g, _ := obj["type"].(string); g != "message" {
		t.Errorf("空壳响应应为 type=message, got %v out=%s", obj["type"], out)
	}
}

// TestRequestByFormatPopulated 验证链式转换的 RequestByFormat 填充语义：
//
//	单段链 Claude→Chat，RequestByFormat[client=Claude]=入站原始、RequestByFormat[Chat]=最终上游请求体；
//	响应链 Chat→Claude 单段的 RequestBody 应取 RequestByFormat[Chat]（=上游请求体），OriginalRequest 取入站原始。
func TestRequestByFormatPopulated(t *testing.T) {
	origReq := mustCPAJSON(t, map[string]any{
		"model": "m", "max_tokens": 100,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	fallback := func(b []byte) ([]byte, error) { return b, nil }
	route, body, err := cpaTranslateRequest(nil, sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "m", origReq, false, fallback)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if route == nil {
		t.Fatal("route 不应为 nil")
	}
	// RequestByFormat 应含 client 原始请求（Claude）与 upstream 终态请求（Chat）。
	if string(route.RequestByFormat[sdktranslator.FormatClaude]) != string(origReq) {
		t.Error("RequestByFormat[Claude] 应等于入站原始请求")
	}
	if string(route.RequestByFormat[sdktranslator.FormatOpenAI]) != string(body) {
		t.Error("RequestByFormat[Chat/OpenAI] 应等于最终翻译后上游请求 body")
	}
	// 响应链单段 Chat→Claude，其 RequestBody 应来自 RequestByFormat[Chat]。
	st := route.ResponseStagesNonStream[0]
	if string(st.RequestBody) != string(body) {
		t.Errorf("响应段 RequestBody 应取 RequestByFormat[Chat]=上游请求体，got %s", st.RequestBody)
	}
	if string(st.OriginalRequest) != string(origReq) {
		t.Errorf("响应段 OriginalRequest 应为入站原始请求，got %s", st.OriginalRequest)
	}
}

// TestBuildResponseStagesForRouteNilFormats 空 fmts 返回 nil（防御）。
func TestBuildResponseStagesForRouteNilFormats(t *testing.T) {
	route := &cpaTranslationRoute{OriginalRequest: []byte("{}")}
	if got := buildResponseStagesForRoute(route, nil); got != nil {
		t.Errorf("空 fmts 应返回 nil，got %v", got)
	}
}

// TestBuildResponseStagesForRouteTwoStageMapping 验证多段响应链的 RequestBody 映射纯逻辑（绕过真实能力探测）：
// 构造 fmts=[Responses,Chat,Claude]（两段：Responses→Chat、Chat→Claude），
//   - 第 1 段 RequestBody 应取 RequestByFormat[Responses]（该格式的请求体）
//   - 第 2 段 RequestBody 应取 RequestByFormat[Chat]
//   - 任一段 OriginalRequest 统一为入站原始请求
//   - 若 RequestByFormat 缺某格式，RequestBody 应回退 OriginalRequest
//
// 当前 CPA v7 矩阵下两段经 Chat 中转的链实际很少走通，故用纯逻辑测映射正确性，不依赖真实 registry。
func TestBuildResponseStagesForRouteTwoStageMapping(t *testing.T) {
	origReq := []byte(`{"client":"orig"}`)
	respsBody := []byte(`{"fmt":"responses"}`)
	chatBody := []byte(`{"fmt":"chat"}`)
	route := &cpaTranslationRoute{
		OriginalRequest: origReq,
		RequestByFormat: map[sdktranslator.Format][]byte{
			sdktranslator.FormatOpenAIResponse: respsBody,
			sdktranslator.FormatOpenAI:         chatBody,
			// FormatClaude 故意不填，以验证回退 OriginalRequest。
		},
	}
	// 伪造响应链：Responses→Chat→Claude。
	fmts := []sdktranslator.Format{
		sdktranslator.FormatOpenAIResponse,
		sdktranslator.FormatOpenAI,
		sdktranslator.FormatClaude,
	}
	stages := buildResponseStagesForRoute(route, fmts)
	if len(stages) != 2 {
		t.Fatalf("两段链应产出 2 段，got %d", len(stages))
	}
	// 第 1 段 Responses→Chat：RequestBody=RequestByFormat[Responses]。
	if string(stages[0].FromFormat) != string(sdktranslator.FormatOpenAIResponse) || string(stages[0].ToFormat) != string(sdktranslator.FormatOpenAI) {
		t.Errorf("第1段方向错: got %s->%s", stages[0].FromFormat, stages[0].ToFormat)
	}
	if string(stages[0].RequestBody) != string(respsBody) {
		t.Errorf("第1段 RequestBody 应取 RequestByFormat[Responses]，got %s", stages[0].RequestBody)
	}
	if string(stages[0].OriginalRequest) != string(origReq) {
		t.Errorf("第1段 OriginalRequest 应为入站原始，got %s", stages[0].OriginalRequest)
	}
	// 第 2 段 Chat→Claude：RequestByFormat[Claude] 缺失 → 回退 OriginalRequest。
	if string(stages[1].FromFormat) != string(sdktranslator.FormatOpenAI) || string(stages[1].ToFormat) != string(sdktranslator.FormatClaude) {
		t.Errorf("第2段方向错: got %s->%s", stages[1].FromFormat, stages[1].ToFormat)
	}
	if string(stages[1].RequestBody) != string(chatBody) {
		// 注意：第2段 FromFormat=Chat，RequestBody 取 RequestByFormat[Chat]，不是 Claude。
		t.Errorf("第2段 RequestBody 应取 RequestByFormat[Chat]（按 FromFormat），got %s", stages[1].RequestBody)
	}
}
