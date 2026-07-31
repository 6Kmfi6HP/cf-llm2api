package main

import (
	"context"
	"encoding/json"
	"strings"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin" // 注册内置翻译器（init 副作用）
)

// ======================== CPA 翻译层胶水（库式接入） ========================
//
// 本文件只负责"协议翻译主干"：把三入站协议（OpenAI Chat / Anthropic / OpenAI Responses）
// 的请求/响应，通过 CPA sdk/translator 互译后交给上游 transport 层。它不承担：
//   - alias/config/admin/统计/错误策略（仍在 main.go 业务层）
//   - 上游 HTTP 实际调用
//
// 关键约定（CPA v7 实测，写错会让探测/转换方向不匹配而静默退化）：
//   - RequestTransform:   Register(from,to,requestFn) 存 requests[from][to]，请求 from→to 翻译。
//   - ResponseTransform:  存 responses[from][to]，语义是"把 to 格式的响应翻译回 from 格式"。
//   - TranslateRequest(from,to,...)            查 requests[from][to] —— 传参 (源,目标)，方向一致。
//   - TranslateNonStream/Stream(from,to,...)   查 responses[to][from] —— 传参 (源,目标)，内部反查。
//   - HasRequestTransformer(from,to)           查 requests[from][to] —— 传参 (源,目标)。
//   - Has*ResponseTransformer(from,to)          查 responses[from][to] —— 传参 (目标,源) !!
//
// 因此：对同一对 (源,目标)，Has*ResponseTransformer 探测与 Translate* 转换传参顺序相反。
// 本胶水层统一对外暴露 (源 source, 目标 target) 语义，内部各自适配，避免调用方踩坑。
//
// 内置可用方向矩阵（实测 v7.2.97 builtin）：
//   请求直连:  Chat→Chat(恒等) | Chat→Claude | Chat→Responses(无,经Chat中转间接) |
//              Claude→Chat | Claude→Responses(无直接,经Chat) |
//              Responses→Chat | Responses→Claude
//   响应直连:  Chat→Claude | Chat→Responses | Claude→Chat | Claude→Responses |
//              Responses→Chat(无直接,经Chat) | Responses→Claude(经Chat) | Chat→Chat(恒等)
// 无直连的 pair（Claude↔Responses 请求；Responses→Claude/Responses→Chat 响应）经 Chat 中转。

// cpaRequestsEnabled 报告 CPA 请求翻译是否在运行期灰度打开（Enabled 且 Requests）。
// handler 在请求方向据此决定走 CPA 还是手写 fallback。
func cpaRequestsEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return cpaTranslatorCfg.Enabled && cpaTranslatorCfg.Requests
}

// cpaNonStreamEnabled / cpaStreamEnabled 报告对应响应方向是否灰度打开。
func cpaNonStreamEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return cpaTranslatorCfg.Enabled && cpaTranslatorCfg.NonStreamResponses
}

func cpaStreamEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return cpaTranslatorCfg.Enabled && cpaTranslatorCfg.StreamResponses
}

// formatForUpstream 把 llm2api 上游类型映射到 CPA 格式常量。
func formatForUpstream(upstream *UpstreamConfig) sdktranslator.Format {
	if upstream == nil {
		return sdktranslator.FormatOpenAI
	}
	switch upstream.APIType {
	case UpstreamAnthropic:
		return sdktranslator.FormatClaude
	case UpstreamResponses:
		return sdktranslator.FormatOpenAIResponse
	case UpstreamOpenAI:
		return sdktranslator.FormatOpenAI
	default:
		return sdktranslator.FormatOpenAI
	}
}

// cpaClientFormat 把入站协议映射到 CPA 格式常量。
func cpaClientFormat(apiType string) sdktranslator.Format {
	switch apiType {
	case "anthropic":
		return sdktranslator.FormatClaude
	case "openai-responses":
		return sdktranslator.FormatOpenAIResponse
	default: // chat completions / 未知一律按 OpenAI Chat
		return sdktranslator.FormatOpenAI
	}
}

// ---- capability 探测（统一 (源,目标) 语义，内部适配 CPA 反序规则）----

// hasCPARequest 报告"把请求从 source 翻到 target"是否有内置翻译器。
func hasCPARequest(source, target sdktranslator.Format) bool {
	return sdktranslator.HasRequestTransformer(source, target)
}

// hasCPAResponse 报告"把上游 source 格式的响应翻回 client target 格式"是否有内置翻译器。
// 注意：CPA Has*ResponseTransformer(from,to) 查 responses[from][to]，
// 而实际转换 Translate*(source,target) 查 responses[target][source]，
// 故探测时须传 (target=client, source=upstream)，与转换传参顺序相反。
func hasCPAResponse(source sdktranslator.Format, target sdktranslator.Format, stream bool) bool {
	if stream {
		return sdktranslator.HasStreamResponseTransformer(target, source)
	}
	return sdktranslator.HasNonStreamResponseTransformer(target, source)
}

// cpaRouteStage 是链式转换的一段。
type cpaRouteStage struct {
	FromFormat      sdktranslator.Format // 本段源格式（请求方向=客户端→上游；响应方向=上游→客户端）
	ToFormat        sdktranslator.Format // 本段目标格式
	OriginalRequest []byte               // 本段对应的原始入站请求体（供响应翻译器）
	RequestBody     []byte               // 本段翻译后的请求体（供响应翻译器第二参数）
}

// cpaTranslationRoute 描述一次翻译的完整路径（可能单段直连，可能经 Chat 两段中转）。
type cpaTranslationRoute struct {
	ClientFormat    sdktranslator.Format // 入站客户端格式
	UpstreamFormat  sdktranslator.Format // 上游格式
	Model           string               // 已 resolve 的模型 ID
	OriginalRequest []byte               // 入站原始请求体，供响应翻译器使用

	// RequestStages: 请求方向（客户端→上游）的各段。直连为 1 段；无直连经 Chat 中转为 2 段。
	// 第 0 段 FromFormat==ClientFormat；最后一段 ToFormat==UpstreamFormat。
	RequestStages []cpaRouteStage

	// RequestByFormat: 每种格式对应的请求体，供响应翻译器按其源格式取 RequestBody。
	// 键为格式，值为该格式的请求 body：含 ClientFormat 原始入站请求、各中间段输出、UpstreamFormat 最终上游请求。
	RequestByFormat map[sdktranslator.Format][]byte

	// ResponseStages: 响应方向（上游→客户端）的各段。与请求方向相反但段数可能不同（直连 availability 不同）。
	// 每段的 OriginalRequest/RequestBody 在 buildResponseStagesForRoute 中按其 FromFormat 从 RequestByFormat 取。
	ResponseStagesNonStream []cpaRouteStage
	ResponseStagesStream    []cpaRouteStage
}

// formatChatHub 是请求/响应中转枢纽：无直连 pair 经它中转。
const formatChatHub = sdktranslator.FormatOpenAI

// buildRequestStages 构造请求方向链：source→target。无直连时经 Chat 中转。
func buildRequestStages(source, target sdktranslator.Format) []sdktranslator.Format {
	if source == target || hasCPARequest(source, target) {
		return []sdktranslator.Format{source, target}
	}
	// source→Chat→target
	if hasCPARequest(source, formatChatHub) && hasCPARequest(formatChatHub, target) {
		return []sdktranslator.Format{source, formatChatHub, target}
	}
	return nil // 无可用链
}

// buildResponseStages 构造响应方向链：upstream→client。无直连时经 Chat 中转。
func buildResponseStages(source, target sdktranslator.Format, stream bool) []sdktranslator.Format {
	if source == target || hasCPAResponse(source, target, stream) {
		return []sdktranslator.Format{source, target}
	}
	if hasCPAResponse(source, formatChatHub, stream) && hasCPAResponse(formatChatHub, target, stream) {
		return []sdktranslator.Format{source, formatChatHub, target}
	}
	return nil
}

// canBuildRoute 在实际转换前整条探测，避免流式中途切换。
func canBuildRoute(client, upstream sdktranslator.Format) bool {
	req := buildRequestStages(client, upstream)
	if req == nil {
		return false
	}
	if buildResponseStages(upstream, client, false) == nil {
		return false
	}
	if buildResponseStages(upstream, client, true) == nil {
		return false
	}
	return true
}

// ======================== 请求翻译（阶段1） ========================

// cpaTranslateRequest 把入站请求 body 翻成上游格式。
//   - client: 入站客户端格式；upstream: 上游格式；model: 已 resolve 模型 ID
//   - original: 入站原始请求 JSON（用于响应翻译器的 OriginalRequest）
//   - fallback: CPA 无可用翻译器或失败时回退的手写翻译，返回 (body,error)
//
// 返回 (route, translatedBody, error)。
//
//	route==nil 表示该 client→upstream 方向 CPA 无翻译器（非对称 matrix），translatedBody 是 fallback 结果，
//	handler 应就此走完整手写路径（既不 patch 也不在响应阶段调用 CPA）。route!=nil 表示 CPA 已翻译，后续可走 CPA 响应链。
//
// stream 模式提示给 CPA（部分翻译器据此调整字段）。
func cpaTranslateRequest(ctx context.Context, client, upstream sdktranslator.Format, model string, original []byte, stream bool, fallback func([]byte) ([]byte, error)) (*cpaTranslationRoute, []byte, error) {
	stages := buildRequestStages(client, upstream)
	if stages == nil {
		// CPA 无该请求方向翻译器：走手写 fallback，route==nil 告知 handler 整条走手写。
		body, err := fallback(original)
		if err != nil {
			return nil, nil, err
		}
		return nil, body, nil
	}

	body := original
	route := &cpaTranslationRoute{
		ClientFormat: client, UpstreamFormat: upstream, Model: model, OriginalRequest: original,
		RequestByFormat: map[sdktranslator.Format][]byte{client: original},
	}
	route.RequestStages = make([]cpaRouteStage, 0, len(stages)-1)
	for i := 0; i+1 < len(stages); i++ {
		from, to := stages[i], stages[i+1]
		if !hasCPARequest(from, to) {
			// 中转段缺失（理论上 buildRequestStages 已保证，双保险）：放弃 CPA，route==nil。
			body, err := fallback(original)
			if err != nil {
				return nil, nil, err
			}
			return nil, body, nil
		}
		translated := sdktranslator.TranslateRequest(from, to, model, body, stream)
		if len(translated) == 0 || !json.Valid(translated) {
			// TranslateRequest 缺失 transformer 时返回原文（仅改 model），不会变空/非法；
			// 这里只是双保险：理论上不会触发（TranslateRequest 缺失转换器只更新 model，不变空/非法）。
			// 若真触发则认为 CPA 此段失败，放弃整条 CPA 路径，route==nil。
			body, err := fallback(original)
			if err != nil {
				return nil, nil, err
			}
			return nil, body, nil
		}
		// 强制把最终段 model 归一为 resolve 后的模型 ID，防止 client 前缀泄漏上游。
		if i == len(stages)-2 {
			if m, err := jsonSetField(translated, "model", model); err == nil {
				translated = m
			}
		}
		route.RequestStages = append(route.RequestStages, cpaRouteStage{FromFormat: from, ToFormat: to, OriginalRequest: original, RequestBody: translated})
		// 每格式都留一份请求体，供响应链段按其 FromFormat 取 RequestBody。
		route.RequestByFormat[to] = translated
		body = translated
	}
	// 预建响应方向链（请求成功后再建，避免流式中途切换）：非流式 + 流式。
	route.ResponseStagesNonStream = buildResponseStagesForRoute(route, buildResponseStages(upstream, client, false))
	route.ResponseStagesStream = buildResponseStagesForRoute(route, buildResponseStages(upstream, client, true))
	return route, body, nil
}

// buildResponseStagesForRoute 把响应格式链展开成 cpaRouteStage，每段从 route.RequestByFormat
// 取对应源格式的请求体作 RequestBody、入站原始请求作 OriginalRequest。
func buildResponseStagesForRoute(route *cpaTranslationRoute, fmts []sdktranslator.Format) []cpaRouteStage {
	if len(fmts) == 0 {
		return nil
	}
	stages := make([]cpaRouteStage, 0, len(fmts)-1)
	for i := 0; i+1 < len(fmts); i++ {
		from, to := fmts[i], fmts[i+1] // from=源响应格式, to=目标客户端格式
		reqBody := route.RequestByFormat[from]
		if reqBody == nil {
			reqBody = route.OriginalRequest
		}
		stages = append(stages, cpaRouteStage{
			FromFormat:      from,
			ToFormat:        to,
			OriginalRequest: route.OriginalRequest,
			RequestBody:     reqBody,
		})
	}
	return stages
}

// ======================== 项目方言 patch（thinking 方言后置） ========================
//
// CPA 通用翻译器不会内置特定模型的推理方言：effort=none 时"不发 thinking 对象"
// （2026-07-26 实测：发了 thinking:{type:disabled} 反而触发 1569 字推理）。
// 这个 patch 在 CPA 翻译主干之后运行，依据 alias 把 thinking/reasoning_effort 校正到项目预期。
// 参考 convertRequest(main.go:2436-2493) 的原始逻辑，但作用于 CPA 输出的 body。

// patchCPARequestForAlias 对 CPA 翻译后的上游请求体应用项目侧 patch：
//   - 剥离 CPA 自动注入的 metadata.user_id（确定性 hash，非客户端原 metadata）
//   - reasoning/thinking 方言：按项目档级校正/注入 thinking、抑制/透传 reasoning_effort
//   - canonicalEffort: 入站规范化后的 canonical effort（none|low|medium|high|xhigh|max，""=无）
//   - clientThinking: 客户端显式传入的 thinking 对象（任意格式），已透传则不再覆盖
//   - alias: 模型别名（含 ReasoningFormat / AcceptedEfforts）
//
// 返回 patch 后的 body。
func patchCPARequestForAlias(body []byte, canonicalEffort string, clientThinking any, alias ModelAlias, upstreamFormat sdktranslator.Format) []byte {
	thinkingFormat := aliasReasoningFormatKey(alias) // "thinking" 或 ""

	// 0) 剥离 CPA 注入的 metadata.user_id（Chat→Claude / Responses→Claude 都会注入确定性
	//    hash user_<rand>_account_<rand>_session_<rand>，非客户端原 metadata）。
	body = stripCPAInjectedMetadataUserID(body)

	// 1) AcceptedEfforts 收敛（与 convertRequest 同序）。none 绕过全局 map。
	normalized := canonicalEffort
	if normalized != "" {
		normalized = normalizeReasoningEffortToAlias(normalized, alias.AcceptedEfforts)
	}

	body = removeTopLevelReasoningEffortIfThinking(body, thinkingFormat)

	// 2) thinking 方言（部分兼容上游只认 thinking 对象）
	if thinkingFormat == "thinking" {
		hasThinking := clientThinking != nil
		if !hasThinking && normalized != "" && normalized != "none" {
			// 注入 thinking{enabled,budget} 触发推理——同时覆盖 CPA 可能已写入的 budget=8192。
			injected := reasoningEffortToAnthropicThinking(normalized)
			if m, err := jsonSetField(body, "thinking", injected); err == nil {
				body = m
			}
		}
		// none 路径保持不发 thinking 对象（CPA 若加了 thinking:{type:disabled} 须清掉）
		if normalized == "none" && !hasThinking {
			if bodyHasField(body, "thinking") {
				body = removeField(body, "thinking")
			}
		}
		// thinking 方言下抑制顶层 reasoning_effort（已在上面移除）
		return body
	}

	// 3) 非 thinking 方言。Anthropic(Claude) 上游：CPA 仍会注入 thinking 块（budget 多半被压成 8192），
	//    无显式 clientThinking 时按项目档级重建覆盖；有显式 clientThinking 保留客户端原值不动。
	//    这是对「alias 不声明 thinking 方言但上游是 Anthropic」场景的 budget 校正。
	if upstreamFormat == sdktranslator.FormatClaude {
		hasThinking := clientThinking != nil
		if !hasThinking && normalized != "" && normalized != "none" {
			injected := reasoningEffortToAnthropicThinking(normalized)
			if m, err := jsonSetField(body, "thinking", injected); err == nil {
				body = m
			}
		}
		if normalized == "none" && !hasThinking && bodyHasField(body, "thinking") {
			body = removeField(body, "thinking")
		}
		// Claude 上游不透传顶层 reasoning_effort（CPA 已消费它生成 thinking）
		return body
	}

	// 4) 非 thinking 方言 + OpenAI/Responses 上游：透传 reasoning_effort（含 none，DeepSeek 等用 none|high|max）
	if normalized != "" {
		// 仅对 OpenAI Chat wire 写顶层 reasoning_effort；Responses 上游不该有顶层 reasoning_effort
		if upstreamFormat == sdktranslator.FormatOpenAI {
			if m, err := jsonSetField(body, "reasoning_effort", normalized); err == nil {
				body = m
			}
		}
	}
	return body
}

// patchClaudeUpstreamBody 把 Claude 原始入站请求里"上游本可接受、却在翻译中被吞掉"的字段补回上游 body，
// 并清掉会让上游直接 400 的取值。**CPA 路径与手写 fallback 路径都要调用**——两条链丢的字段高度重叠。
//
// 处理项（original = 入站 Claude body，body = 已翻译的上游 body）：
//   - stop_sequences → stop：手写 convertRequest 完全不带该字段；CPA 已翻则不覆盖。
//   - top_p：CPA ConvertClaudeRequestToOpenAI 里 temperature/top_p 是 `else if` 互斥
//     （openai_claude_request.go:38-42），客户端同时给两个时 top_p 被吃掉，这里补回。
//   - max_tokens == 0：Claude 的合法"预热缓存不生成"语义，但 OpenAI 系上游要求 >=1，原样发必 400 → 删字段。
//   - top_k：OpenAI Chat wire 无此字段，官方端点见到未知字段会 400，因此丢弃。
//   - output_config.format(json_schema) → response_format：保住 Claude 侧的结构化输出能力。
//     Responses 上游的 body 此时仍是 Chat 中间格式，且其结构化输出字段名不同，故不处理。
//
// Anthropic 上游不会走到这里（同协议 passthrough 已在 handler 前段返回）。
func patchClaudeUpstreamBody(body []byte, original []byte, upstream *UpstreamConfig) []byte {
	var src map[string]any
	if err := json.Unmarshal(original, &src); err != nil || src == nil {
		return body
	}

	apiType := UpstreamOpenAI
	if upstream != nil {
		apiType = upstream.APIType
	}

	// max_tokens:0 —— 任何上游都要删，否则 400。
	if v, ok := src["max_tokens"]; ok && toFloat64Any(v) == 0 {
		if bodyHasField(body, "max_tokens") {
			body = removeField(body, "max_tokens")
		}
	}

	// stop_sequences → stop
	if stops, ok := src["stop_sequences"].([]any); ok && len(stops) > 0 && !bodyHasField(body, "stop") {
		list := make([]string, 0, len(stops))
		for _, s := range stops {
			if str, ok := s.(string); ok && str != "" {
				list = append(list, str)
			}
		}
		if len(list) > 0 {
			var value any = list
			if len(list) == 1 {
				value = list[0]
			}
			if m, err := jsonSetField(body, "stop", value); err == nil {
				body = m
			}
		}
	}

	// top_p —— CPA 的 temperature/top_p 互斥补偿。
	if topP, ok := src["top_p"]; ok && !bodyHasField(body, "top_p") {
		if m, err := jsonSetField(body, "top_p", topP); err == nil {
			body = m
		}
	}

	// output_config.format(json_schema) → response_format
	if apiType == UpstreamOpenAI {
		if rf, ok := claudeOutputFormatToResponseFormat(src); ok && !bodyHasField(body, "response_format") {
			if m, err := jsonSetField(body, "response_format", rf); err == nil {
				body = m
			}
		}
	}

	return body
}

// claudeOutputFormatToResponseFormat 把 Claude 的 output_config.format（JSONOutputFormat）
// 转成 OpenAI Chat 的 response_format。无 schema 时返回 false（不写字段，避免上游拒绝空 schema）。
func claudeOutputFormatToResponseFormat(src map[string]any) (map[string]any, bool) {
	oc, ok := src["output_config"].(map[string]any)
	if !ok {
		return nil, false
	}
	format, ok := oc["format"].(map[string]any)
	if !ok {
		return nil, false
	}
	if t, _ := format["type"].(string); t != "json_schema" {
		return nil, false
	}
	schema, ok := format["schema"]
	if !ok || schema == nil {
		return nil, false
	}
	return map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "response",
			"schema": schema,
		},
	}, true
}

// toFloat64Any 把 JSON 反序列化出来的数值转 float64；非数值返回 -1（区别于合法的 0）。
func toFloat64Any(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return -1
	}
}

// cpaInjectedUserIDPattern 是 CPA 注入 metadata.user_id 的值前缀（确定性随机 hash）。
// 客户端原请求即便带 metadata.user_id，通常也不会匹配 user_<x>_account_<x>_session_<x> 形态。
const cpaInjectedUserIDPrefix = "user_"

// stripCPAInjectedMetadataUserID 删除顶层 metadata.user_id 仅当其值形如 CPA 注入的
// "user_<rand>_account_<rand>_session_<rand>" hash，避免误删客户端原 metadata。
// 若 metadata 删空则一并清掉顶层 metadata 字段，防止发个空对象给上游。
func stripCPAInjectedMetadataUserID(body []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return body
	}
	md, ok := obj["metadata"].(map[string]any)
	if !ok {
		return body
	}
	uid, ok := md["user_id"].(string)
	if !ok || !looksLikeCPAInjectedUserID(uid) {
		return body
	}
	delete(md, "user_id")
	if len(md) == 0 {
		delete(obj, "metadata")
	} else {
		obj["metadata"] = md
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// looksLikeCPAInjectedUserID 识别 CPA 注入的 user_id hash：以 "user_" 开头且含 _account_ 与 _session_ 段。
func looksLikeCPAInjectedUserID(s string) bool {
	if !strings.HasPrefix(s, cpaInjectedUserIDPrefix) {
		return false
	}
	return strings.Contains(s, "_account_") && strings.Contains(s, "_session_")
}

// aliasReasoningFormatKey 取 alias.ReasoningFormat 的小写归一键。
func aliasReasoningFormatKey(alias ModelAlias) string {
	return normalizeReasoningFormatStr(alias.ReasoningFormat)
}

// ======================== 响应翻译（阶段2 非流式） ========================

// cpaTranslateNonStream 把上游非流式响应翻回客户端格式。
//   - route: 由 cpaTranslateRequest 成功返回的翻译路径（含预建的 ResponseStagesNonStream）
//   - rawResponse: 上游原始响应 JSON（未经 callPreparedUpstream 提前二次转换的 raw body）
//   - fallback: CPA 无翻译器/失败/路线不可用 时回退的手写响应翻译
//
// 返回翻译后的客户端格式响应 JSON。
func cpaTranslateNonStream(ctx context.Context, route *cpaTranslationRoute, rawResponse []byte, fallback func([]byte) []byte) []byte {
	// route==nil：该入站-上游方向 CPA 通不了（非对称 matrix），整条走手写 fallback。
	if route == nil {
		return fallback(rawResponse)
	}
	stages := route.ResponseStagesNonStream
	if len(stages) == 0 {
		return fallback(rawResponse)
	}

	body := rawResponse
	for _, st := range stages {
		// 该段响应翻译：把 source(st.FromFormat) 响应翻成 target(st.ToFormat)。
		// CPA TranslateNonStream(ctx, from=源, to=目标, ...) 内部查 responses[to][from]，与我们探测一致。
		var param any
		out := sdktranslator.TranslateNonStream(ctx, st.FromFormat, st.ToFormat, route.Model, st.OriginalRequest, st.RequestBody, body, &param)
		if len(out) == 0 || !json.Valid(out) {
			// 该段翻译失败：放弃整条 CPA 路径，回手写 fallback（用原始上游响应，不是半成品）。
			return fallback(rawResponse)
		}
		body = out
	}
	return body
}

// cpaGoodResponsePairs 是 CPA v7.2.97 响应翻译器**质量已验证可用**的方向集合（from=源上游格式,to=目标客户端格式）。
// 探针实测（2026-07-26）：
//   - Chat→Claude（Anthropic 入站+Chat 上游）：content/usage 完整保留，可用 ✓
//   - Claude→Chat（Chat 入站+Anthropic 上游）：输出空壳（content=""/usage 全 0），✗ 不可用
//   - Responses→Chat（Chat 入站+Responses 上游）：TranslateNonStream 原样透传不翻译，✗ 不可用
//   - Responses→Claude：待 e2e 验证后再加入
//
// 仅当响应链每段都在此集合（或单段恒等 Chat→Chat）时才允许走 CPA 响应翻译，否则整条手写 fallback。
// 未来 CPA 升级修复 Claude→Chat 等方向后，扩充此集合即可灰度放开，无需改 handler。
var cpaGoodResponsePairs = map[string]bool{
	formatPairKey(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude): true, // Chat→Claude
}

// formatPairKey 把 (from,to) 压成一个稳定的字符串键（Format 常量可能同首字母，如 "openai"/"openai-response"，故用完整拼接）。
func formatPairKey(from, to sdktranslator.Format) string {
	return string(from) + "|" + string(to)
}

// cpaResponseUsableForRoute 报告该 route 的响应链是否适合走 CPA 响应翻译：
//   - 流式或非流式分别查对应 stages
//   - 单段恒等（from==to，如 Chat→Chat）算可用（恒等翻译无质量风险）
//   - 任一段不在 cpaGoodResponsePairs 白名单则不可用（回手写，规避 CPA 空壳/透传缺陷）
func cpaResponseUsableForRoute(route *cpaTranslationRoute, stream bool) bool {
	if route == nil {
		return false
	}
	stages := route.ResponseStagesNonStream
	if stream {
		stages = route.ResponseStagesStream
	}
	if len(stages) == 0 {
		return false
	}
	for _, st := range stages {
		if st.FromFormat == st.ToFormat {
			continue // 恒等段
		}
		if !cpaGoodResponsePairs[formatPairKey(st.FromFormat, st.ToFormat)] {
			return false
		}
	}
	return true
}

// handwrittenResponseToChat 把 raw 上游响应按上游格式手写翻回 **OpenAI Chat** 客户端格式。
// 用于 chat 入站 + CPA 请求翻译路径：transport 用 callPreparedUpstream(raw=true) 拿到 raw 上游响应后，
// 响应翻译因 CPA 翻译器质量缺陷（Claude→Chat 空壳、Responses→Chat 透传）走手写分派。
// 这复刻了 callPreparedUpstream(raw=false) 在 main.go:3209-3215 内部的分派，但对 Chat 上游额外跑 convertResponse 清洗。
func handwrittenResponseToChat(rawResp []byte, model string, upstreamFormat sdktranslator.Format) []byte {
	switch upstreamFormat {
	case sdktranslator.FormatOpenAIResponse:
		return convertResponsesToChat(rawResp, model)
	case sdktranslator.FormatClaude:
		return convertAnthropicToOpenAI(rawResp, model)
	default: // FormatOpenAI（Chat wire）
		converted, err := convertResponse(rawResp)
		if err == nil {
			return converted
		}
		return rawResp
	}
}

// handwrittenResponseToClaude 把 raw 上游响应按上游格式手写翻回 **Anthropic/Claude** 客户端格式。
// 用于 anthropicMessagesHandler 非流式 + CPA 请求翻译路径：transport callPreparedUpstream(raw=true) 后，
// 响应翻译因 CPA 翻译器质量缺陷走手写分派。
//   - Chat 上游：openAIToAnthropicResponse（Chat→Claude）
//   - Responses 上游：先 convertResponsesToChat 再 openAIToAnthropicResponse（Responses→Chat→Claude 两段，复刻旧 callUpstream 隐式链）
//   - Claude 上游：原样（Anthropic 入站+Anthropic 上游走 passthrough，不至此）；防御返回原样
func handwrittenResponseToClaude(rawResp []byte, model string, upstreamFormat sdktranslator.Format) []byte {
	switch upstreamFormat {
	case sdktranslator.FormatOpenAIResponse:
		chat := convertResponsesToChat(rawResp, model)
		out, _ := openAIToAnthropicResponse(chat, model)
		if len(out) > 0 {
			return out
		}
		return rawResp
	case sdktranslator.FormatClaude:
		return rawResp // 同协议直通由 passthrough 处理；此处防御原样返回
	default: // FormatOpenAI（Chat wire）
		out, ok := openAIToAnthropicResponse(rawResp, model)
		if ok && len(out) > 0 {
			return out
		}
		return rawResp
	}
}

// handwrittenResponseToResponses 把 raw 上游响应按上游格式手写翻回 **OpenAI Responses** 客户端格式。
// 用于 responsesHandler 非流式 + CPA 请求翻译路径：transport callPreparedUpstream(raw=true) 后，
// 响应翻译（Responses 入站响应方向 Chat→Responses/Claude→Responses 不在白名单）走手写分派。
// tools/toolChoice/toolNameMappings 是 Responses 入站特有的 tool name mapping，由 responsesHandler 传入。
//   - Chat 上游：convertChatToResponses（Chat→Responses）
//   - Anthropic 上游：先 convertAnthropicToOpenAI 再 convertChatToResponses（Claude→Chat→Responses 两段，复刻旧 callUpstream 隐式链）
//   - Responses 上游：原样（passthrough 已处理；防御返回原样）
func handwrittenResponseToResponses(rawResp []byte, model string, upstreamFormat sdktranslator.Format, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) []byte {
	switch upstreamFormat {
	case sdktranslator.FormatClaude:
		chat := convertAnthropicToOpenAI(rawResp, model)
		return convertChatToResponses(chat, model, tools, toolChoice, toolNameMappings)
	case sdktranslator.FormatOpenAIResponse:
		return rawResp // 同协议直通由 passthrough 处理；防御原样返回
	default: // FormatOpenAI（Chat wire）
		return convertChatToResponses(rawResp, model, tools, toolChoice, toolNameMappings)
	}
}

type cpaStageStreamState struct {
	stage cpaRouteStage
	param any
}

// cpaStreamChain 驱动多段流式翻译。阶段3 实现。
type cpaStreamChain struct {
	route  *cpaTranslationRoute
	stages []*cpaStageStreamState // 响应方向各段，独立 param
	emit   func([]byte) error
}

// 阶段2/3 占位：实现在相应阶段补全。

// ======================== internal helpers ========================

// jsonSetField 在 JSON body 顶层设字段。失败返回原 body + err。
func jsonSetField(body []byte, field string, value any) ([]byte, error) {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, err
	}
	if obj == nil {
		obj = map[string]any{}
	}
	obj[field] = value
	out, err := json.Marshal(obj)
	if err != nil {
		return body, err
	}
	return out, nil
}

// bodyHasField 报告顶层是否含某字段。
func bodyHasField(body []byte, field string) bool {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return false
	}
	_, ok := obj[field]
	return ok
}

// removeField 移除顶层字段。
func removeField(body []byte, field string) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	delete(obj, field)
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// removeTopLevelReasoningEffortIfThinking 在 thinking 方言下移除顶层 reasoning_effort。
func removeTopLevelReasoningEffortIfThinking(body []byte, thinkingFormat string) []byte {
	if thinkingFormat != "thinking" {
		return body
	}
	if bodyHasField(body, "reasoning_effort") {
		return removeField(body, "reasoning_effort")
	}
	return body
}

// normalizeReasoningFormatStr 归一 ReasoningFormat 为 "" 或 "thinking"。
func normalizeReasoningFormatStr(s string) string {
	switch s {
	case "thinking", "Thinking", "THINKING":
		return "thinking"
	default:
		return ""
	}
}
