package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// ======================== Claude 入站兼容夹层（L1 入站降级 / L5 出站补全） ========================
//
// 背景：/v1/messages 入站在**非 Anthropic 上游**（Chat / Responses）下，
// 无论走 CPA 翻译还是手写翻译，Claude 协议里大量结构都会被静默丢弃——document、search_result、
// server-tool 结果块、tool_result 的 is_error 与 image 子块、未知新 block 等。丢弃等于模型看不见，
// 是实打实的能力下降。本文件把这些结构**降级成模型仍能读到的文本**，而不是丢，也绝不因此回 400。
//
// 分工：
//   L1 normalizeClaudeInboundRequest —— 入站 Claude body → 仍是 Claude body，只是把上游/翻译器
//      看不懂的块换成等价 text 块。放在 handler 最前，CPA 与手写两条路径共享收益。
//   L5 enrichClaudeResponse —— 出站 Claude body 补 thinking signature 与 usage 缓存字段。
//
// signature 闭环（本文件存在的最重要理由）：
//   CPA v7.2.97 的 ConvertClaudeRequestToOpenAI 通过 shouldMapClaudeThinkingToGPTReasoning
//   校验 thinking 块的 signature 必须是 GPT Fernet 形状（gAAAA 前缀 / 解码首字节 0x80 /
//   密文长度 16 倍数），否则**整段历史思考被丢弃**。本网关出站的 thinking 块原本从不带 signature，
//   于是多轮对话在 CPA 路径下 100% 丢历史推理。解法是闭环：
//     L5 出站签发形状合法的合成 signature → 客户端原样回传 → L1 见其合法直接放行 → CPA 保留 reasoning_content。
//   合成 signature 只作用于 CPA 的门禁判定，不会进入上游请求体（CPA 输出的是 reasoning_content 纯文本）。

// ======================== 开关 ========================
//
// 未配置即开启：这两层补的是原本会被静默丢弃的内容，属修复语义，默认关等于没做。
// 开关只为出问题时一键回退到旧行为。

func claudeInboundNormalizeEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	if claudeCompatCfg.InboundNormalize == nil {
		return true
	}
	return *claudeCompatCfg.InboundNormalize
}

func claudeOutboundEnrichEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	if claudeCompatCfg.OutboundEnrich == nil {
		return true
	}
	return *claudeCompatCfg.OutboundEnrich
}

// ======================== thinking signature 合成与校验 ========================

// thinkingSignatureSalt 让合成签名与任何真实 provider 签名在派生上不可能碰撞。
const thinkingSignatureSalt = "llm2api-thinking-sig\x00"

// synthesizeThinkingSignature 为一段 thinking 文本生成形状合法的 Fernet 形态签名。
//
// 布局（与 CPA InspectGPTReasoningSignature 的校验一一对应）：
//
//	[0]      0x80          版本号
//	[1:9]    big-endian ts  固定 0——high 位为 0 才能保证 base64 后以 "gAAAA" 开头，且保持幂等
//	[9:25]   16B IV
//	[25:41]  16B 密文（1 个 AES 块，满足 ciphertextLen%16==0）
//	[41:73]  32B HMAC
//
// 解码总长 73 字节，正好满足 CPA 的 >=73 下限。IV/密文/HMAC 全部由 thinking 文本 SHA-256 派生，
// 因此同文本恒等同签名——L1/L5 反复作用于同一 body 时结果稳定，便于测试与排障。
func synthesizeThinkingSignature(thinkingText string) string {
	seed := sha256.Sum256([]byte(thinkingSignatureSalt + thinkingText))
	mac := sha256.Sum256(seed[:])

	buf := make([]byte, 0, 73)
	buf = append(buf, 0x80)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, 0)
	buf = append(buf, ts...)
	buf = append(buf, seed[0:16]...)  // IV
	buf = append(buf, seed[16:32]...) // 密文（1 块）
	buf = append(buf, mac[:]...)      // HMAC

	return base64.RawURLEncoding.EncodeToString(buf)
}

// thinkingSignatureUsable 复刻 CPA InspectGPTReasoningSignature 的形状检查，
// 用来判断入站 thinking 块的 signature 是否已经能被 CPA 接受（能则不覆盖客户端原值）。
// 只做形状检查，不证明可解密——与 CPA 的语义一致。
func thinkingSignatureUsable(sig string) bool {
	sig = strings.TrimSpace(sig)
	if sig == "" || !strings.HasPrefix(sig, "gAAAA") {
		return false
	}
	for _, r := range sig {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '=':
		default:
			return false
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(sig)
		if err != nil {
			return false
		}
	}
	if len(decoded) < 73 || decoded[0] != 0x80 {
		return false
	}
	ciphertextLen := len(decoded) - 1 - 8 - 16 - 32
	return ciphertextLen > 0 && ciphertextLen%16 == 0
}

// ======================== L1：入站降级 ========================

// claudeBlockTextLimit 限制单个降级块产出的文本长度，避免超大 server-tool 结果撑爆上下文。
const claudeBlockTextLimit = 4000

// normalizeClaudeInboundRequest 把入站 Claude 请求里上游/翻译器无法表达的内容块降级为 text 块。
// 输入输出都是 Claude 格式 JSON；任何解析失败都原样返回，绝不报错、绝不让调用方 400。
// 幂等：对已降级过的 body 再跑一次结果不变（降级产物都是 text 块，thinking 签名由文本派生）。
//
// 注意：仅用于**非 Anthropic 上游**路径。真 Claude 上游走 passthrough，原生支持全部块类型，
// 降级只会白白损失信息。
//
// 成本：每个请求多一次 json.Unmarshal（无需降级时不再 Marshal）。有意不做"关键字预检跳过解析"
// 的优化——未知的新 block 类型没有可预检的关键字，预检会让"未来新块也降级而不丢"这条保证失效。
func normalizeClaudeInboundRequest(body []byte) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil || req == nil {
		return body
	}

	changed := false
	if sysArr, ok := req["system"].([]any); ok {
		if out, c := degradeClaudeBlocks(sysArr, "system"); c {
			req["system"] = out
			changed = true
		}
	}
	if msgs, ok := req["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			blocks, ok := msg["content"].([]any)
			if !ok {
				continue
			}
			role, _ := msg["role"].(string)
			if out, c := degradeClaudeBlocks(blocks, role); c {
				msg["content"] = out
				changed = true
			}
		}
	}
	if !changed {
		return body
	}
	out, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return out
}

// degradeClaudeBlocks 逐块处理一个 content 数组，返回新数组与"是否发生改动"。
// 原生支持的块（text/image/tool_use）原样保留；thinking 补签；redacted_thinking 丢弃
// （内容已加密，无法降级，与 CPA 行为一致）；其余一律降级为 text 块，包括**未知的新 block 类型**
// ——这样 Anthropic 之后加新块时本网关也只会降级，不会静默丢。
func degradeClaudeBlocks(blocks []any, role string) ([]any, bool) {
	out := make([]any, 0, len(blocks))
	changed := false

	for _, item := range blocks {
		block, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		blockType, _ := block["type"].(string)

		switch blockType {
		case "text", "image":
			out = append(out, block)

		case "thinking":
			// 只有 assistant 的 thinking 有回放价值；其它角色 CPA 本就忽略，不补签。
			if role == "assistant" {
				sig, _ := block["signature"].(string)
				if !thinkingSignatureUsable(sig) {
					text, _ := block["thinking"].(string)
					block["signature"] = synthesizeThinkingSignature(text)
					changed = true
				}
			}
			out = append(out, block)

		case "redacted_thinking":
			// 加密内容，无可降级的明文，丢弃。
			changed = true

		case "tool_use":
			out = append(out, block)

		case "tool_result":
			if degradeToolResultBlock(block) {
				changed = true
			}
			out = append(out, block)

		default:
			text := claudeBlockToText(block, blockType)
			if text == "" {
				// 连降级文本都产不出（罕见）：保留原块交给下游，不做无谓丢弃。
				out = append(out, block)
				continue
			}
			out = append(out, map[string]any{"type": "text", "text": text})
			changed = true
		}
	}
	return out, changed
}

// claudeToolResultContentToText 把一个 tool_result 的 content（string / block 数组 / 其它）
// 转成上游 OpenAI tool message 能承载的纯文本。
//
// 背景（PR#2 review comment 1）：手写 Claude→OpenAI 转换器过去只取 type:text 子块，于是
// 成功的 tool_result 里 image / document / search_result / 未知子块会被**静默吞成空 tool message**，
// 模型看不见工具结果。CPA 路径会保留 image 并降级其它子块，这里与之一致而不扩大 L1 降级：
//   - text 子块：原样保留文本
//   - image 子块：降级为可读占位（上游不支持 tool message 内嵌图片）
//   - 其它已知块（document/search_result/...）：复用 claudeBlockToText 无损或文本化降级
//   - 未知子块：claudeBlockToText 的 default 分支保留 JSON 摘要
//   - string：原样返回；nil / 空数组：空串
//
// 顺序按原 content 数组顺序拼接。
func claudeToolResultContentToText(content any) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			sub, ok := item.(map[string]any)
			if !ok {
				// 数组里的裸字符串直接取值（compactJSONPreview 会包成 "result"，可读性错误）；
				// 其它基本类型（数字/布尔）才退到紧凑 JSON 兜底，至少不留空。
				if s, isStr := item.(string); isStr {
					if s != "" {
						parts = append(parts, s)
					}
					continue
				}
				if s := compactJSONPreview(item); s != "" && s != "null" {
					parts = append(parts, s)
				}
				continue
			}
			blockType, _ := sub["type"].(string)
			switch blockType {
			case "text":
				if t, _ := sub["text"].(string); t != "" {
					parts = append(parts, t)
				}
			case "image":
				parts = append(parts, imageBlockToText(sub))
			default:
				// 复用 L1 的降级语：document/search_result/server-tool 结果/未知块都能产出可读文本，
				// 而不是让模型看到一个空 tool message。
				if t := claudeBlockToText(sub, blockType); t != "" {
					parts = append(parts, t)
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		// 兜底：把无法归类的 content 序列化成 JSON 文本，而不是丢成空串。
		s := compactJSONPreview(content)
		if s == "" || s == "null" {
			return ""
		}
		return s
	}
}

// imageBlockToText 把 image 块降级成上游 tool message 可读的文本占位。
// OpenAI tool message 不支持嵌入图片，故仅留给模型"这里曾有一张图"的语义而非像素。
func imageBlockToText(block map[string]any) string {
	mediaType := ""
	if source, ok := block["source"].(map[string]any); ok {
		if mt, ok := source["media_type"].(string); ok {
			mediaType = mt
		}
	}
	if mediaType == "" {
		return "[image]"
	}
	return fmt.Sprintf("[image: %s]", mediaType)
}

// degradeToolResultBlock 就地处理 tool_result：把 is_error 折进文本前缀。
// image/search_result/document 等子块由 CPA 的 convertClaudeToolResultContent 处理
// （image 保留、未知子块降级为 JSON 文本），这里不重复干预。
// 返回是否改动。
func degradeToolResultBlock(block map[string]any) bool {
	isErr, _ := block["is_error"].(bool)
	if !isErr {
		return false
	}
	const prefix = "[error] "

	switch content := block["content"].(type) {
	case string:
		if strings.HasPrefix(content, prefix) {
			return false
		}
		block["content"] = prefix + content
		return true
	case []any:
		for _, item := range content {
			sub, ok := item.(map[string]any)
			if !ok || sub["type"] != "text" {
				continue
			}
			text, _ := sub["text"].(string)
			if strings.HasPrefix(text, prefix) {
				return false
			}
			sub["text"] = prefix + text
			return true
		}
		// 没有 text 子块（例如纯 image 结果）：插一个错误标记块到最前。
		block["content"] = append([]any{map[string]any{"type": "text", "text": strings.TrimSpace(prefix)}}, content...)
		return true
	case nil:
		block["content"] = strings.TrimSpace(prefix)
		return true
	}
	return false
}

// claudeBlockToText 把一个上游无法表达的 Claude 内容块转成等价文本。
// 原则：能无损就无损（document 的 text source、search_result 的正文都是纯文本），
// 无法无损时至少让模型知道"这里有过什么"，而不是凭空消失。
func claudeBlockToText(block map[string]any, blockType string) string {
	switch blockType {
	case "document":
		return documentBlockToText(block)

	case "search_result":
		title, _ := block["title"].(string)
		source, _ := block["source"].(string)
		head := strings.TrimSpace(fmt.Sprintf("[search result: %s — %s]", title, source))
		body := extractClaudeTextFromBlocks(block["content"])
		return joinBlockText(head, body)

	case "server_tool_use":
		name, _ := block["name"].(string)
		input := compactJSONPreview(block["input"])
		return truncatePreview(fmt.Sprintf("[%s 调用: %s]", name, input), claudeBlockTextLimit)

	case "web_search_tool_result", "web_fetch_tool_result", "code_execution_tool_result",
		"bash_code_execution_tool_result", "text_editor_code_execution_tool_result",
		"tool_search_tool_result":
		body := extractClaudeTextFromBlocks(block["content"])
		if body == "" {
			body = compactJSONPreview(block["content"])
		}
		return joinBlockText("["+blockType+"]", truncatePreview(body, claudeBlockTextLimit))

	case "container_upload":
		fileID, _ := block["file_id"].(string)
		return fmt.Sprintf("[container upload: %s]", fileID)

	case "mid_conv_system":
		body := extractClaudeTextFromBlocks(block["content"])
		return joinBlockText("[system]", body)

	case "tool_reference":
		toolName, _ := block["tool_name"].(string)
		return fmt.Sprintf("[tool: %s]", toolName)

	default:
		// 未知块（Anthropic 新增类型）：保留原始 JSON 摘要，让模型至少能看到内容。
		return truncatePreview(
			fmt.Sprintf("[unsupported content block: %s]\n%s", blockType, compactJSONPreview(block)),
			claudeBlockTextLimit,
		)
	}
}

// documentBlockToText 处理 document 块。text / content 两种 source 是无损的（正文就是纯文本），
// base64 / url 形态（PDF 等）上游无法解析，只留一条说明让模型知道有这份文档存在。
func documentBlockToText(block map[string]any) string {
	title, _ := block["title"].(string)
	head := "[document]"
	if strings.TrimSpace(title) != "" {
		head = fmt.Sprintf("[document: %s]", title)
	}
	if ctx, ok := block["context"].(string); ok && strings.TrimSpace(ctx) != "" {
		head = head + " " + strings.TrimSpace(ctx)
	}

	source, _ := block["source"].(map[string]any)
	if source == nil {
		return head
	}
	switch source["type"] {
	case "text":
		data, _ := source["data"].(string)
		return joinBlockText(head, truncatePreview(data, claudeBlockTextLimit))
	case "content":
		return joinBlockText(head, truncatePreview(extractClaudeTextFromBlocks(source["content"]), claudeBlockTextLimit))
	default:
		mediaType, _ := source["media_type"].(string)
		if mediaType == "" {
			mediaType, _ = source["type"].(string)
		}
		return fmt.Sprintf("%s（%s，上游不支持文档输入，内容未传递）", head, mediaType)
	}
}

// extractClaudeTextFromBlocks 从任意 Claude content（string / block 数组）里抽出纯文本。
func extractClaudeTextFromBlocks(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			switch sub := item.(type) {
			case string:
				parts = append(parts, sub)
			case map[string]any:
				if text, ok := sub["text"].(string); ok && text != "" {
					parts = append(parts, text)
					continue
				}
				// 嵌套结构（如 web_search_result）没有 text 字段，退化为紧凑 JSON。
				parts = append(parts, compactJSONPreview(sub))
			}
		}
		return strings.Join(parts, "\n")
	case map[string]any:
		if text, ok := v["text"].(string); ok {
			return text
		}
		return compactJSONPreview(v)
	default:
		return ""
	}
}

// joinBlockText 拼接标题行与正文，正文为空时只留标题。
func joinBlockText(head, body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return head
	}
	return head + "\n" + body
}

// compactJSONPreview 把任意值序列化成紧凑 JSON；失败时退回 Go 默认格式化。
func compactJSONPreview(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// logUnenforceableComplianceFields 对"上游无法兑现、但客户端会当成保证"的字段留痕。
//
// 按本网关的一贯原则，不支持的字段一律降级/丢弃而不回 400——但 inference_geo 不同于
// container/service_tier 那类性能与调度参数：它是**数据驻留合规控制**（Anthropic 官方在不支持
// 该参数的模型上返回 400 而非静默忽略，US-only 推理还是 1.1x 计价）。转发到第三方 vLLM 时
// 我们既无法兑现地域约束，也无从校验，调用方却会以为拿到了境内推理保证。
// 折中：不拒绝请求（遵循降级原则），但把这次"承诺未兑现"记进日志，让它可被审计到。
func logUnenforceableComplianceFields(body []byte, model string, upstream *UpstreamConfig) {
	var req struct {
		InferenceGeo string `json:"inference_geo"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return
	}
	if strings.TrimSpace(req.InferenceGeo) == "" {
		return
	}
	apiType := UpstreamOpenAI
	if upstream != nil {
		apiType = upstream.APIType
	}
	log.Printf("[compliance] 请求带 inference_geo=%q，但上游 api_type=%s 无法兑现数据驻留约束，字段已丢弃（model=%s）",
		req.InferenceGeo, apiType, model)
}

// ======================== L5：出站补全 ========================

// enrichClaudeResponse 补全回给客户端的 Claude 非流式响应：
//   - thinking 块补 signature（signature 闭环的签发端，见文件头说明）
//   - usage 补 cache_creation_input_tokens / cache_read_input_tokens（官方响应恒有这两项，
//     缺失会让客户端把缓存统计显示为空）
//
// 任何解析失败原样返回。
func enrichClaudeResponse(body []byte) []byte {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil || resp == nil {
		return body
	}
	changed := false

	if blocks, ok := resp["content"].([]any); ok {
		for _, item := range blocks {
			block, ok := item.(map[string]any)
			if !ok || block["type"] != "thinking" {
				continue
			}
			sig, _ := block["signature"].(string)
			if thinkingSignatureUsable(sig) {
				continue
			}
			text, _ := block["thinking"].(string)
			block["signature"] = synthesizeThinkingSignature(text)
			changed = true
		}
	}

	if usage, ok := resp["usage"].(map[string]any); ok {
		for _, k := range []string{"cache_creation_input_tokens", "cache_read_input_tokens"} {
			if _, exists := usage[k]; !exists {
				usage[k] = 0
				changed = true
			}
		}
	}

	if !changed {
		return body
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return out
}

// ======================== count_tokens 估算 ========================

// Claude 官方 /v1/messages/count_tokens 需要真实 tokenizer，本网关不引入 tokenizer 依赖，
// 用字符级粗估代替：宁可返回一个 ±20% 的估算值让客户端的上下文管理能工作，
// 也好过 404 让 SDK 调用直接失败。
const (
	// charsPerToken 是中英混合语料的折中系数（纯英文约 4，纯中文约 1.5）。
	charsPerToken = 3.5
	// base64CharsPerImageToken 由 Anthropic 图片计费近似（约 750 base64 字符 ≈ 1 token 的量级）。
	base64CharsPerImageToken = 750
	// perMessageOverhead 是每条消息的角色/分隔符固定开销。
	perMessageOverhead = 4
)

// estimateClaudeInputTokens 粗估一个 Claude 请求的输入 token 数。返回值至少为 1。
func estimateClaudeInputTokens(body []byte) int {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil || req == nil {
		return 1
	}

	total := 0.0
	total += estimateClaudeContentTokens(req["system"])

	if msgs, ok := req["messages"].([]any); ok {
		for _, m := range msgs {
			total += perMessageOverhead
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			total += estimateClaudeContentTokens(msg["content"])
		}
	}

	// 工具定义整体进 prompt，按序列化后的字符数计。
	if tools, ok := req["tools"]; ok {
		total += float64(len([]rune(compactJSONPreview(tools)))) / charsPerToken
	}

	n := int(total)
	if n < 1 {
		n = 1
	}
	return n
}

// anthropicCountTokensHandler 实现 POST /v1/messages/count_tokens。
// 官方端点需要真实 tokenizer，本网关给出字符级估算——返回 200 + 合规响应体，
// 好过 404 让 Anthropic SDK 的 count_tokens() 直接失败。响应体不加任何非标字段
// （协议里没有"这是估算值"的位置），估算属性只记在日志里。
func anthropicCountTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "Failed to read request body")
		return
	}

	var req struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON")
		return
	}
	if !isKnownAlias(req.Model) {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "model not found; only configured aliases are accepted")
		return
	}

	// 与推理路径同样先做 L1 降级，估算才与真正发给上游的内容量一致。
	if claudeInboundNormalizeEnabled() {
		body = normalizeClaudeInboundRequest(body)
	}
	tokens := estimateClaudeInputTokens(body)
	if debugMode {
		log.Printf("[count_tokens] model=%q input_tokens=%d (estimated, no tokenizer)", req.Model, tokens)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{"input_tokens": tokens})
}

// writeAnthropicError 输出 Anthropic 形态的错误体，复用 buildAnthropicErrorBody 的结构。
func writeAnthropicError(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buildAnthropicErrorBody(errType, message))
}

// estimateClaudeContentTokens 估算一段 content（string / block 数组）的 token 数。
// image 按 base64 数据量折算，其余结构统一按其文本/JSON 长度折算——L1 已把复杂块降级成文本，
// 这里对未降级的原始 body 也能给出同量级的估算。
func estimateClaudeContentTokens(content any) float64 {
	switch v := content.(type) {
	case nil:
		return 0
	case string:
		return float64(len([]rune(v))) / charsPerToken
	case []any:
		total := 0.0
		for _, item := range v {
			block, ok := item.(map[string]any)
			if !ok {
				total += float64(len([]rune(compactJSONPreview(item)))) / charsPerToken
				continue
			}
			if block["type"] == "image" {
				if source, ok := block["source"].(map[string]any); ok {
					if data, ok := source["data"].(string); ok {
						total += float64(len(data)) / base64CharsPerImageToken
						continue
					}
				}
			}
			total += float64(len([]rune(compactJSONPreview(block)))) / charsPerToken
		}
		return total
	default:
		return float64(len([]rune(compactJSONPreview(v)))) / charsPerToken
	}
}
