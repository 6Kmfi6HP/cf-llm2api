package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	_ "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
)

// TestMain 把 token 统计的落盘路径改到临时目录。
// recordTokenUsage 末尾会 `go saveTokenStats()` 异步覆写 tokenStatsPath，跑推理路径的测试
// 会把仓库里真实的 stats.json 冲掉；异步写入还可能发生在单个测试结束之后，
// 因此必须在进程级别改，而不是逐测试保存/恢复。
func TestMain(m *testing.M) {
	tokenStatsPath = filepath.Join(os.TempDir(), "llm2api-test-stats.json")
	os.Exit(m.Run())
}

// ======================== signature 闭环 ========================

// TestSynthesizedThinkingSignatureAcceptedByCPA 是本方案最关键的契约测试。
// CPA 的 ConvertClaudeRequestToOpenAI 只在 thinking 块带有"GPT Fernet 形状"的 signature 时
// 才把思考映射成 reasoning_content，否则整段丢弃。本网关出站签发的合成 signature 必须能过这道门禁，
// 否则多轮对话的历史推理会全部丢失。CPA 升级改了校验规则时，这条测试立刻变红。
func TestSynthesizedThinkingSignatureAcceptedByCPA(t *testing.T) {
	const thinkingText = "先算 GCD(1071,462)，再验证结果。"
	sig := synthesizeThinkingSignature(thinkingText)

	if !thinkingSignatureUsable(sig) {
		t.Fatalf("自校验失败：合成签名不满足形状要求: %q", sig)
	}
	if !strings.HasPrefix(sig, "gAAAA") {
		t.Fatalf("合成签名缺少 gAAAA 前缀: %q", sig)
	}

	body := mustJSON(t, map[string]any{
		"model":      "m",
		"max_tokens": 100,
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": thinkingText, "signature": sig},
				map[string]any{"type": "text", "text": "答案是 21"},
			}},
		},
	})

	out := sdktranslator.TranslateRequest(sdktranslator.FormatClaude, sdktranslator.FormatOpenAI, "m", body, false)
	var chat struct {
		Messages []struct {
			Role             string `json:"role"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &chat); err != nil {
		t.Fatalf("CPA 输出不是合法 JSON: %v\n%s", err, out)
	}

	found := false
	for _, m := range chat.Messages {
		if m.Role == "assistant" && strings.Contains(m.ReasoningContent, thinkingText) {
			found = true
		}
	}
	if !found {
		t.Fatalf("CPA 丢弃了带合成签名的思考内容，signature 门禁未通过\n%s", out)
	}
}

// TestThinkingSignatureUsableRejectsGarbage 确保门禁判定不会把任意字符串当成合法签名，
// 否则 L1 会跳过补签、思考照样被 CPA 丢掉。
func TestThinkingSignatureUsableRejectsGarbage(t *testing.T) {
	for _, sig := range []string{"", "   ", "abc", "gAAAA", "gAAAA###", strings.Repeat("A", 200)} {
		if thinkingSignatureUsable(sig) {
			t.Errorf("非法签名被误判为可用: %q", sig)
		}
	}
}

// TestNormalizeAddsThinkingSignature 验证 L1 只给 assistant 的无签名 thinking 补签，
// 且不覆盖客户端已有的合法签名。
func TestNormalizeAddsThinkingSignature(t *testing.T) {
	existing := synthesizeThinkingSignature("客户端原值")
	body := mustJSON(t, map[string]any{
		"messages": []any{
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "无签名"},
			}},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "有签名", "signature": existing},
			}},
		},
	})

	got := normalizeClaudeInboundRequest(body)
	blocks := messageBlocks(t, got)

	if sig, _ := blocks[0][0]["signature"].(string); !thinkingSignatureUsable(sig) {
		t.Errorf("无签名 thinking 未被补签: %v", blocks[0][0])
	}
	if sig, _ := blocks[1][0]["signature"].(string); sig != existing {
		t.Errorf("已有合法签名被覆盖: got %q want %q", sig, existing)
	}
}

// ======================== tool_result 非文本子块降级（手写 fallback 路径） ========================

// TestClaudeToolResultContentToText 对照 PR#2 comment 1：手写 Claude→OpenAI 转换器过去只取 text 子块，
// image/document/search_result 等非文本子块会被吞成空 tool message。这里直接断言新的纯函数降级结果。
func TestClaudeToolResultContentToText(t *testing.T) {
	t.Run("纯文本数组保持原文", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "text", "text": "line1"},
			map[string]any{"type": "text", "text": "line2"},
		})
		if got != "line1\nline2" {
			t.Errorf("纯文本数组降级错误: %q", got)
		}
	})

	t.Run("image 子块不留空", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "AAA"}},
		})
		if strings.TrimSpace(got) == "" {
			t.Errorf("image-only tool_result 被吞成空内容")
		}
		if !strings.Contains(got, "image") {
			t.Errorf("image 子块降级文本缺少可读标识: %q", got)
		}
	})

	t.Run("document 子块正文保留", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "document", "title": "报告", "source": map[string]any{"type": "text", "data": "结论 OK"}},
		})
		if !strings.Contains(got, "结论 OK") {
			t.Errorf("document 正文丢失: %q", got)
		}
	})

	t.Run("search_result 子块保留正文", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "search_result", "title": "天气", "source": "e.com", "content": []any{map[string]any{"type": "text", "text": "晴"}}},
		})
		if !strings.Contains(got, "晴") {
			t.Errorf("search_result 正文丢失: %q", got)
		}
	})

	t.Run("混合内容保持顺序", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "text", "text": "before"},
			map[string]any{"type": "image", "source": map[string]any{"type": "base64", "data": "AAA"}},
			map[string]any{"type": "text", "text": "after"},
		})
		if !strings.HasPrefix(got, "before") || !strings.HasSuffix(got, "after") {
			t.Errorf("混合内容顺序被打乱: %q", got)
		}
	})

	t.Run("未知子块不留空", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{
			map[string]any{"type": "future_block", "payload": "重要数据"},
		})
		if strings.TrimSpace(got) == "" {
			t.Errorf("未知子块被吞成空内容")
		}
		if !strings.Contains(got, "重要数据") {
			t.Errorf("未知子块内容丢失: %q", got)
		}
	})

	t.Run("字符串 content 原样返回", func(t *testing.T) {
		if got := claudeToolResultContentToText("plain result"); got != "plain result" {
			t.Errorf("字符串 content 被改动: %q", got)
		}
	})

	t.Run("nil/空数组返回空串", func(t *testing.T) {
		if got := claudeToolResultContentToText(nil); got != "" {
			t.Errorf("nil 应返回空串: %q", got)
		}
		if got := claudeToolResultContentToText([]any{}); got != "" {
			t.Errorf("空数组应返回空串: %q", got)
		}
	})

	// 裸字符串子项不能被当成 JSON 包成 "result"（带引号）——会污染工具结果文本。
	t.Run("数组内裸字符串直接取值不带引号", func(t *testing.T) {
		got := claudeToolResultContentToText([]any{"plain", 42.0, true})
		if !strings.Contains(got, "plain") {
			t.Errorf("裸字符串丢失: %q", got)
		}
		if strings.Contains(got, `"plain"`) {
			t.Errorf("裸字符串被包成 JSON 字面量（带引号）: %q", got)
		}
	})
}

// TestSplitOpenAIInputWithCache 覆盖非流式/流式共用的缓存拆分口径，重点是非法负值钳制与异常口径。
func TestSplitOpenAIInputWithCache(t *testing.T) {
	cases := []struct {
		name                      string
		inputTokens, cachedTokens int
		wantInput                 int
		wantCacheRead             int
	}{
		{"无缓存", 100, 0, 100, 0},
		{"正常扣除", 100, 30, 70, 30},
		{"全部命中", 100, 100, 0, 100},
		{"缓存超过 input 钳到 input", 20, 50, 0, 20},
		{"负 cached 归零", 100, -10, 100, 0},
		{"负 input 归零", -5, 10, 0, 0},
		{"两者皆负", -5, -5, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, cr := splitOpenAIInputWithCache(tc.inputTokens, tc.cachedTokens)
			if in != tc.wantInput {
				t.Errorf("input_tokens: got %d want %d", in, tc.wantInput)
			}
			if cr != tc.wantCacheRead {
				t.Errorf("cache_read: got %d want %d", cr, tc.wantCacheRead)
			}
			if in < 0 || cr < 0 {
				t.Errorf("出现负数: in=%d cr=%d", in, cr)
			}
		})
	}
}

// ======================== L1 降级表 ========================

func TestNormalizeClaudeInboundRequestDegradesBlocks(t *testing.T) {
	tests := []struct {
		name        string
		block       map[string]any
		wantSubstrs []string
		wantDropped bool // 期望整块消失（不产出任何替代块）
	}{
		{
			name: "document 的 text source 无损保留正文",
			block: map[string]any{
				"type":  "document",
				"title": "设计稿",
				"source": map[string]any{
					"type": "text", "media_type": "text/plain", "data": "第一章 概述",
				},
			},
			wantSubstrs: []string{"[document: 设计稿]", "第一章 概述"},
		},
		{
			name: "document 的 base64 PDF 留说明",
			block: map[string]any{
				"type": "document",
				"source": map[string]any{
					"type": "base64", "media_type": "application/pdf", "data": "JVBER",
				},
			},
			wantSubstrs: []string{"[document]", "application/pdf", "上游不支持文档输入"},
		},
		{
			name: "search_result 保留标题与正文",
			block: map[string]any{
				"type": "search_result", "title": "天气", "source": "example.com",
				"content": []any{map[string]any{"type": "text", "text": "今天晴"}},
			},
			wantSubstrs: []string{"[search result: 天气 — example.com]", "今天晴"},
		},
		{
			name:        "server_tool_use 保留调用信息",
			block:       map[string]any{"type": "server_tool_use", "id": "srv1", "name": "web_search", "input": map[string]any{"query": "gcd"}},
			wantSubstrs: []string{"web_search 调用", "gcd"},
		},
		{
			name: "web_search_tool_result 保留结果",
			block: map[string]any{
				"type": "web_search_tool_result", "tool_use_id": "srv1",
				"content": []any{map[string]any{"type": "web_search_result", "title": "R1", "url": "https://e.com"}},
			},
			wantSubstrs: []string{"[web_search_tool_result]", "R1"},
		},
		{
			name:        "container_upload 留占位",
			block:       map[string]any{"type": "container_upload", "file_id": "file_123"},
			wantSubstrs: []string{"[container upload: file_123]"},
		},
		{
			name: "mid_conv_system 降级为文本",
			block: map[string]any{
				"type": "mid_conv_system", "content": []any{map[string]any{"type": "text", "text": "保持简洁"}},
			},
			wantSubstrs: []string{"[system]", "保持简洁"},
		},
		{
			name:        "tool_reference 降级为文本",
			block:       map[string]any{"type": "tool_reference", "tool_name": "grep"},
			wantSubstrs: []string{"[tool: grep]"},
		},
		{
			name:        "未知的新块类型也降级而不是丢弃",
			block:       map[string]any{"type": "some_future_block", "payload": "重要内容"},
			wantSubstrs: []string{"unsupported content block: some_future_block", "重要内容"},
		},
		{
			name:        "redacted_thinking 无明文可降级，丢弃",
			block:       map[string]any{"type": "redacted_thinking", "data": "encrypted"},
			wantDropped: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := mustJSON(t, map[string]any{
				"messages": []any{map[string]any{"role": "user", "content": []any{tc.block}}},
			})
			got := normalizeClaudeInboundRequest(body)

			if tc.wantDropped {
				if blocks := messageBlocks(t, got); len(blocks[0]) != 0 {
					t.Fatalf("期望丢弃该块，实际保留: %v", blocks[0])
				}
				return
			}

			blocks := messageBlocks(t, got)
			if len(blocks[0]) != 1 {
				t.Fatalf("期望降级为 1 个块，得到 %d 个: %v", len(blocks[0]), blocks[0])
			}
			out := blocks[0][0]
			if out["type"] != "text" {
				t.Fatalf("降级结果不是 text 块: %v", out)
			}
			text, _ := out["text"].(string)
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(text, want) {
					t.Errorf("降级文本缺少 %q:\n%s", want, text)
				}
			}
		})
	}
}

// TestNormalizeKeepsNativeBlocks 确认原生支持的块不被改动——降级层不该制造噪音。
func TestNormalizeKeepsNativeBlocks(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "hello"},
			map[string]any{"type": "image", "source": map[string]any{"type": "base64", "media_type": "image/png", "data": "AAA"}},
		}}},
	})
	if got := normalizeClaudeInboundRequest(body); string(got) != string(body) {
		t.Errorf("原生块被改动:\nbefore %s\nafter  %s", body, got)
	}
}

// TestNormalizeToolResultIsError 验证 is_error 折进文本——否则模型无法区分成功与失败的工具结果。
func TestNormalizeToolResultIsError(t *testing.T) {
	t.Run("字符串 content", func(t *testing.T) {
		body := mustJSON(t, map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "t1", "is_error": true, "content": "file not found"},
			}}},
		})
		blocks := messageBlocks(t, normalizeClaudeInboundRequest(body))
		content, _ := blocks[0][0]["content"].(string)
		if !strings.HasPrefix(content, "[error] ") {
			t.Errorf("错误标记缺失: %q", content)
		}
	})

	t.Run("数组 content 的 text 子块", func(t *testing.T) {
		body := mustJSON(t, map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "t1", "is_error": true, "content": []any{
					map[string]any{"type": "text", "text": "boom"},
				}},
			}}},
		})
		blocks := messageBlocks(t, normalizeClaudeInboundRequest(body))
		inner, _ := blocks[0][0]["content"].([]any)
		first, _ := inner[0].(map[string]any)
		if text, _ := first["text"].(string); !strings.HasPrefix(text, "[error] ") {
			t.Errorf("错误标记缺失: %q", text)
		}
	})

	t.Run("成功的 tool_result 不加前缀", func(t *testing.T) {
		body := mustJSON(t, map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
			}}},
		})
		if got := normalizeClaudeInboundRequest(body); string(got) != string(body) {
			t.Errorf("成功结果被改动: %s", got)
		}
	})
}

// TestNormalizeSystemArray 验证 system 的 block 数组同样降级——CPA 的 system 处理也只认 text/image。
func TestNormalizeSystemArray(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"system": []any{
			map[string]any{"type": "text", "text": "你是助手"},
			map[string]any{"type": "tool_reference", "tool_name": "bash"},
		},
	})
	var got map[string]any
	if err := json.Unmarshal(normalizeClaudeInboundRequest(body), &got); err != nil {
		t.Fatal(err)
	}
	arr, _ := got["system"].([]any)
	if len(arr) != 2 {
		t.Fatalf("system 块数变化: %v", arr)
	}
	second, _ := arr[1].(map[string]any)
	if second["type"] != "text" || !strings.Contains(second["text"].(string), "[tool: bash]") {
		t.Errorf("system 里的 tool_reference 未降级: %v", second)
	}
}

// TestNormalizeIdempotent 确保重复归一化结果稳定（合成签名由文本派生，降级产物是 text 块）。
func TestNormalizeIdempotent(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"messages": []any{
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "think"},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "document", "source": map[string]any{"type": "text", "data": "正文"}},
				map[string]any{"type": "tool_result", "tool_use_id": "t", "is_error": true, "content": "err"},
			}},
		},
	})
	once := normalizeClaudeInboundRequest(body)
	twice := normalizeClaudeInboundRequest(once)
	if string(once) != string(twice) {
		t.Errorf("非幂等:\n1st %s\n2nd %s", once, twice)
	}
}

// TestNormalizeInvalidJSONPassthrough 确认坏输入原样返回——这一层永远不能成为新的 400 来源。
func TestNormalizeInvalidJSONPassthrough(t *testing.T) {
	raw := []byte(`{not json`)
	if got := normalizeClaudeInboundRequest(raw); string(got) != string(raw) {
		t.Errorf("非法 JSON 未原样返回: %s", got)
	}
}

// ======================== L5 出站补全 ========================

func TestEnrichClaudeResponse(t *testing.T) {
	body := mustJSON(t, map[string]any{
		"type": "message",
		"content": []any{
			map[string]any{"type": "thinking", "thinking": "推理过程"},
			map[string]any{"type": "text", "text": "答案"},
		},
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 5},
	})

	var got map[string]any
	if err := json.Unmarshal(enrichClaudeResponse(body), &got); err != nil {
		t.Fatal(err)
	}

	blocks, _ := got["content"].([]any)
	thinking, _ := blocks[0].(map[string]any)
	if sig, _ := thinking["signature"].(string); !thinkingSignatureUsable(sig) {
		t.Errorf("thinking 块未签发可用 signature: %v", thinking)
	}
	usage, _ := got["usage"].(map[string]any)
	for _, k := range []string{"cache_creation_input_tokens", "cache_read_input_tokens"} {
		if _, ok := usage[k]; !ok {
			t.Errorf("usage 缺少 %s: %v", k, usage)
		}
	}
}

// TestEnrichRoundTripsThroughNormalize 验证 signature 闭环：出站签发 → 客户端回传 → L1 放行不覆盖。
func TestEnrichRoundTripsThroughNormalize(t *testing.T) {
	resp := mustJSON(t, map[string]any{
		"content": []any{map[string]any{"type": "thinking", "thinking": "闭环"}},
	})
	var enriched map[string]any
	if err := json.Unmarshal(enrichClaudeResponse(resp), &enriched); err != nil {
		t.Fatal(err)
	}
	blocks, _ := enriched["content"].([]any)
	issued, _ := blocks[0].(map[string]any)["signature"].(string)

	next := mustJSON(t, map[string]any{
		"messages": []any{map[string]any{"role": "assistant", "content": []any{
			map[string]any{"type": "thinking", "thinking": "闭环", "signature": issued},
		}}},
	})
	got := messageBlocks(t, normalizeClaudeInboundRequest(next))
	if sig, _ := got[0][0]["signature"].(string); sig != issued {
		t.Errorf("回传的签名被改写: got %q want %q", sig, issued)
	}
}

// ======================== 上游 body 补丁 ========================

func TestPatchClaudeUpstreamBody(t *testing.T) {
	chat := &UpstreamConfig{APIType: UpstreamOpenAI}

	t.Run("stop_sequences 补成 stop", func(t *testing.T) {
		original := []byte(`{"stop_sequences":["END","STOP"]}`)
		got := patchClaudeUpstreamBody([]byte(`{"model":"m"}`), original, chat)
		var obj map[string]any
		json.Unmarshal(got, &obj)
		stops, ok := obj["stop"].([]any)
		if !ok || len(stops) != 2 {
			t.Fatalf("stop 未补齐: %s", got)
		}
	})

	t.Run("单个 stop_sequence 用字符串形态", func(t *testing.T) {
		got := patchClaudeUpstreamBody([]byte(`{}`), []byte(`{"stop_sequences":["END"]}`), chat)
		var obj map[string]any
		json.Unmarshal(got, &obj)
		if obj["stop"] != "END" {
			t.Fatalf("单值 stop 形态错误: %s", got)
		}
	})

	t.Run("top_p 在 CPA 互斥吃掉后补回", func(t *testing.T) {
		original := []byte(`{"temperature":0.5,"top_p":0.9}`)
		got := patchClaudeUpstreamBody([]byte(`{"temperature":0.5}`), original, chat)
		var obj map[string]any
		json.Unmarshal(got, &obj)
		if obj["top_p"] != 0.9 {
			t.Fatalf("top_p 未补回: %s", got)
		}
	})

	t.Run("max_tokens:0 删除避免上游 400", func(t *testing.T) {
		got := patchClaudeUpstreamBody([]byte(`{"max_tokens":0}`), []byte(`{"max_tokens":0}`), chat)
		if bodyHasField(got, "max_tokens") {
			t.Fatalf("max_tokens:0 未删除: %s", got)
		}
	})

	t.Run("top_k 不向 OpenAI 上游透传", func(t *testing.T) {
		original := []byte(`{"top_k":40}`)
		if got := patchClaudeUpstreamBody([]byte(`{}`), original, chat); bodyHasField(got, "top_k") {
			t.Errorf("OpenAI 上游不该带 top_k: %s", got)
		}
	})

	t.Run("output_config.format 映射为 response_format", func(t *testing.T) {
		original := []byte(`{"output_config":{"format":{"type":"json_schema","schema":{"type":"object"}}}}`)
		got := patchClaudeUpstreamBody([]byte(`{}`), original, chat)
		var obj map[string]any
		json.Unmarshal(got, &obj)
		rf, ok := obj["response_format"].(map[string]any)
		if !ok || rf["type"] != "json_schema" {
			t.Fatalf("response_format 未生成: %s", got)
		}
	})

	t.Run("非法 original 原样返回", func(t *testing.T) {
		body := []byte(`{"model":"m"}`)
		if got := patchClaudeUpstreamBody(body, []byte(`oops`), chat); string(got) != string(body) {
			t.Errorf("坏输入下 body 被改动: %s", got)
		}
	})
}

// ======================== 反向：OpenAI → Anthropic 上游 ========================

// TestOpenAIToAnthropicThinkingBudgetFitsMaxTokens 覆盖一个确定性 400：
// Anthropic 要求 budget_tokens < max_tokens，而缺省 max_tokens 只有 4096。
func TestOpenAIToAnthropicThinkingBudgetFitsMaxTokens(t *testing.T) {
	body := []byte(`{"model":"claude","reasoning_effort":"medium","messages":[{"role":"user","content":"hi"}]}`)
	var got map[string]any
	if err := json.Unmarshal(openAIToAnthropicRequest(body), &got); err != nil {
		t.Fatal(err)
	}
	thinking, _ := got["thinking"].(map[string]any)
	budget := int(thinking["budget_tokens"].(float64))
	maxTokens := int(got["max_tokens"].(float64))
	if maxTokens <= budget {
		t.Fatalf("max_tokens(%d) 必须大于 budget_tokens(%d)，否则 Anthropic 必 400", maxTokens, budget)
	}
}

// TestOpenAIToAnthropicClampsSamplingParams 覆盖另一个确定性 400：
// Anthropic 的 temperature 只接受 [0,1]，OpenAI 客户端常给 >1 的值。
func TestOpenAIToAnthropicClampsSamplingParams(t *testing.T) {
	body := []byte(`{"model":"claude","temperature":1.5,"top_p":1.2,"messages":[{"role":"user","content":"hi"}]}`)
	var got map[string]any
	if err := json.Unmarshal(openAIToAnthropicRequest(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["temperature"] != 1.0 {
		t.Errorf("temperature 未 clamp: %v", got["temperature"])
	}
	if got["top_p"] != 1.0 {
		t.Errorf("top_p 未 clamp: %v", got["top_p"])
	}
}

// TestOpenAIToAnthropicKeepsExplicitZeroTemperature 修的是旧的 `!=0` 判断把显式 0 当未设丢掉。
func TestOpenAIToAnthropicKeepsExplicitZeroTemperature(t *testing.T) {
	body := []byte(`{"model":"claude","temperature":0,"messages":[{"role":"user","content":"hi"}]}`)
	var got map[string]any
	if err := json.Unmarshal(openAIToAnthropicRequest(body), &got); err != nil {
		t.Fatal(err)
	}
	temp, ok := got["temperature"]
	if !ok || temp != 0.0 {
		t.Errorf("显式 temperature:0 被丢弃: %v", got["temperature"])
	}
}

// ======================== count_tokens 估算 ========================

func TestEstimateClaudeInputTokens(t *testing.T) {
	short := estimateClaudeInputTokens([]byte(`{"messages":[{"role":"user","content":"hi"}]}`))
	long := estimateClaudeInputTokens(mustJSON(t, map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": strings.Repeat("这是一段中文测试文本。", 100)}},
	}))
	if short < 1 {
		t.Errorf("估算值必须 >=1，得到 %d", short)
	}
	if long <= short {
		t.Errorf("长文本估算(%d)应大于短文本(%d)", long, short)
	}
	if got := estimateClaudeInputTokens([]byte(`bad json`)); got != 1 {
		t.Errorf("坏输入应回落到 1，得到 %d", got)
	}
}

// ======================== helpers ========================

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// messageBlocks 取出每条 message 的 content 数组，便于断言。
func messageBlocks(t *testing.T, body []byte) [][]map[string]any {
	t.Helper()
	var obj struct {
		Messages []struct {
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	out := make([][]map[string]any, 0, len(obj.Messages))
	for _, m := range obj.Messages {
		out = append(out, m.Content)
	}
	return out
}
