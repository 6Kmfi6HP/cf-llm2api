package main

import (
	"encoding/json"
	"testing"
)

// normalizeToolCallArguments 的契约（对照 CLIProxyAPI claude_openai_request.go:233-248）：
// 合法 JSON object → 规整后透传；非 object 或非法 JSON → 兜底 "{}"；
// 永不返回 error，保证该 tool_call 总会被发出，避免上游本可处理却被本网关抢先 400。
func TestNormalizeToolCallArgumentsFallback(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "{}"},
		{"whitespace", "   ", "{}"},
		{"valid object compact", `{"a":1}`, `{"a":1}`},
		{"valid object normalized spacing", `{"a" : 1, "b": "x"}`, `{"a":1,"b":"x"}`},
		{"nested object", `{"a":{"b":[1,2]}}`, `{"a":{"b":[1,2]}}`},
		// 非法 JSON 一律兜底，不报错
		{"invalid json garbled", `{not json}`, "{}"},
		{"truncated", `{"a":`, "{}"},
		{"literal null", "null", "{}"},
		{"number", "42", "{}"},
		{"string", `"text"`, "{}"},
		{"array", "[1,2,3]", "{}"},
		{"bool", "true", "{}"},
		// 已经是 "{}" 保持不变
		{"bare empty object", "{}", "{}"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeToolCallArguments(c.in)
			if got != c.want {
				t.Fatalf("normalizeToolCallArguments(%q) = %q, want %q", c.in, got, c.want)
			}
			// 不变量：结果必须是合法 JSON 字符串
			var v any
			if err := json.Unmarshal([]byte(got), &v); err != nil {
				t.Fatalf("normalizeToolCallArguments(%q) produced non-JSON %q: %v", c.in, got, err)
			}
		})
	}
}
