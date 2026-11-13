package service

import (
	"bytes"
	"encoding/json"
	"unicode/utf16"
)

// codexTurnMetadataKeyOrder 是真机 x-codex-turn-metadata 的键序（0.167.0 抓包实测）。
// map 序列化是字典序，与真机线序不同；该头整串会原样进上游，键序即指纹。
var codexTurnMetadataKeyOrder = []string{
	"installation_id", "session_id", "thread_id", "agent_name", "turn_id", "window_id",
	"window_number", "context_window_id", "request_kind", "history_initialization",
	"root_turn_id", "thread_source", "turn_trigger", "sandbox", "sandbox_mode",
	"auto_review_enabled", "node_repl_auto_review_required", "node_repl_disabled",
	"turn_started_at_unix_ms", "analytics_enabled", "model", "reasoning_effort",
}

// Turn metadata is also used as an HTTP header, including when carried in WS JSON.
func marshalCodexTurnMetadata(metadata map[string]any) ([]byte, error) {
	raw, err := marshalCodexOrderedObject(metadata, codexTurnMetadataKeyOrder)
	if err != nil {
		return nil, err
	}
	for i, b := range raw {
		if b < 0x7f {
			continue
		}
		out := make([]byte, 0, len(raw)+16)
		out = append(out, raw[:i]...)
		appendEscape := func(r rune) {
			const hex = "0123456789abcdef"
			out = append(out, '\\', 'u', hex[r>>12&15], hex[r>>8&15], hex[r>>4&15], hex[r&15])
		}
		for _, r := range string(raw[i:]) {
			switch {
			case r < 0x7f:
				out = append(out, byte(r))
			case r <= 0xffff:
				appendEscape(r)
			default:
				high, low := utf16.EncodeRune(r)
				appendEscape(high)
				appendEscape(low)
			}
		}
		return out, nil
	}
	return raw, nil
}

// marshalCodexOrderedObject 按 prefer 给定的键序序列化对象，未列出的键按字典序追加在尾部。
// 键序是 JSON 对象可观测的特征，真机字段序固定，不能交给 map 的字典序。
func marshalCodexOrderedObject(obj map[string]any, prefer []string) ([]byte, error) {
	keys := make([]string, 0, len(obj))
	seen := make(map[string]bool, len(obj))
	for _, key := range prefer {
		if _, ok := obj[key]; ok {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	rest := make([]string, 0, len(obj))
	for key := range obj {
		if !seen[key] {
			rest = append(rest, key)
		}
	}
	sortStrings(rest)
	keys = append(keys, rest...)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		valueJSON, err := json.Marshal(obj[key])
		if err != nil {
			return nil, err
		}
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// sortStrings 是最小插入排序：metadata 键数很少，避免为此引入 sort 依赖面。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
