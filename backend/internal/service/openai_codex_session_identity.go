package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// 本文件把「客户端没带、但真实 Codex 客户端一定会带」的会话身份补齐到出站请求上。
//
// 背景：codex-cli 0.167.0 的推理面固定携带 x-codex-window-id / x-codex-turn-metadata /
// x-client-request-id / session-id / thread-id 与 x-codex-beta-features。经 sub2api 转发的
// 第三方客户端（以及 compat 桥接）未必带这些头，出站报文因此缺项，与真机形态不符。
//
// 原则：**只补缺，不覆盖**。客户端自带的值是真实会话标识，必须原样到达上游；
// 这里只为缺失项按同一份会话标识派生，保证 session-id / thread-id / window-id /
// turn-metadata 内部自洽（上游会交叉核对这些字段）。

// codexSessionIdentity 是一次出站请求的会话身份，全部字段同源派生。
type codexSessionIdentity struct {
	sessionID      string
	threadID       string
	turnID         string
	windowID       string
	installationID string
	contextWindow  string
	turnStartedAt  int64
}

// resolveCodexSessionIdentity 从现有请求头推导会话身份。
// 优先沿用客户端已带的 session/thread，保证同一 Codex 会话在多次 turn 间稳定；
// 全缺时才新铸一组。返回值永不为 nil。
func resolveCodexSessionIdentity(h http.Header) *codexSessionIdentity {
	threadID := strings.TrimSpace(h.Get("thread-id"))
	sessionID := extractClientSessionID(h)
	if sessionID == "" {
		sessionID = strings.TrimSpace(h.Get("x-client-request-id"))
	}
	if threadID == "" {
		threadID = sessionID
	}
	if sessionID == "" {
		sessionID = threadID
	}
	if sessionID == "" {
		sessionID = uuid.Must(uuid.NewV7()).String()
	}
	if threadID == "" {
		threadID = sessionID
	}

	windowID := strings.TrimSpace(h.Get("x-codex-window-id"))
	// 会话标识可能已被 isolateOpenAIUpstreamSessionID 改写（跨用户隔离），此时客户端
	// 带来的 window-id 仍指向旧 session-id。window-id 是 `{thread_id}:{n}` 形态，前半段
	// 必须与最终 thread-id 一致，否则上游能看出两者不是同一会话。
	if windowID == "" || strings.SplitN(windowID, ":", 2)[0] != threadID {
		windowID = threadID + ":0"
	}

	return &codexSessionIdentity{
		sessionID:      sessionID,
		threadID:       threadID,
		turnID:         uuid.Must(uuid.NewV7()).String(),
		windowID:       windowID,
		installationID: strings.TrimSpace(h.Get("x-codex-installation-id")),
		contextWindow:  uuid.Must(uuid.NewV7()).String(),
		turnStartedAt:  time.Now().UnixMilli(),
	}
}

// newCodexTurnMetadata 构建与真机同构的 x-codex-turn-metadata。
// sandbox / sandboxMode / model / effort 取自本次请求；缺失时用真机默认值，
// 保证 metadata 始终是完整对象而不是部分键。
func newCodexTurnMetadata(identity *codexSessionIdentity, sandbox, sandboxMode, model, effort string) map[string]any {
	if sandbox == "" {
		sandbox = "windows_elevated"
	}
	if sandboxMode == "" {
		sandboxMode = "read-only"
	}
	if effort == "" {
		effort = "xhigh"
	}
	return map[string]any{
		"installation_id":                identity.installationID,
		"session_id":                     identity.sessionID,
		"thread_id":                      identity.threadID,
		"agent_name":                     "/root",
		"turn_id":                        identity.turnID,
		"window_id":                      identity.windowID,
		"window_number":                  0,
		"context_window_id":              identity.contextWindow,
		"request_kind":                   "turn",
		"history_initialization":         "new",
		"root_turn_id":                   identity.turnID,
		"thread_source":                  "user",
		"turn_trigger":                   "exec",
		"sandbox":                        sandbox,
		"sandbox_mode":                   sandboxMode,
		"auto_review_enabled":            false,
		"node_repl_auto_review_required": true,
		"node_repl_disabled":             false,
		"turn_started_at_unix_ms":        identity.turnStartedAt,
		"analytics_enabled":              true,
		"model":                          model,
		"reasoning_effort":               effort,
	}
}

// ensureCodexSessionHeaders 为缺失的会话身份头补值。必须在所有 UA / 身份改写之后、
// 请求发出之前调用；已存在的头一律保留。
//
// 只对 OAuth（ChatGPT 内部接口）路径生效：compat 桥接与 API-key 直连上游的报文形态
// 与 Codex 推理面不同，补这些头反而会制造新的不一致。
func ensureCodexSessionHeaders(h http.Header, body []byte) {
	if h == nil || h.Get("originator") == "" {
		return
	}

	identity := resolveCodexSessionIdentity(h)
	if identity.installationID == "" {
		identity.installationID = uuid.NewString()
	}

	missing := func(key string) bool { return strings.TrimSpace(h.Get(key)) == "" }

	if missing("session-id") {
		h.Set("session-id", identity.sessionID)
	}
	if missing("thread-id") {
		h.Set("thread-id", identity.threadID)
	}
	if missing("x-client-request-id") {
		h.Set("x-client-request-id", identity.threadID)
	}
	// window-id 是 `{thread_id}:{n}` 形态，前半段必须等于最终 thread-id。客户端带来的值
	// 在会话被隔离改写后前缀就对不上了，因此按前缀一致性而非「是否缺失」判断。
	if existing := strings.TrimSpace(h.Get("x-codex-window-id")); existing == "" ||
		strings.SplitN(existing, ":", 2)[0] != identity.threadID {
		h.Set("x-codex-window-id", identity.windowID)
	}
	if missing("x-codex-installation-id") {
		h.Set("x-codex-installation-id", identity.installationID)
	}
	// x-codex-beta-features 是会话级能力声明，真机每个推理请求都带。
	if missing("x-codex-beta-features") {
		h.Set("x-codex-beta-features", openAIRemoteCompactionV2Feature)
	}

	if missing("x-codex-turn-metadata") {
		metadata := newCodexTurnMetadata(
			identity,
			codexRequestSandbox(body),
			"",
			gjson.GetBytes(body, "model").String(),
			gjson.GetBytes(body, "reasoning.effort").String(),
		)
		if raw, err := marshalCodexTurnMetadata(metadata); err == nil {
			h.Set("x-codex-turn-metadata", string(raw))
		}
	}

	// metadata 内嵌的会话三元组必须等于最终出站头。客户端带来的 metadata 属于改写前的
	// 会话（session-id 被跨用户隔离替换过），直接透传会出现「头是 A、metadata 写 B」，
	// 上游可据此判定拼接。
	syncCodexTurnMetadataIdentity(h, identity)
	// body 里那份 metadata 是同一串字节，一并跟随（存在才改）。
}

// syncCodexTurnMetadataIdentity 把 metadata 里指向旧会话的字段拉到当前出站身份。
// window_id 的前半段同样必须等于 thread-id。
func syncCodexTurnMetadataIdentity(h http.Header, identity *codexSessionIdentity) {
	if h == nil || identity == nil {
		return
	}
	raw := strings.TrimSpace(h.Get("x-codex-turn-metadata"))
	if raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		return
	}
	changed := false
	setField := func(key, want string) {
		if want == "" {
			return
		}
		if cur, _ := metadata[key].(string); cur == want {
			return
		}
		metadata[key] = want
		changed = true
	}
	setField("session_id", identity.sessionID)
	setField("thread_id", identity.threadID)
	setField("window_id", identity.windowID)
	// turn_id / root_turn_id 是每轮新铸的值，客户端自带的即合法，不必跟随隔离改写。
	if !changed {
		return
	}
	if rebuilt, err := marshalCodexTurnMetadata(metadata); err == nil {
		h.Set("x-codex-turn-metadata", string(rebuilt))
	}
}

// codexRequestSandbox 从 body 的 permissions/sandbox 声明推导真机的 sandbox 命名。
// 取不到时返回空串，由调用方填默认值。
func codexRequestSandbox(body []byte) string {
	if gjson.GetBytes(body, "permissions.sandbox").Exists() || gjson.GetBytes(body, "sandbox").Exists() {
		return "windows_elevated"
	}
	return ""
}

// ensureCodexReasoningContext 为带 reasoning 的请求补 reasoning.context="all_turns"。
// 真机在带 reasoning 时固定声明该字段（0.167.0 实测），缺失即为可识别的旧形态。
// 已有值保留；无 reasoning 对象时不创建，避免给不支持的上游塞未知字段。
func ensureCodexReasoningContext(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}
	reasoning := gjson.GetBytes(body, "reasoning")
	if !reasoning.Exists() || !reasoning.IsObject() {
		return body, false
	}
	if strings.TrimSpace(reasoning.Get("context").String()) != "" {
		return body, false
	}
	next, err := sjson.SetBytes(body, "reasoning.context", "all_turns")
	if err != nil {
		return body, false
	}
	return next, true
}

// ensureCodexConfigurationUpdate 在 input 末尾补真机固定的收尾项
// `{"type":"configuration_update","reasoning":{"effort":"<effort>"}}`（0.167.0 实测：
// 每个推理请求的最后一项都是它）。已有同类型尾项时只校验键序，不重复追加。
//
// 键序按真机书写（type 在前）。客户端多经 map 序列化，键序是字典序（reasoning 在前），
// 与真机线序不符，因此已存在也要重写字节。
func ensureCodexConfigurationUpdate(body []byte) ([]byte, bool) {
	if len(body) == 0 {
		return body, false
	}
	input := gjson.GetBytes(body, "input")
	if !input.Exists() || !input.IsArray() {
		return body, false
	}
	items := input.Array()
	if len(items) == 0 {
		return body, false
	}
	tail := items[len(items)-1]
	hasTail := tail.Get("type").String() == "configuration_update"

	effort := strings.TrimSpace(tail.Get("reasoning.effort").String())
	if effort == "" {
		effort = strings.TrimSpace(gjson.GetBytes(body, "reasoning.effort").String())
	}
	if effort == "" {
		return body, false
	}

	item := []byte(`{"type":"configuration_update","reasoning":{"effort":` + strconv.Quote(effort) + `}}`)
	if hasTail && string(tail.Raw) == string(item) {
		return body, false
	}

	// 走文本拼接而非 sjson.SetRawBytes：后者会把 raw 重新解析成 map 再序列化，
	// 键序被字典序打乱（type 会跑到 reasoning 后面），与真机线序不符。
	arrIdx := int(input.Index)
	arrEnd := arrIdx + len(input.Raw)
	if arrIdx < 0 || arrEnd <= arrIdx || body[arrEnd-1] != ']' {
		return body, false
	}
	// prefixEnd 指向「要保留的字节」长度：追加时停在数组的 ']'，覆盖时停在新项原起点
	// （两者都保留前置逗号，因此拼接处无需再补分隔符）。
	prefixEnd := arrEnd - 1
	needComma := false
	if hasTail {
		itemIdx := int(tail.Index)
		if itemIdx <= arrIdx || itemIdx >= arrEnd {
			return body, false
		}
		prefixEnd = itemIdx
	} else if len(bytes.TrimSpace(body[arrIdx+1:arrEnd-1])) > 0 {
		needComma = true
	}
	out := make([]byte, 0, len(body)+len(item)+1)
	out = append(out, body[:prefixEnd]...)
	if needComma {
		out = append(out, ',')
	}
	out = append(out, item...)
	out = append(out, body[arrEnd-1:]...) // 从数组收尾的 ']' 起，保留结构
	return out, true
}

// syncCodexBodySessionIdentity 把 body 里的会话声明拉到最终出站身份。
//
// 顺序问题：client_metadata 的补齐早于 session-id 的跨用户隔离改写，因此 body 记录的是
// 改写前的会话；而真机的头、metadata、client_metadata、prompt_cache_key 四者恒等。
// 不跟随就会留下「头说 A、体说 B」的拼接痕迹。只在确实存在对应字段时改，不新造。
func syncCodexBodySessionIdentity(body []byte, h http.Header) ([]byte, bool) {
	if len(body) == 0 || h == nil {
		return body, false
	}
	threadID := strings.TrimSpace(h.Get("thread-id"))
	sessionID := strings.TrimSpace(h.Get("session-id"))
	if sessionID == "" {
		sessionID = threadID
	}
	if threadID == "" {
		threadID = sessionID
	}
	if threadID == "" {
		return body, false
	}
	windowID := threadID + ":0"
	changed := false
	setIfPresent := func(path, want string) {
		cur := gjson.GetBytes(body, path)
		if !cur.Exists() || cur.String() == want {
			return
		}
		if next, err := sjson.SetBytes(body, path, want); err == nil {
			body, changed = next, true
		}
	}
	setIfPresent("client_metadata.session_id", sessionID)
	setIfPresent("client_metadata.thread_id", threadID)
	setIfPresent("client_metadata.x-codex-window-id", windowID)
	// prompt_cache_key 不跟随：真机它与 session 同值，但第三方客户端的缓存键是独立语义，
	// 上游已按它做前缀缓存，改写成派生值会丢命中。
	if meta := strings.TrimSpace(h.Get("x-codex-turn-metadata")); meta != "" {
		setIfPresent("client_metadata.x-codex-turn-metadata", meta)
	}
	return body, changed
}

// codexBodyKeyOrder 是真机推理请求 body 的顶层键线序（codex-cli 0.167.0 实测）。
// Go map 序列化是字典序，与真机顺序不同，是可直接区分的指纹。
var codexBodyKeyOrder = []string{
	"model", "stream", "service_tier", "input", "tool_choice", "parallel_tool_calls",
	"reasoning", "store", "include", "prompt_cache_key", "text", "client_metadata",
}

// canonicalizeCodexBodyKeyOrder 按真机线序重排 body 顶层键。
// 已知键按固定顺序输出，未知键保持原有相对顺序追加在尾部（不丢弃）。
// 键序已正确时返回 changed=false，避免无谓的字节重写。
func canonicalizeCodexBodyKeyOrder(body []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return body, false, nil
	}

	type kv struct {
		key string
		val json.RawMessage
	}
	order := make([]string, 0, len(codexBodyKeyOrder))
	values := make(map[string]json.RawMessage, len(codexBodyKeyOrder))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return body, false, err
		}
		key, ok := tok.(string)
		if !ok {
			return body, false, nil
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return body, false, err
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = val
	}

	current := append([]string(nil), order...)
	wanted := make([]string, 0, len(order))
	for _, key := range codexBodyKeyOrder {
		if _, ok := values[key]; ok {
			wanted = append(wanted, key)
		}
	}
	for _, key := range order {
		if !slices.Contains(codexBodyKeyOrder, key) {
			wanted = append(wanted, key)
		}
	}
	if slices.Equal(current, wanted) {
		return body, false, nil
	}

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range wanted {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return body, false, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(values[key])
	}
	buf.WriteByte('}')
	return buf.Bytes(), true, nil
}

// ensureCodexClientMetadataBody 为 body 补齐 client_metadata 中真机必带的键。
// 已存在的键保留客户端原值；只补缺失项，且与请求头共用同一份会话身份。
func ensureCodexClientMetadataBody(body []byte, h http.Header) ([]byte, bool) {
	if len(body) == 0 || h == nil || h.Get("originator") == "" {
		return body, false
	}
	existing := gjson.GetBytes(body, "client_metadata")
	if !existing.Exists() {
		return body, false
	}

	identity := resolveCodexSessionIdentity(h)
	if identity.installationID == "" {
		if v := strings.TrimSpace(h.Get("x-codex-installation-id")); v != "" {
			identity.installationID = v
		} else {
			identity.installationID = uuid.NewString()
		}
	}

	// 真机 client_metadata 的值**全部是字符串**（含 mcp_attribution 与
	// guardian_credits_requested:"true"），内层 JSON 以字符串形式嵌入，不是对象。
	pairs := [][2]string{
		{"session_id", identity.sessionID},
		{"thread_id", identity.threadID},
		{"root_turn_id", identity.turnID},
		{"turn_id", identity.turnID},
		{"x-codex-installation-id", identity.installationID},
		{"x-codex-window-id", identity.windowID},
		{"guardian_credits_requested", "true"},
		{"mcp_attribution", `{"status":"none"}`},
	}

	changed := false
	for _, pair := range pairs {
		if gjson.GetBytes(body, "client_metadata."+pair[0]).Exists() {
			continue
		}
		if next, err := sjson.SetBytes(body, "client_metadata."+pair[0], pair[1]); err == nil {
			body, changed = next, true
		}
	}
	if changed {
		if meta := strings.TrimSpace(h.Get("x-codex-turn-metadata")); meta != "" &&
			!gjson.GetBytes(body, "client_metadata.x-codex-turn-metadata").Exists() {
			if next, err := sjson.SetBytes(body, "client_metadata.x-codex-turn-metadata", meta); err == nil {
				body = next
			}
		}
	}
	return body, changed
}
