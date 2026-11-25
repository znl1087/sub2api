package oauth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthorizeURLMatchesClaudeCodeCLI(t *testing.T) {
	const want = "https://claude.com/cai/oauth/authorize"
	if AuthorizeURL != want {
		t.Fatalf("AuthorizeURL = %q, want %q", AuthorizeURL, want)
	}
}

// 官方 sst() 在 challenge 不是 43 个 [\w-] 字符时原样返回长链接。
func TestBuildAuthorizationURLShortensOnlyWith43CharChallenge(t *testing.T) {
	const state = "state43"
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"

	// 载荷只有位图 + challenge，不含 state（官方 sst 如此）。
	want := "https://claude.ai/oauth/authorize?T-" + challenge
	if got := BuildAuthorizationURL(state, challenge, ScopeOAuth); got != want {
		t.Fatalf("short link = %q, want %q", got, want)
	}

	for _, bad := range []string{"", "abc", challenge + "x", challenge[:42] + "!", "challenge-value"} {
		got := BuildAuthorizationURL(state, bad, ScopeOAuth)
		if !strings.HasPrefix(got, AuthorizeURL+"?") {
			t.Fatalf("challenge %q must keep the long link, got %q", bad, got)
		}
	}
}

// 官方长链接：URLSearchParams 插入序，冒号 %3A、空格 +。
func TestBuildLongAuthorizationURLMatchesURLSearchParams(t *testing.T) {
	const want = "https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e" +
		"&response_type=code&redirect_uri=https%3A%2F%2Fplatform.claude.com%2Foauth%2Fcode%2Fcallback" +
		"&scope=org%3Acreate_api_key+user%3Aprofile&code_challenge=abc&code_challenge_method=S256&state=s"
	got := buildLongAuthorizationURL("s", "abc", "org:create_api_key user:profile")
	if got != want {
		t.Fatalf("long link = %q, want %q", got, want)
	}
}

// 表外 scope 走 scope 参数；官方 URLSearchParams 会把 ":" 编码成 %3A、空格用 "+"。
func TestBuildAuthorizationURLKeepsUnknownScopes(t *testing.T) {
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"
	const want = "https://claude.ai/oauth/authorize?T-" + challenge +
		"&scope=user%3Adesign%3Aread+user%3Adesign%3Awrite"
	if got := BuildAuthorizationURL("s4", challenge, ScopeOAuth+" user:design:read user:design:write"); got != want {
		t.Fatalf("unknown scope link = %q, want %q", got, want)
	}
}

// 设计 client id 置位 0；其它 client id 不压缩。
func TestShortenAuthorizationURLClientIDBit(t *testing.T) {
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"
	long := buildLongAuthorizationURL("s", challenge, ScopeOAuth)
	design := strings.Replace(long, "client_id="+ClientID, "client_id="+DesignClientID, 1)
	// design id 只在控制台入口被接受，控制台入口保留控制台域名。
	design = strings.Replace(design, AuthorizeURL, ConsoleAuthorizeURL, 1)
	if got, want := shortenAuthorizationURL(design, challenge, ScopeOAuth), ConsoleAuthorizeURL+"?T_"+challenge; got != want {
		t.Fatalf("design client link = %q, want %q", got, want)
	}
	unknown := strings.Replace(long, "client_id="+ClientID, "client_id=00000000-0000-4000-8000-00000000c4a9", 1)
	if got := shortenAuthorizationURL(unknown, challenge, ScopeOAuth); got != unknown {
		t.Fatalf("unknown client id must stay long, got %q", got)
	}
}

// prompt / orgUUID 存在时官方不压缩。
func TestShortenAuthorizationURLGuards(t *testing.T) {
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"
	long := buildLongAuthorizationURL("s", challenge, ScopeOAuth)
	for _, extra := range []string{"&prompt=login", "&orgUUID=abc"} {
		if got := shortenAuthorizationURL(long+extra, challenge, ScopeOAuth); got != long+extra {
			t.Fatalf("%s must stay long, got %q", extra, got)
		}
	}
}

func TestBuildLongAuthorizationURL(t *testing.T) {
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"
	got := BuildLongAuthorizationURL("st", challenge, ScopeOAuth)
	// 长链是回退形态，state 必须在 URL 里，且与短链的载荷互补。
	if !strings.Contains(got, "&state=st") {
		t.Fatalf("long link must carry the state: %q", got)
	}
	if !strings.HasPrefix(got, AuthorizeURL+"?") {
		t.Fatalf("long link must stay on the console origin: %q", got)
	}
	if strings.Contains(got, "?T-"+challenge) {
		t.Fatalf("long link must not be shortened: %q", got)
	}
}

// 附加参数保持原始顺序：重复键不分组，表外 scope 追加到末尾。
func TestShortenKeepsParameterOrder(t *testing.T) {
	const challenge = "VuOB14ATDVoyjSUVMAGhPV8eZIp6LTWG-2HxWZ4VbJE"
	long := buildLongAuthorizationURL("s", challenge, ScopeOAuth+" user:design:read")
	// 交错重复的键 + 两个普通参数。
	long += "&login_hint=a&login_method=sso&login_hint=b"

	got := shortenAuthorizationURL(long, challenge, ScopeOAuth+" user:design:read")
	want := ShortAuthorizeURL + "?T-" + challenge +
		"&login_hint=a&login_method=sso&login_hint=b&scope=user%3Adesign%3Aread"
	if got != want {
		t.Fatalf("short link = %q, want %q", got, want)
	}
}

func TestEncodeScopeBitset(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scopes []string
		want   string
	}{
		{"empty still writes one char", nil, "B"},
		{"first scope is bit 0", []string{"org:create_api_key"}, "D"},
		{"second scope is bit 1", []string{"user:profile"}, "F"},
		{"bit 5 rolls into the next character", []string{"user:file_upload"}, "BB"},
		{"full CLI set", strings.Fields(ScopeOAuth), "T_"},
		{"desktop config is the top bit", []string{"org:desktop_config"}, "gB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, extra := encodeScopeBitset(1, tc.scopes)
			if blob != tc.want || len(extra) != 0 {
				t.Fatalf("blob = %q extra = %v, want %q", blob, extra, tc.want)
			}
		})
	}
}

func TestSessionStore_Stop_Idempotent(t *testing.T) {
	store := NewSessionStore()

	store.Stop()
	store.Stop()

	select {
	case <-store.stopCh:
		// ok
	case <-time.After(time.Second):
		t.Fatal("stopCh 未关闭")
	}
}

func TestSessionStore_Stop_Concurrent(t *testing.T) {
	store := NewSessionStore()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Stop()
		}()
	}

	wg.Wait()

	select {
	case <-store.stopCh:
		// ok
	case <-time.After(time.Second):
		t.Fatal("stopCh 未关闭")
	}
}
