package oauth

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthorizeURLMatchesClaudeCodeCLI(t *testing.T) {
	const want = "https://claude.ai/oauth/authorize"
	if ShortAuthorizeURL != want {
		t.Fatalf("ShortAuthorizeURL = %q, want %q", ShortAuthorizeURL, want)
	}

	// The full scope set must decode from "B-"; the first bit stays set because
	// the CLI ORs 1 for a console client.
	authURL := BuildAuthorizationURL("state-value", "challenge-value", ScopeOAuth)
	wantURL := want + "?B-&code_challenge=challenge-value&state=state-value"
	if authURL != wantURL {
		t.Fatalf("BuildAuthorizationURL() = %q, want %q", authURL, wantURL)
	}
	// Real PKCE values: the CLI's link stays short enough to fit in chat.
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatal(err)
	}
	realURL := BuildAuthorizationURL(verifier, GenerateCodeChallenge(verifier), ScopeOAuth)
	if len(realURL) > 200 {
		t.Fatalf("authorize URL length = %d, want <= 200", len(realURL))
	}
}

func TestEncodeScopeBitset(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scopes []string
		want   string
		extra  []string
	}{
		{"empty still writes one char", nil, "A", nil},
		{"first scope is bit 0", []string{"org:create_api_key"}, "C", nil},
		{"second scope is bit 1", []string{"user:profile"}, "E", nil},
		{"bit 5 rolls into the next character", []string{"user:file_upload"}, "BA", nil},
		{"full CLI set", strings.Fields(ScopeOAuth), "B-", nil},
		{"desktop config is the top bit", []string{"org:desktop_config"}, "gA", nil},
		{"unknown scopes fall through", []string{"user:inference", "user:design:read"}, "I", []string{"user:design:read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob, extra := EncodeScopeBitset(tc.scopes)
			if blob != tc.want {
				t.Fatalf("blob = %q, want %q", blob, tc.want)
			}
			if strings.Join(extra, " ") != strings.Join(tc.extra, " ") {
				t.Fatalf("extra = %v, want %v", extra, tc.extra)
			}
		})
	}
}

func TestBuildAuthorizationURLKeepsUnknownScopesAsParameter(t *testing.T) {
	authURL := BuildAuthorizationURL("st", "ch", ScopeOAuth+" user:design:read")
	if !strings.HasSuffix(authURL, "&scope=user%3Adesign%3Aread") {
		t.Fatalf("unknown scope must survive as a scope parameter, got %q", authURL)
	}
}

func TestBuildAuthorizationURLSetupToken(t *testing.T) {
	authURL := BuildAuthorizationURL("st", "ch", ScopeInference)
	if authURL != ShortAuthorizeURL+"?I&code_challenge=ch&state=st" {
		t.Fatalf("setup-token URL = %q", authURL)
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
