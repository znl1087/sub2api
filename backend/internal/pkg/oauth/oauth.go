// Package oauth provides helpers for OAuth flows used by this service.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Claude OAuth Constants
const (
	// OAuth Client ID for Claude
	ClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	// DesignClientID is the CLI's second client id, the only other one the
	// console authorize endpoint accepts; it sets the short link's bit 0. It is
	// the CLI's `_vt`, which is not DESIGN_CLIENT_ID.
	DesignClientID = "41077d10-94b8-4194-be48-d251e9eb21b4"

	// OAuth endpoints, straight from the CLI's endpoint table. AuthorizeURL is
	// the claude.ai sign-in the CLI builds on; ConsoleAuthorizeURL is the
	// organization sign-in. A shortened claude.ai link lands on ShortAuthorizeURL,
	// a shortened console link keeps its own origin.
	AuthorizeURL        = "https://claude.com/cai/oauth/authorize"
	ConsoleAuthorizeURL = "https://platform.claude.com/oauth/authorize"
	ShortAuthorizeURL   = "https://claude.ai/oauth/authorize"
	TokenURL            = "https://platform.claude.com/v1/oauth/token"
	RedirectURI         = "https://platform.claude.com/oauth/code/callback"

	// Scopes - Browser URL (includes org:create_api_key for user authorization).
	// Ordered exactly like the CLI's own authorize scope list, which is also the
	// short-link bit order. The CLI appends user:projects:read/write only when
	// projects are registered, so the default login flow does not request them.
	ScopeOAuth = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins user:privacy_consents:write"
	// Scopes - Internal API call (org:create_api_key not supported in API)
	ScopeAPI = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	// Scopes - Setup token (inference only)
	ScopeInference = "user:inference"

	// Session TTL
	SessionTTL = 30 * time.Minute
)

// shortLinkScopes is the CLI's ordered scope table for its short authorize
// link: each scope's index is its bit position in the base64url scope bitmap.
// The order and content are byte-for-byte the CLI's array, including
// org:desktop_config last; it is not the ScopeOAuth order (ScopeOAuth omits
// the optional tail).
var shortLinkScopes = []string{
	"org:create_api_key",
	"user:profile",
	"user:inference",
	"user:sessions:claude_code",
	"user:mcp_servers",
	"user:file_upload",
	"user:plugins",
	"user:projects:read",
	"user:projects:write",
	"user:privacy_consents:write",
	"org:desktop_config",
}

// scopeBitsetAlphabet is the CLI's base64url alphabet for the scope bitmap.
const scopeBitsetAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// shortLinkChallengePattern is the CLI's guard on the challenge: anything that
// is not exactly 43 URL-safe characters leaves the link long.
var shortLinkChallengePattern = regexp.MustCompile(`^[\w-]{43}$`)

// OAuthSession stores OAuth flow state

type OAuthSession struct {
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	Scope        string `json:"scope"`
	ProxyURL     string `json:"proxy_url,omitempty"`
	// LongLink records that the link handed to the user was the full one. The
	// short link never carries the state to the authorize page, so only a long
	// link makes a mismatching pasted state meaningful.
	LongLink  bool      `json:"long_link,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// SessionStore manages OAuth sessions in memory
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*OAuthSession
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*OAuthSession),
		stopCh:   make(chan struct{}),
	}
	go store.cleanup()
	return store
}

// Stop stops the cleanup goroutine
func (s *SessionStore) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// Set stores a session
func (s *SessionStore) Set(sessionID string, session *OAuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
}

// Get retrieves a session
func (s *SessionStore) Get(sessionID string) (*OAuthSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	if time.Since(session.CreatedAt) > SessionTTL {
		return nil, false
	}
	return session, true
}

// Delete removes a session
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// cleanup removes expired sessions periodically
func (s *SessionStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.mu.Lock()
			for id, session := range s.sessions {
				if time.Since(session.CreatedAt) > SessionTTL {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateState generates a random state string for OAuth (base64url encoded)
func GenerateState() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

// GenerateSessionID generates a unique session ID
func GenerateSessionID() (string, error) {
	bytes, err := GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GenerateCodeVerifier generates a PKCE code verifier (RFC 7636).
// Uses 32 random bytes → base64url-no-pad, producing a 43-char verifier.
func GenerateCodeVerifier() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64URLEncode(bytes), nil
}

// GenerateCodeChallenge generates a PKCE code challenge using S256 method
func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64URLEncode(hash[:])
}

// base64URLEncode encodes bytes to base64url without padding
func base64URLEncode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

// BuildAuthorizationURL builds the OAuth authorization URL the way Claude Code
// 2.1.33x does, in two steps: build the full link (the CLI's mjs), then shorten
// it (the CLI's sst). The shortened result is
// `https://claude.ai/oauth/authorize?<scope bitmap>&code_challenge=…&state=…`,
// 174 characters for the full scope set — the same length the CLI produces.
//
// The short form is a pure rewrite of the long one, so every condition the CLI
// checks is reproduced here; when one fails the long link is returned verbatim,
// exactly like the CLI.
func BuildAuthorizationURL(state, codeChallenge, scope string) string {
	long := buildLongAuthorizationURL(state, codeChallenge, scope)
	return shortenAuthorizationURL(long, codeChallenge, scope)
}

// BuildLongAuthorizationURL always returns the full authorize link. The short
// form drops the state, so this is the fallback for flows that need the state in
// the URL (and the shape the CLI emits with CLAUDE_CODE_FULL_SIGN_IN_LINK=1).
func BuildLongAuthorizationURL(state, codeChallenge, scope string) string {
	return buildLongAuthorizationURL(state, codeChallenge, scope)
}

// buildLongAuthorizationURL mirrors the CLI's mjs: a URLSearchParams built in
// the CLI's insertion order and serialized by the same rules as the short
// form's leftovers.
func buildLongAuthorizationURL(state, codeChallenge, scope string) string {
	pairs := [][2]string{
		{"code", "true"},
		{"client_id", ClientID},
		{"response_type", "code"},
		{"redirect_uri", RedirectURI},
		{"scope", scope},
		{"code_challenge", codeChallenge},
		{"code_challenge_method", "S256"},
		{"state", state},
	}
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, url.QueryEscape(pair[0])+"="+url.QueryEscape(pair[1]))
	}
	return AuthorizeURL + "?" + strings.Join(parts, "&")
}

// shortenAuthorizationURL mirrors the CLI's sst. Guards, in the CLI's order:
//
//   - the client id must be one of the two the CLI recognises for the console
//     endpoint (the main id leaves bit 0 clear, the design id sets it);
//   - the challenge must be 43 URL-safe characters;
//   - code, response_type, redirect_uri and code_challenge_method must hold the
//     CLI's exact values;
//   - prompt and orgUUID must be absent, otherwise the parameter order is not
//     the one the format assumes.
//
// The scope is then folded into a little-endian bitmap (bit i = the i-th entry
// of shortLinkScopes, ORed with 2<<i; bit 0 is the client id marker) and
// rendered big-endian in base64url, at least one character. Scopes outside the
// table come back as a plain scope parameter. client_id, scope, code_challenge
// and state are removed from the query, and code_challenge and state are
// re-appended after the bitmap.
func shortenAuthorizationURL(long, codeChallenge, scope string) string {
	parsed, err := url.Parse(long)
	if err != nil {
		return long
	}
	base := parsed.Scheme + "://" + parsed.Host + parsed.Path
	// The console endpoint only accepts the two known client ids; the claude.ai
	// endpoint keeps the order-independent path below.
	console := base == ConsoleAuthorizeURL
	if !console && base != AuthorizeURL {
		return long
	}
	params := parsed.Query()

	// Bit 0 marks the client id; the main id leaves it clear. On the console
	// endpoint the design id is the only other accepted client.
	clientBit := 0
	switch params.Get("client_id") {
	case ClientID:
	case DesignClientID:
		if !console {
			return long
		}
		clientBit = 1
	default:
		return long
	}
	if !shortLinkChallengePattern.MatchString(codeChallenge) {
		return long
	}
	if params.Get("code") != "true" || params.Get("response_type") != "code" ||
		params.Get("redirect_uri") != RedirectURI || params.Get("code_challenge_method") != "S256" {
		return long
	}
	if params.Has("prompt") || params.Has("orgUUID") {
		return long
	}

	blob, extra := encodeScopeBitset(clientBit, strings.Fields(params.Get("scope")))

	// URLSearchParams is an ordered list, so the query is carried through as one:
	// deletions drop every entry of a key, and a re-added scope is appended last.
	// Duplicated keys keep their interleaving.
	pairs := orderedPairs(long)
	pairs = deleteKeys(pairs, "client_id", "scope", "code_challenge", "state")
	pairs = deleteKeys(pairs, "code", "response_type", "redirect_uri", "code_challenge_method")
	if len(extra) > 0 {
		pairs = append(pairs, [2]string{"scope", strings.Join(extra, " ")})
	}

	// The CLI's payload is exactly the bitmap plus the challenge. The state is
	// not in the link: the client keeps it locally and sends it at exchange.
	origin := parsed.Scheme + "://" + parsed.Host
	path := parsed.Path
	if !console {
		origin = ShortAuthorizeURL
		path = ""
	}
	shortened := origin + path + "?" + blob + codeChallenge
	if rest := searchParamsEncode(pairs); rest != "" {
		shortened += "&" + rest
	}
	return shortened
}

// orderedPairs splits a URL's query into decoded key/value pairs, keeping the
// original order and every duplicate.
func orderedPairs(rawURL string) [][2]string {
	query := rawURL
	if idx := strings.IndexByte(query, '?'); idx != -1 {
		query = query[idx+1:]
	}
	pairs := make([][2]string, 0, strings.Count(query, "&")+1)
	for _, field := range strings.Split(query, "&") {
		if field == "" {
			continue
		}
		key, value, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(key)
		if err != nil {
			continue
		}
		if value, err = url.QueryUnescape(value); err != nil {
			continue
		}
		pairs = append(pairs, [2]string{key, value})
	}
	return pairs
}

// deleteKeys drops every pair whose key is listed.
func deleteKeys(pairs [][2]string, keys ...string) [][2]string {
	drop := make(map[string]bool, len(keys))
	for _, key := range keys {
		drop[key] = true
	}
	kept := pairs[:0]
	for _, pair := range pairs {
		if !drop[pair[0]] {
			kept = append(kept, pair)
		}
	}
	return kept
}

// orderedLeftovers rebuilds the surviving query parameters in their original
// order, taking the values from params.
func orderedLeftovers(long string, params url.Values) url.Values {
	ordered := url.Values{}
	query := long
	if idx := strings.IndexByte(query, '?'); idx != -1 {
		query = query[idx+1:]
	}
	for _, pair := range strings.Split(query, "&") {
		if pair == "" {
			continue
		}
		key, _, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(key)
		if err != nil {
			continue
		}
		if _, kept := params[key]; !kept {
			continue
		}
		if _, seen := ordered[key]; seen {
			continue
		}
		ordered[key] = params[key]
	}
	return ordered
}

// searchParamsEncode serializes a query the way URLSearchParams#toString does:
// keys in insertion order, ":" left alone, a space as "+", and any other byte
// outside the spec's safe set percent-encoded.
//
// url.Values is a map and loses the order, so callers that care about it pass
// an explicit key order; leftover keys keep their map order, which is what the
// CLI does too.
func searchParamsEncode(pairs [][2]string) string {
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, searchParamsEscape(pair[0])+"="+searchParamsEscape(pair[1]))
	}
	return strings.Join(parts, "&")
}

// searchParamsEscape applies the URLSearchParams percent-encode set to one
// component: everything but the ASCII alphanumerics and `* - . _` is escaped,
// except that a space becomes "+".
func searchParamsEscape(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// encodeScopeBitset folds the client marker bit and the scopes into the bitmap
// and returns the base64url rendering plus the scopes outside the table. At
// least one character is always written: an empty bitmap encodes as "A".
func encodeScopeBitset(clientBit int, scopes []string) (string, []string) {
	bits := clientBit
	var extra []string
	for _, scope := range scopes {
		bit, known := scopeBit(scope)
		if !known {
			extra = append(extra, scope)
			continue
		}
		bits |= bit
	}
	var blob []byte
	for {
		blob = append([]byte{scopeBitsetAlphabet[bits%64]}, blob...)
		bits >>= 6
		if bits == 0 {
			break
		}
	}
	return string(blob), extra
}

// scopeBit returns the bitmap bit for a scope: 2 << its index in
// shortLinkScopes.
func scopeBit(scope string) (int, bool) {
	for i, known := range shortLinkScopes {
		if known == scope {
			return 2 << i, true
		}
	}
	return 0, false
}

// TokenResponse represents the token response from OAuth provider
type TokenResponse struct {
	AccessToken  string       `json:"access_token"`
	TokenType    string       `json:"token_type"`
	ExpiresIn    int64        `json:"expires_in"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	Scope        string       `json:"scope,omitempty"`
	Organization *OrgInfo     `json:"organization,omitempty"`
	Account      *AccountInfo `json:"account,omitempty"`
}

// OrgInfo represents organization info from OAuth response
type OrgInfo struct {
	UUID string `json:"uuid"`
}

// AccountInfo represents account info from OAuth response
type AccountInfo struct {
	UUID         string `json:"uuid"`
	EmailAddress string `json:"email_address"`
}
