// Package oauth provides helpers for OAuth flows used by this service.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Claude OAuth Constants
const (
	// OAuth Client ID for Claude
	ClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

	// OAuth endpoints. AuthorizeURL is the console origin the CLI builds the
	// authorize link on before shortening it; ShortAuthorizeURL is the origin the
	// shortened link is rewritten to (see BuildAuthorizationURL).
	AuthorizeURL      = "https://platform.claude.com/oauth/authorize"
	ShortAuthorizeURL = "https://claude.ai/oauth/authorize"
	TokenURL          = "https://platform.claude.com/v1/oauth/token"
	RedirectURI       = "https://platform.claude.com/oauth/code/callback"

	// Scopes - Browser URL (includes org:create_api_key for user authorization)
	ScopeOAuth = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
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
// org:desktop_config last; it is not the ScopeOAuth order.
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

// OAuthSession stores OAuth flow state

type OAuthSession struct {
	State        string    `json:"state"`
	CodeVerifier string    `json:"code_verifier"`
	Scope        string    `json:"scope"`
	ProxyURL     string    `json:"proxy_url,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
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

// BuildAuthorizationURL builds the OAuth authorization URL with correct parameter order.
//
// The result has the shape of a real Claude Code 2.1.33x authorize link:
// `https://claude.ai/oauth/authorize?<scope blob>&code_challenge=…&state=…`.
// With the full scope set that is 174 characters, exactly as short as the CLI's
// link, so no client-side long-link escape hatch is needed.
func BuildAuthorizationURL(state, codeChallenge, scope string) string {
	blob, extra := EncodeScopeBitset(strings.Fields(scope))

	query := blob + "&code_challenge=" + codeChallenge + "&state=" + state
	if len(extra) > 0 {
		query += "&scope=" + strings.ReplaceAll(url.QueryEscape(strings.Join(extra, " ")), "%20", "+")
	}
	return ShortAuthorizeURL + "?" + query
}

// EncodeScopeBitset packs scopes into the CLI's short-link scope bitmap.
//
// Claude Code 2.1.330 stopped emitting the authorize link as a plain query
// string. It keeps only `code_challenge` and `state` and moves the rest into a
// base64url blob in front of them, where client_id / response_type / redirect_uri
// / code are implied by the endpoint and the scopes are a little-endian bitmask
// (bit i = the i-th entry of shortLinkScopes). Scopes outside that table fall
// back to a plain `scope` parameter.
//
// It mirrors the CLI byte for byte: bits accumulate into one number, at least one
// base64url character is always written, and the value is big-endian in the
// alphabet.
func EncodeScopeBitset(scopes []string) (string, []string) {
	bits := 0
	var extra []string
	for _, scope := range scopes {
		index := -1
		for i, known := range shortLinkScopes {
			if known == scope {
				index = i
				break
			}
		}
		if index == -1 {
			extra = append(extra, scope)
			continue
		}
		bits |= 2 << index
	}
	// At least one character: an empty bitset still encodes as "A".
	blob := ""
	for {
		blob = string(scopeBitsetAlphabet[bits%64]) + blob
		bits >>= 6
		if bits == 0 {
			break
		}
	}
	return blob, extra
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
