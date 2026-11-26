package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

// KV key prefixes. Secrets (codes and tokens) appear in keys only as SHA-256 hashes.
const (
	keyClient    = "c:"  // c:<client_id> -> oauthClient
	keyAuthReq   = "ar:" // ar:<request id> -> authRequest, a consent page awaiting a decision
	keyCode      = "ac:" // ac:<sha256(code)> -> authCode
	keyAccess    = "at:" // at:<sha256(token)> -> tokenRecord
	keyRefresh   = "rt:" // rt:<sha256(token)> -> tokenRecord
	keyGrant     = "g:"  // g:<grant id> -> grant, one connected client for one user
	keyUserGrant = "ug:" // ug:<user id> -> []string of grant ids
	keyRevoked   = "rg:" // rg:<grant id> -> true, a grant revoked by a code replay, possibly before it was saved
)

// oauthClient is a dynamically registered client (RFC 7591).
type oauthClient struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	ClientURI    string   `json:"client_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	AuthMethod   string   `json:"token_endpoint_auth_method"`
	SecretHash   string   `json:"secret_hash,omitempty"`
	CreatedAt    int64    `json:"created_at"`
	// Approved is set once a user consents; until then the registration expires after unapprovedClientTTL.
	Approved bool `json:"approved"`
}

// authRequest is a validated authorization request shown on a consent page.
type authRequest struct {
	UserID        string `json:"user_id"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
	Scope         string `json:"scope"`
	Resource      string `json:"resource"`
}

// authCode is an issued authorization code. Used is set on redemption so a replay can be detected.
type authCode struct {
	authRequest
	ExpiresAt int64  `json:"expires_at"`
	Used      bool   `json:"used"`
	GrantID   string `json:"grant_id,omitempty"`
}

// grant is one client connected to one user. Deleting it revokes every token issued under it.
type grant struct {
	GrantID     string `json:"grant_id"`
	UserID      string `json:"user_id"`
	ClientID    string `json:"client_id"`
	ClientName  string `json:"client_name"`
	Scope       string `json:"scope"`
	Resource    string `json:"resource"`
	CreatedAt   int64  `json:"created_at"`
	RefreshedAt int64  `json:"refreshed_at"`
	// RefreshHash is the hash of the only refresh token that may be redeemed next.
	RefreshHash string `json:"refresh_hash"`
	// PasswordUpdatedAt is the user's LastPasswordUpdate at approval. A password change ends the grant,
	// as it ends the user's Mattermost sessions.
	PasswordUpdatedAt int64 `json:"password_updated_at"`
}

// tokenRecord is what an access or refresh token hash points to.
type tokenRecord struct {
	GrantID   string `json:"grant_id"`
	UserID    string `json:"user_id"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	Resource  string `json:"resource"`
	ExpiresAt int64  `json:"expires_at"`
}

var errNotFound = errors.New("not found")

// store keeps OAuth state in the plugin KV store.
type store struct {
	api mmAPI
	now func() time.Time
}

// newSecret returns a random URL-safe string with 256 bits of entropy and the given prefix.
func newSecret(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// hashSecret is the SHA-256 hex digest used as a KV key; the secret itself is never stored.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ttlSeconds converts a lifetime to the KV expiry, at least one second.
func ttlSeconds(d time.Duration) int64 {
	return max(int64(d/time.Second), 1)
}

// getJSON loads key into v, returning errNotFound when it is absent or expired.
func (s *store) getJSON(key string, v any) ([]byte, error) {
	data, appErr := s.api.KVGet(key)
	if appErr != nil {
		return nil, errors.Wrap(appErr, "kv get")
	}
	if data == nil {
		return nil, errNotFound
	}
	if err := json.Unmarshal(data, v); err != nil {
		return nil, errors.Wrap(err, "decode kv value")
	}
	return data, nil
}

// setJSON stores v under key, expiring after ttl unless ttl is zero.
func (s *store) setJSON(key string, v any, ttl time.Duration) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	opts := model.PluginKVSetOptions{}
	if ttl > 0 {
		opts.ExpireInSeconds = ttlSeconds(ttl)
	}
	if _, appErr := s.api.KVSetWithOptions(key, data, opts); appErr != nil {
		return errors.Wrap(appErr, "kv set")
	}
	return nil
}

// compareAndSet replaces key's value only if it still equals old, reporting whether it did.
// A nil v deletes the key.
func (s *store) compareAndSet(key string, old []byte, v any, ttl time.Duration) (bool, error) {
	var data []byte
	if v != nil {
		var err error
		if data, err = json.Marshal(v); err != nil {
			return false, err
		}
	}
	opts := model.PluginKVSetOptions{Atomic: true, OldValue: old}
	if ttl > 0 && data != nil {
		opts.ExpireInSeconds = ttlSeconds(ttl)
	}
	ok, appErr := s.api.KVSetWithOptions(key, data, opts)
	if appErr != nil {
		return false, errors.Wrap(appErr, "kv compare and set")
	}
	return ok, nil
}

// getClient loads a registered client.
func (s *store) getClient(clientID string) (*oauthClient, error) {
	var c oauthClient
	if _, err := s.getJSON(keyClient+clientID, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// saveClient stores a client; an unapproved one expires so anonymous registrations cannot pile up.
func (s *store) saveClient(c *oauthClient) error {
	ttl := time.Duration(0)
	if !c.Approved {
		ttl = unapprovedClientTTL
	}
	return s.setJSON(keyClient+c.ClientID, c, ttl)
}

// takeAuthRequest consumes a pending consent request, so each consent page is answered once.
func (s *store) takeAuthRequest(id string) (*authRequest, error) {
	var ar authRequest
	data, err := s.getJSON(keyAuthReq+id, &ar)
	if err != nil {
		return nil, err
	}
	ok, err := s.compareAndSet(keyAuthReq+id, data, nil, 0)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNotFound
	}
	return &ar, nil
}

// getGrant loads a grant.
func (s *store) getGrant(id string) (*grant, []byte, error) {
	var g grant
	data, err := s.getJSON(keyGrant+id, &g)
	if err != nil {
		return nil, nil, err
	}
	return &g, data, nil
}

// userGrantIDs lists the grant ids recorded for a user, with the raw value for compare-and-set.
func (s *store) userGrantIDs(userID string) ([]string, []byte, error) {
	var ids []string
	data, err := s.getJSON(keyUserGrant+userID, &ids)
	if errors.Is(err, errNotFound) {
		return nil, nil, nil
	}
	return ids, data, err
}

// updateUserGrants applies change to the user's grant list with compare-and-set, retrying on races.
func (s *store) updateUserGrants(userID string, change func([]string) []string) error {
	for range 10 {
		ids, old, err := s.userGrantIDs(userID)
		if err != nil {
			return err
		}
		next := change(slices.Clone(ids))
		var v any = next
		if len(next) == 0 {
			v = nil
		}
		ok, err := s.compareAndSet(keyUserGrant+userID, old, v, 0)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return errors.New("user grant list kept changing")
}

// listGrants returns the user's live grants, dropping ids whose grant has gone.
func (s *store) listGrants(userID string) ([]*grant, error) {
	ids, _, err := s.userGrantIDs(userID)
	if err != nil {
		return nil, err
	}
	var out []*grant
	for _, id := range ids {
		g, _, err := s.getGrant(id)
		if errors.Is(err, errNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if g.UserID == userID {
			out = append(out, g)
		}
	}
	return out, nil
}

// revokeGrant deletes a grant, which invalidates every token issued under it.
func (s *store) revokeGrant(grantID string) error {
	g, _, err := s.getGrant(grantID)
	if errors.Is(err, errNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if appErr := s.api.KVDelete(keyGrant + grantID); appErr != nil {
		return errors.Wrap(appErr, "delete grant")
	}
	return s.updateUserGrants(g.UserID, func(ids []string) []string {
		return slices.DeleteFunc(ids, func(id string) bool { return id == grantID })
	})
}

// tokenPair is a freshly issued access and refresh token.
type tokenPair struct {
	Access    string
	Refresh   string
	ExpiresIn int64
}

// issueTokens mints an access and refresh token for g and stores their hashes. The caller saves g,
// whose RefreshHash this sets.
func (s *store) issueTokens(g *grant, cfg *configuration) (*tokenPair, error) {
	now := s.now()
	pair := &tokenPair{
		Access:    newSecret("mmcp_at_"),
		Refresh:   newSecret("mmcp_rt_"),
		ExpiresIn: int64(cfg.accessTokenTTL() / time.Second),
	}
	rec := tokenRecord{GrantID: g.GrantID, UserID: g.UserID, ClientID: g.ClientID, Scope: g.Scope, Resource: g.Resource}
	rec.ExpiresAt = now.Add(cfg.accessTokenTTL()).UnixMilli()
	if err := s.setJSON(keyAccess+hashSecret(pair.Access), rec, cfg.accessTokenTTL()); err != nil {
		return nil, err
	}
	rec.ExpiresAt = now.Add(cfg.refreshTokenTTL()).UnixMilli()
	refreshHash := hashSecret(pair.Refresh)
	if err := s.setJSON(keyRefresh+refreshHash, rec, cfg.refreshTokenTTL()); err != nil {
		return nil, err
	}
	g.RefreshHash = refreshHash
	g.RefreshedAt = now.UnixMilli()
	return pair, nil
}

// lookupToken resolves a token of the given kind to its record, checking expiry and that its
// grant still exists.
func (s *store) lookupToken(prefix, token string) (*tokenRecord, *grant, error) {
	var rec tokenRecord
	if _, err := s.getJSON(prefix+hashSecret(token), &rec); err != nil {
		return nil, nil, err
	}
	if s.now().UnixMilli() >= rec.ExpiresAt {
		return nil, nil, errNotFound
	}
	g, _, err := s.getGrant(rec.GrantID)
	if err != nil {
		return nil, nil, err
	}
	return &rec, g, nil
}
