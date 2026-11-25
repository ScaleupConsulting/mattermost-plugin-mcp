package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

const (
	scopeRead  = "mcp:read"
	scopeWrite = "mcp:write"

	authRequestTTL      = 10 * time.Minute
	authCodeTTL         = 2 * time.Minute
	unapprovedClientTTL = 24 * time.Hour
	usedCodeTTL         = 10 * time.Minute

	maxFormBytes       = 64 << 10
	maxRedirectURIs    = 5
	maxClientNameRunes = 80

	// registrationsPerHour caps anonymous client registrations across the whole server.
	registrationsPerHour = 200
)

// oauthServer is the plugin's own OAuth 2.1 authorization server for the MCP endpoint.
type oauthServer struct {
	api     mmAPI
	store   *store
	config  func() *configuration
	siteURL func() string
	now     func() time.Time

	regLock    sync.Mutex
	regWindow  time.Time
	regInCycle int
}

// base is the plugin's public URL, which is also the OAuth issuer.
func (o *oauthServer) base() string {
	return strings.TrimRight(o.siteURL(), "/") + "/plugins/" + pluginID
}

// resourceURL is the canonical URL of the MCP endpoint, the audience every token is bound to.
func (o *oauthServer) resourceURL() string { return o.base() + "/mcp" }

// resourceMetadataURL is where the 401 from the MCP endpoint points clients (RFC 9728).
func (o *oauthServer) resourceMetadataURL() string {
	return o.base() + "/.well-known/oauth-protected-resource"
}

// supportedScopes lists the scopes a client may be granted under the current settings.
func (o *oauthServer) supportedScopes() []string {
	if o.config().EnableWriteTools {
		return []string{scopeRead, scopeWrite}
	}
	return []string{scopeRead}
}

// handleProtectedResourceMetadata serves RFC 9728 metadata for the MCP endpoint.
func (o *oauthServer) handleProtectedResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	allowCORS(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 o.resourceURL(),
		"authorization_servers":    []string{o.base()},
		"scopes_supported":         o.supportedScopes(),
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Mattermost",
	})
}

// handleAuthServerMetadata serves RFC 8414 metadata.
func (o *oauthServer) handleAuthServerMetadata(w http.ResponseWriter, _ *http.Request) {
	allowCORS(w)
	b := o.base()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         b,
		"authorization_endpoint":                         b + "/oauth/authorize",
		"token_endpoint":                                 b + "/oauth/token",
		"registration_endpoint":                          b + "/oauth/register",
		"revocation_endpoint":                            b + "/oauth/revoke",
		"scopes_supported":                               o.supportedScopes(),
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported":          false,
	})
}

// allowRegistration applies the server-wide hourly cap on anonymous registrations.
func (o *oauthServer) allowRegistration() bool {
	o.regLock.Lock()
	defer o.regLock.Unlock()
	now := o.now()
	if now.Sub(o.regWindow) > time.Hour {
		o.regWindow, o.regInCycle = now, 0
	}
	if o.regInCycle >= registrationsPerHour {
		return false
	}
	o.regInCycle++
	return true
}

// registrationRequest is the subset of RFC 7591 client metadata this server reads.
type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// handleRegister implements dynamic client registration (RFC 7591).
func (o *oauthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	if !o.config().EnableAccess {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "an administrator has turned off assistant access")
		return
	}
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFormBytes)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "body must be a JSON object")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirectURIs {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "give 1 to 5 redirect_uris")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := validRedirectURI(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_type "+g)
			return
		}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response_type "+rt)
			return
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic" // the RFC 7591 default
	}
	if method != "none" && method != "client_secret_post" && method != "client_secret_basic" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
		return
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "Unnamed client"
	}
	if r := []rune(name); len(r) > maxClientNameRunes {
		name = string(r[:maxClientNameRunes])
	}
	if !o.allowRegistration() {
		oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations, try again later")
		return
	}

	c := &oauthClient{
		ClientID:     model.NewId(),
		ClientName:   name,
		RedirectURIs: req.RedirectURIs,
		AuthMethod:   method,
		CreatedAt:    o.now().UnixMilli(),
	}
	if u, err := url.Parse(req.ClientURI); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		c.ClientURI = u.String()
	}
	var secret string
	if method != "none" {
		secret = newSecret("mmcp_cs_")
		c.SecretHash = hashSecret(secret)
	}
	if err := o.store.saveClient(c); err != nil {
		o.api.LogError("Failed to save client registration", "err", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	resp := map[string]any{
		"client_id":                  c.ClientID,
		"client_id_issued_at":        c.CreatedAt / 1000,
		"client_name":                c.ClientName,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": c.AuthMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      strings.Join(o.supportedScopes(), " "),
	}
	if c.ClientURI != "" {
		resp["client_uri"] = c.ClientURI
	}
	if secret != "" {
		resp["client_secret"] = secret
		resp["client_secret_expires_at"] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

// validRedirectURI accepts https URLs, and http only on a loopback host for native clients (RFC 8252).
func validRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.Errorf("redirect_uri %q is not an absolute URL", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.Errorf("redirect_uri %q must not have a fragment", raw)
	}
	if u.User != nil {
		return errors.Errorf("redirect_uri %q must not carry credentials", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.Errorf("redirect_uri %q must use https unless it is on localhost", raw)
	default:
		return errors.Errorf("redirect_uri %q must use https", raw)
	}
}

// parseScope validates a requested scope string and returns the granted scope. An empty request
// gets every scope the settings allow; asking for a scope the settings forbid is an error.
func (o *oauthServer) parseScope(requested string) (string, error) {
	supported := o.supportedScopes()
	fields := strings.Fields(requested)
	if len(fields) == 0 {
		return strings.Join(supported, " "), nil
	}
	var out []string
	for _, s := range fields {
		if !slices.Contains(supported, s) {
			return "", errors.Errorf("scope %q is not available", s)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if !slices.Contains(out, scopeRead) {
		out = append([]string{scopeRead}, out...) // every tool needs read access to find what it acts on
	}
	return strings.Join(out, " "), nil
}

// canonicalResource checks a client-supplied RFC 8707 resource indicator against this server's.
func (o *oauthServer) canonicalResource(requested string) (string, bool) {
	want := o.resourceURL()
	if requested == "" {
		return want, true
	}
	return want, strings.TrimRight(requested, "/") == want
}

// handleAuthorize validates an authorization request and shows the consent page to the signed-in user.
func (o *oauthServer) handleAuthorize(w http.ResponseWriter, r *http.Request, sessionCSRF func() string) {
	if !o.config().EnableAccess {
		renderError(w, http.StatusServiceUnavailable, "An administrator has turned off assistant access to this Mattermost server.")
		return
	}
	q := r.URL.Query()
	client, err := o.store.getClient(q.Get("client_id"))
	if err != nil {
		renderError(w, http.StatusBadRequest, "This assistant is not registered here, or its registration expired. Remove it and add it again.")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		// Never redirect to an unregistered URI: the error is shown here instead.
		renderError(w, http.StatusBadRequest, "The redirect address does not match the one this assistant registered.")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		http.Redirect(w, r, o.redirectWith(redirectURI, map[string]string{"error": code, "error_description": desc, "state": state}), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" || !validChallenge(challenge) {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	resource, ok := o.canonicalResource(q.Get("resource"))
	if !ok {
		fail("invalid_target", "resource must be "+o.resourceURL())
		return
	}
	scope, err := o.parseScope(q.Get("scope"))
	if err != nil {
		fail("invalid_scope", err.Error())
		return
	}

	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		http.Redirect(w, r, strings.TrimRight(o.siteURL(), "/")+"/login?redirect_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	user, appErr := o.api.GetUser(userID)
	if appErr != nil || user.DeleteAt != 0 || user.IsBot {
		renderError(w, http.StatusForbidden, "This account cannot connect assistants.")
		return
	}

	reqID := model.NewId() + model.NewId()
	ar := authRequest{UserID: userID, ClientID: client.ClientID, RedirectURI: redirectURI, State: state, CodeChallenge: challenge, Scope: scope, Resource: resource}
	if err := o.store.setJSON(keyAuthReq+reqID, ar, authRequestTTL); err != nil {
		o.api.LogError("Failed to save authorization request", "err", err.Error())
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	renderConsent(w, consentPage{
		ClientName:     client.ClientName,
		ClientURI:      client.ClientURI,
		RedirectHost:   hostOf(redirectURI),
		Username:       user.Username,
		CanWrite:       strings.Contains(scope, scopeWrite),
		RequestID:      reqID,
		CSRF:           sessionCSRF(),
		Action:         o.base() + "/oauth/authorize",
		ConnectionsURL: o.base() + "/connections",
	})
}

// handleAuthorizeDecision handles the consent form. Mattermost has already checked the form's csrf
// field against the session; this also checks it and binds the request to the same user.
func (o *oauthServer) handleAuthorizeDecision(w http.ResponseWriter, r *http.Request, sessionCSRF func() string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "The form could not be read.")
		return
	}
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" || !csrfMatches(r.PostForm.Get("csrf"), sessionCSRF()) {
		renderError(w, http.StatusForbidden, "Your Mattermost session could not be confirmed. Start the connection again from the assistant.")
		return
	}
	ar, err := o.store.takeAuthRequest(r.PostForm.Get("request_id"))
	if err != nil || ar.UserID != userID {
		renderError(w, http.StatusBadRequest, "This approval page has expired or was already used. Start the connection again from the assistant.")
		return
	}
	if !o.config().EnableAccess {
		renderError(w, http.StatusServiceUnavailable, "An administrator has turned off assistant access to this Mattermost server.")
		return
	}
	if r.PostForm.Get("decision") != "approve" {
		http.Redirect(w, r, o.redirectWith(ar.RedirectURI, map[string]string{"error": "access_denied", "error_description": "the user declined", "state": ar.State}), http.StatusSeeOther)
		return
	}
	client, err := o.store.getClient(ar.ClientID)
	if err != nil {
		renderError(w, http.StatusBadRequest, "This assistant's registration expired. Start the connection again from the assistant.")
		return
	}
	if !client.Approved {
		client.Approved = true
		if err := o.store.saveClient(client); err != nil {
			o.api.LogError("Failed to save approved client", "err", err.Error())
			renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
			return
		}
	}
	code := newSecret("mmcp_ac_")
	ac := authCode{authRequest: *ar, ExpiresAt: o.now().Add(authCodeTTL).UnixMilli()}
	if err := o.store.setJSON(keyCode+hashSecret(code), ac, usedCodeTTL); err != nil {
		o.api.LogError("Failed to save authorization code", "err", err.Error())
		renderError(w, http.StatusInternalServerError, "Something went wrong. Try again.")
		return
	}
	http.Redirect(w, r, o.redirectWith(ar.RedirectURI, map[string]string{"code": code, "state": ar.State}), http.StatusSeeOther)
}

// redirectWith appends params and the issuer (RFC 9207) to a registered redirect URI.
func (o *oauthServer) redirectWith(redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	q.Set("iss", o.base())
	u.RawQuery = q.Encode()
	return u.String()
}

// validChallenge accepts an S256 code challenge: 43 base64url characters.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

// pkceMatches checks a code verifier against an S256 challenge (RFC 7636).
func pkceMatches(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// authenticateClient identifies the client at the token and revocation endpoints by its registered method.
func (o *oauthServer) authenticateClient(r *http.Request) (*oauthClient, bool) {
	id, secret, hasBasic := r.BasicAuth()
	if hasBasic {
		var err error
		if id, err = url.QueryUnescape(id); err != nil {
			return nil, false
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			return nil, false
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	client, err := o.store.getClient(id)
	if err != nil {
		return nil, false
	}
	switch client.AuthMethod {
	case "none":
		return client, !hasBasic && secret == ""
	case "client_secret_basic", "client_secret_post":
		// Accept either secret method: clients often pick one without regard to what they registered.
		if secret == "" {
			return nil, false
		}
		return client, subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(client.SecretHash)) == 1
	}
	return nil, false
}

// handleToken implements the token endpoint for the authorization_code and refresh_token grants.
func (o *oauthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "body must be form-encoded")
		return
	}
	if !o.config().EnableAccess {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "an administrator has turned off assistant access")
		return
	}
	client, ok := o.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="mattermost-mcp"`)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		o.exchangeCode(w, r, client)
	case "refresh_token":
		o.refresh(w, r, client)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	}
}

// exchangeCode redeems an authorization code once. A second redemption revokes the grant the first created.
func (o *oauthServer) exchangeCode(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	code := r.PostForm.Get("code")
	key := keyCode + hashSecret(code)
	var ac authCode
	old, err := o.store.getJSON(key, &ac)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown or expired code")
		return
	}
	if ac.Used {
		if ac.GrantID != "" {
			if err := o.store.revokeGrant(ac.GrantID); err != nil {
				o.api.LogError("Failed to revoke grant after code replay", "err", err.Error())
			}
		}
		o.api.LogWarn("Authorization code replayed; revoked the tokens it issued", "client_id", client.ClientID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code already used")
		return
	}
	if ac.ClientID != client.ClientID || o.now().UnixMilli() >= ac.ExpiresAt ||
		r.PostForm.Get("redirect_uri") != ac.RedirectURI || !pkceMatches(r.PostForm.Get("code_verifier"), ac.CodeChallenge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code, client, redirect_uri or code_verifier do not match")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && strings.TrimRight(res, "/") != ac.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the authorization request")
		return
	}
	user, appErr := o.api.GetUser(ac.UserID)
	if appErr != nil || user.DeleteAt != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not active")
		return
	}

	g := &grant{
		GrantID:    model.NewId(),
		UserID:     ac.UserID,
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		Scope:      ac.Scope,
		Resource:   ac.Resource,
		CreatedAt:  o.now().UnixMilli(),
	}
	// Mark the code used first, so two concurrent redemptions cannot both succeed.
	used := ac
	used.Used, used.GrantID = true, g.GrantID
	won, err := o.store.compareAndSet(key, old, used, usedCodeTTL)
	if err != nil || !won {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code already used")
		return
	}
	pair, err := o.store.issueTokens(g, o.config())
	if err == nil {
		err = o.store.setJSON(keyGrant+g.GrantID, g, 0)
	}
	if err == nil {
		err = o.replaceClientGrants(g)
	}
	if err != nil {
		o.api.LogError("Failed to issue tokens", "err", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	writeTokenResponse(w, pair, g.Scope)
}

// replaceClientGrants records g for its user and revokes the user's older grants to the same client,
// so reconnecting a client does not leave a stale connection behind.
func (o *oauthServer) replaceClientGrants(g *grant) error {
	existing, err := o.store.listGrants(g.UserID)
	if err != nil {
		return err
	}
	for _, old := range existing {
		if old.ClientID == g.ClientID && old.GrantID != g.GrantID {
			if err := o.store.revokeGrant(old.GrantID); err != nil {
				return err
			}
		}
	}
	return o.store.updateUserGrants(g.UserID, func(ids []string) []string { return append(ids, g.GrantID) })
}

// refresh rotates a refresh token. Presenting a superseded refresh token revokes the whole grant,
// since only a stolen copy would still be in use.
func (o *oauthServer) refresh(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	token := r.PostForm.Get("refresh_token")
	hash := hashSecret(token)
	rec, _, err := o.store.lookupToken(keyRefresh, token)
	if err != nil || rec.ClientID != client.ClientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or revoked refresh token")
		return
	}
	// Read the grant once: the hash check and the compare-and-set below must see the same value.
	g, oldData, err := o.store.getGrant(rec.GrantID)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "revoked")
		return
	}
	if subtle.ConstantTimeCompare([]byte(g.RefreshHash), []byte(hash)) != 1 {
		if err := o.store.revokeGrant(g.GrantID); err != nil {
			o.api.LogError("Failed to revoke grant after refresh token reuse", "err", err.Error())
		}
		o.api.LogWarn("Superseded refresh token presented; revoked the connection", "client_id", client.ClientID, "user_id", g.UserID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && strings.TrimRight(res, "/") != g.Resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource does not match the grant")
		return
	}
	scope := g.Scope
	if requested := strings.Fields(r.PostForm.Get("scope")); len(requested) > 0 {
		have := strings.Fields(g.Scope)
		for _, s := range requested {
			if !slices.Contains(have, s) {
				oauthError(w, http.StatusBadRequest, "invalid_scope", "a refresh cannot widen the scope")
				return
			}
		}
		scope = strings.Join(requested, " ")
	}
	user, appErr := o.api.GetUser(g.UserID)
	if appErr != nil || user.DeleteAt != 0 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user is not active")
		return
	}
	next := *g
	next.Scope = scope
	pair, err := o.store.issueTokens(&next, o.config())
	if err != nil {
		o.api.LogError("Failed to issue tokens", "err", err.Error())
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	won, err := o.store.compareAndSet(keyGrant+g.GrantID, oldData, &next, 0)
	if err != nil || !won {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "refresh token already used")
		return
	}
	writeTokenResponse(w, pair, scope)
}

// handleRevoke implements token revocation (RFC 7009); revoking either token disconnects the client.
func (o *oauthServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "body must be form-encoded")
		return
	}
	client, ok := o.authenticateClient(r)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	token := r.PostForm.Get("token")
	for _, prefix := range []string{keyAccess, keyRefresh} {
		var rec tokenRecord
		if _, err := o.store.getJSON(prefix+hashSecret(token), &rec); err == nil && rec.ClientID == client.ClientID {
			if err := o.store.revokeGrant(rec.GrantID); err != nil {
				o.api.LogError("Failed to revoke grant", "err", err.Error())
				oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "")
				return
			}
			break
		}
	}
	w.WriteHeader(http.StatusOK) // RFC 7009: answer 200 whether or not the token was known
}

// writeTokenResponse sends an RFC 6749 token response.
func writeTokenResponse(w http.ResponseWriter, pair *tokenPair, scope string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  pair.Access,
		"token_type":    "Bearer",
		"expires_in":    pair.ExpiresIn,
		"refresh_token": pair.Refresh,
		"scope":         scope,
	})
}

// oauthError sends an RFC 6749 error response.
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, status, body)
}

// allowCORS lets browser-based MCP clients call the token-authenticated endpoints. None of them
// accept cookies, so any origin is safe.
func allowCORS(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Protocol-Version, Mcp-Session-Id, Last-Event-ID")
	h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
}

// writeJSON sends v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// hostOf returns the host of a URL for display.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return raw
}
