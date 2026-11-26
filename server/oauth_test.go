package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedirect = "http://localhost:33418/callback"

// harness drives the plugin's HTTP routes the way the Mattermost server would.
type harness struct {
	t   *testing.T
	w   *world
	p   *Plugin
	cfg *configuration
	// choice is the access radio the user picks on the consent page: "read", "write", or "" for none.
	choice string
}

func newHarness(t *testing.T) *harness {
	w := newWorld()
	cfg := &configuration{EnableAccess: true, ToolsChannels: true, ToolsPosts: true, ToolsSearch: true, ToolsUnreads: true, ToolsUsers: true, ToolsDrafts: true, AccessTokenMinutes: 60, RefreshTokenDays: 30}
	p := &Plugin{}
	p.config.set(cfg)
	p.setup(w.api, w.api.now)
	p.drafts = w.api
	for _, u := range []*model.User{w.alice, w.bob} {
		w.api.sessions["sess-"+u.Username] = &model.Session{Id: "sess-" + u.Username, UserId: u.Id, Props: model.StringMap{"csrf": "csrf-" + u.Username}}
	}
	return &harness{t: t, w: w, p: p, cfg: cfg}
}

// setConfig replaces the active settings.
func (h *harness) setConfig(change func(c *configuration)) {
	c := *h.cfg
	change(&c)
	h.cfg = &c
	h.p.config.set(&c)
}

// do sends a request as the given Mattermost user ("" for none), as the server's plugin router would.
func (h *harness) do(method, path string, body io.Reader, user *model.User, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://chat.example.com/plugins/"+pluginID+path, body)
	// The server strips the /plugins/<id> prefix before the plugin sees the request.
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/plugins/"+pluginID)
	r.RequestURI = r.URL.RequestURI()
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	ctx := &plugin.Context{}
	if user != nil {
		r.Header.Set("Mattermost-User-Id", user.Id)
		ctx.SessionId = "sess-" + user.Username
	}
	rec := httptest.NewRecorder()
	h.p.ServeHTTP(ctx, rec, r)
	return rec
}

func (h *harness) postForm(path string, form url.Values, user *model.User) *httptest.ResponseRecorder {
	return h.do(http.MethodPost, path, strings.NewReader(form.Encode()), user, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func (h *harness) register(body string) map[string]any {
	rec := h.do(http.MethodPost, "/oauth/register", strings.NewReader(body), nil, map[string]string{"Content-Type": "application/json"})
	require.Equal(h.t, http.StatusCreated, rec.Code, rec.Body.String())
	var out map[string]any
	require.NoError(h.t, json.Unmarshal(rec.Body.Bytes(), &out))
	return out
}

func (h *harness) registerPublic() string {
	return h.register(`{"client_name":"Claude Code","redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"none"}`)["client_id"].(string)
}

func pkcePair() (verifier, challenge string) {
	verifier = newSecret("v")
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

var hiddenField = regexp.MustCompile(`name="(request_id|csrf)" value="([^"]*)"`)

// authorize runs the consent flow as user and returns the redirect URL the browser is sent to.
func (h *harness) authorize(clientID, challenge, scope string, user *model.User) *url.URL {
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st-1"},
		"resource": {"https://chat.example.com/plugins/" + pluginID + "/mcp"}}
	if scope != "" {
		q.Set("scope", scope)
	}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, user, nil)
	require.Equal(h.t, http.StatusOK, rec.Code, rec.Body.String())
	fields := url.Values{"decision": {"approve"}}
	if h.choice != "" {
		fields.Set("access", h.choice)
	}
	for _, m := range hiddenField.FindAllStringSubmatch(rec.Body.String(), -1) {
		fields.Set(m[1], m[2])
	}
	require.NotEmpty(h.t, fields.Get("request_id"))
	rec = h.postForm("/oauth/authorize", fields, user)
	require.Equal(h.t, http.StatusSeeOther, rec.Code, rec.Body.String())
	u, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(h.t, err)
	return u
}

// token posts to the token endpoint and decodes the JSON answer.
func (h *harness) token(form url.Values) (int, map[string]any) {
	rec := h.postForm("/oauth/token", form, nil)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// connect runs the whole flow for alice and returns the client id and token response.
func (h *harness) connect(scope string) (string, map[string]any) {
	clientID := h.registerPublic()
	verifier, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, scope, h.w.alice)
	code, tok := h.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}})
	require.Equal(h.t, http.StatusOK, code, tok)
	return clientID, tok
}

// mcp sends one JSON-RPC request to the MCP endpoint with an optional bearer token.
func (h *harness) mcp(token, method string, params any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-11-25"}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	return h.do(http.MethodPost, "/mcp", strings.NewReader(string(body)), nil, headers)
}

// callTool calls a tool and returns its text and whether it failed, as a tool error or a JSON-RPC error.
func (h *harness) callTool(token, name string, args map[string]any) (string, bool) {
	rec := h.mcp(token, "tools/call", map[string]any{"name": name, "arguments": args})
	require.Equal(h.t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	require.NoError(h.t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	if resp.Error != nil {
		return resp.Error.Message, true // a JSON-RPC error, such as an unknown tool
	}
	var b strings.Builder
	for _, c := range resp.Result.Content {
		b.WriteString(c.Text)
	}
	return b.String(), resp.Result.IsError
}

// toolNames lists the tools the server offers this token.
func (h *harness) toolNames(token string) []string {
	rec := h.mcp(token, "tools/list", map[string]any{})
	require.Equal(h.t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	require.NoError(h.t, json.Unmarshal(rec.Body.Bytes(), &resp))
	var names []string
	for _, tool := range resp.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestDiscoveryMetadata(t *testing.T) {
	h := newHarness(t)
	rec := h.mcp("", "tools/list", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `resource_metadata="https://chat.example.com/plugins/com.scaleupconsulting.mcp/.well-known/oauth-protected-resource"`)

	var prm map[string]any
	require.NoError(t, json.Unmarshal(h.do(http.MethodGet, "/.well-known/oauth-protected-resource", nil, nil, nil).Body.Bytes(), &prm))
	assert.Equal(t, "https://chat.example.com/plugins/com.scaleupconsulting.mcp/mcp", prm["resource"])
	var asm map[string]any
	require.NoError(t, json.Unmarshal(h.do(http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil, nil).Body.Bytes(), &asm))
	assert.Equal(t, "https://chat.example.com/plugins/com.scaleupconsulting.mcp", asm["issuer"])
	assert.Equal(t, []any{"S256"}, asm["code_challenge_methods_supported"])
}

func TestFullFlowAndToolAccess(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	assert.Equal(t, "mcp:read", tok["scope"])
	access := tok["access_token"].(string)

	names := h.toolNames(access)
	assert.Contains(t, names, "read_channel")
	assert.NotContains(t, names, "post_message", "write tools are off by default")

	text, isErr := h.callTool(access, "read_channel", map[string]any{"channel": h.w.town.Id})
	assert.False(t, isErr, text)
	assert.Contains(t, text, "secret plan is public here")

	h.w.api.permissive = true // even with system-admin-like role permissions
	for name, ch := range h.w.forbidden() {
		text, isErr = h.callTool(access, "read_channel", map[string]any{"channel": ch.Id})
		assert.True(t, isErr, name)
		assert.Contains(t, text, "do not have access", name)
	}
	text, isErr = h.callTool(access, "search_posts", map[string]any{"query": "secret"})
	assert.False(t, isErr)
	assert.NotContains(t, text, h.w.bobPrivPost.Id)
	assert.NotContains(t, text, h.w.dmBobPost.Id)
}

func TestMattermostSessionIsNotAccepted(t *testing.T) {
	h := newHarness(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	rec := h.do(http.MethodPost, "/mcp", strings.NewReader(body), h.w.alice, map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "a browser session cookie must not authorize MCP")
	rec = h.mcp("not-a-token", "tools/list", map[string]any{})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPKCEFailure(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, "", h.w.alice)
	wrongVerifier, _ := pkcePair()
	code, out := h.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {wrongVerifier}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
}

func TestPlainPKCEIsRefused(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {"plain-challenge-plain-challenge-plain-chall"}, "code_challenge_method": {"plain"}, "state": {"s"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "error=invalid_request")
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	rec = h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	assert.Contains(t, rec.Header().Get("Location"), "error=invalid_request")
}

func TestWrongRedirectURI(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	verifier, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://evil.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "an unregistered redirect is shown an error, never redirected to")
	assert.Empty(t, rec.Header().Get("Location"))

	q.Set("redirect_uri", testRedirect+"/extra")
	rec = h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "redirect URIs match exactly, not by prefix")

	loc := h.authorize(clientID, challenge, "", h.w.alice)
	code, out := h.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"http://localhost:9999/callback"}, "code_verifier": {verifier}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])

	reg := h.do(http.MethodPost, "/oauth/register", strings.NewReader(`{"redirect_uris":["http://evil.example/cb"],"token_endpoint_auth_method":"none"}`), nil, nil)
	assert.Equal(t, http.StatusBadRequest, reg.Code, "plain http is allowed only on loopback")
}

func TestReplayedCodeRevokesItsTokens(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	verifier, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, "", h.w.alice)
	assert.Equal(t, "st-1", loc.Query().Get("state"))
	assert.Equal(t, "https://chat.example.com/plugins/com.scaleupconsulting.mcp", loc.Query().Get("iss"))
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}}
	code, tok := h.token(form)
	require.Equal(t, http.StatusOK, code)
	access := tok["access_token"].(string)
	assert.Equal(t, http.StatusOK, h.mcp(access, "tools/list", map[string]any{}).Code)

	code, out := h.token(form)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code, "replay revokes the first exchange's tokens")
}

func TestExpiredTokens(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	access := tok["access_token"].(string)
	h.w.api.advance(61 * time.Minute)
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code)

	code, fresh := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}})
	require.Equal(t, http.StatusOK, code, fresh)
	assert.Equal(t, http.StatusOK, h.mcp(fresh["access_token"].(string), "tools/list", map[string]any{}).Code)

	h.w.api.advance(31 * 24 * time.Hour)
	code, _ = h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {fresh["refresh_token"].(string)}})
	assert.Equal(t, http.StatusBadRequest, code, "expired refresh token")
}

func TestExpiredCode(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	verifier, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, "", h.w.alice)
	h.w.api.advance(3 * time.Minute)
	code, out := h.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
}

func TestRefreshRotationAndReuse(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	first := tok["refresh_token"].(string)
	code, second := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {first}})
	require.Equal(t, http.StatusOK, code)
	assert.NotEqual(t, first, second["refresh_token"])

	code, out := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {first}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
	assert.Equal(t, http.StatusUnauthorized, h.mcp(second["access_token"].(string), "tools/list", map[string]any{}).Code,
		"reusing a rotated refresh token revokes the whole connection")
	code, _ = h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {second["refresh_token"].(string)}})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestRevokedToken(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	access := tok["access_token"].(string)
	rec := h.postForm("/oauth/revoke", url.Values{"client_id": {clientID}, "token": {access}}, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code)
	code, _ := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestOtherClientCannotRevokeOrRefresh(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	other := h.registerPublic()
	h.postForm("/oauth/revoke", url.Values{"client_id": {other}, "token": {tok["access_token"].(string)}}, nil)
	assert.Equal(t, http.StatusOK, h.mcp(tok["access_token"].(string), "tools/list", map[string]any{}).Code)
	code, _ := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {other}, "refresh_token": {tok["refresh_token"].(string)}})
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestConfidentialClientNeedsSecret(t *testing.T) {
	h := newHarness(t)
	reg := h.register(`{"client_name":"claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"client_secret_post"}`)
	clientID, secret := reg["client_id"].(string), reg["client_secret"].(string)
	require.NotEmpty(t, secret)
	code, out := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {"x"}})
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, "invalid_client", out["error"])
	code, out = h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "client_secret": {secret}, "refresh_token": {"x"}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"], "secret accepted, bogus refresh token refused")
}

func TestConsentCSRF(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Contains(t, rec.Body.String(), "Claude Code")
	reqID := hiddenField.FindStringSubmatch(rec.Body.String())[2]

	rec = h.postForm("/oauth/authorize", url.Values{"request_id": {reqID}, "decision": {"approve"}}, h.w.alice)
	assert.Equal(t, http.StatusForbidden, rec.Code, "no csrf field")
	rec = h.postForm("/oauth/authorize", url.Values{"request_id": {reqID}, "csrf": {"csrf-bob"}, "decision": {"approve"}}, h.w.bob)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "bob cannot answer alice's consent page")
	rec = h.postForm("/oauth/authorize", url.Values{"request_id": {reqID}, "csrf": {"csrf-alice"}, "decision": {"approve"}}, h.w.alice)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "the page was consumed by bob's attempt; it is single-use")
}

func TestDenyRedirectsWithAccessDenied(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	reqID := hiddenField.FindStringSubmatch(rec.Body.String())[2]
	rec = h.postForm("/oauth/authorize", url.Values{"request_id": {reqID}, "csrf": {"csrf-alice"}, "decision": {"deny"}}, h.w.alice)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "error=access_denied")
}

func TestNotSignedInRedirectsToLogin(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, nil, nil)
	assert.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/login", loc.Path)
	assert.Equal(t, "/plugins/"+pluginID+"/oauth/authorize?"+q.Encode(), loc.Query().Get("redirect_to"), "back to the full plugin path")
}

func TestResourceMustMatch(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {"https://other.example/mcp"}}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	assert.Contains(t, rec.Header().Get("Location"), "error=invalid_target")
}

func TestTokenBoundToThisResource(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	h.w.api.siteURL = "https://renamed.example.com"
	assert.Equal(t, http.StatusUnauthorized, h.mcp(tok["access_token"].(string), "tools/list", map[string]any{}).Code)
}

func TestAccessSwitchAndDeactivatedUser(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	access := tok["access_token"].(string)
	h.setConfig(func(c *configuration) { c.EnableAccess = false })
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code)
	h.setConfig(func(c *configuration) { c.EnableAccess = true })
	assert.Equal(t, http.StatusOK, h.mcp(access, "tools/list", map[string]any{}).Code)
	h.w.alice.DeleteAt = 1
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code)
}

func TestConnectionsPageAndCommand(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	rec := h.do(http.MethodGet, "/connections", nil, h.w.alice, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Claude Code")
	grants, err := h.p.oauth.store.listGrants(h.w.alice.Id)
	require.NoError(t, err)
	require.Len(t, grants, 1)

	rec = h.postForm("/connections/revoke", url.Values{"grant_id": {grants[0].GrantID}, "csrf": {"csrf-bob"}}, h.w.bob)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, http.StatusOK, h.mcp(tok["access_token"].(string), "tools/list", map[string]any{}).Code, "bob cannot disconnect alice's assistant")

	resp, _ := h.p.ExecuteCommand(nil, &model.CommandArgs{UserId: h.w.alice.Id, Command: "/mcp"})
	assert.Contains(t, resp.Text, "1. **Claude Code**")
	resp, _ = h.p.ExecuteCommand(nil, &model.CommandArgs{UserId: h.w.alice.Id, Command: "/mcp disconnect 1"})
	assert.Contains(t, resp.Text, "Disconnected 1")
	assert.Equal(t, http.StatusUnauthorized, h.mcp(tok["access_token"].(string), "tools/list", map[string]any{}).Code)
}

func TestReconnectReplacesOldConnection(t *testing.T) {
	h := newHarness(t)
	clientID, first := h.connect("")
	verifier, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, "", h.w.alice)
	code, _ := h.token(url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}})
	require.Equal(t, http.StatusOK, code)
	grants, err := h.p.oauth.store.listGrants(h.w.alice.Id)
	require.NoError(t, err)
	assert.Len(t, grants, 1)
	assert.Equal(t, http.StatusUnauthorized, h.mcp(first["access_token"].(string), "tools/list", map[string]any{}).Code)
}

func TestKVHoldsNoRawSecrets(t *testing.T) {
	h := newHarness(t)
	_, tok := h.connect("")
	for key, e := range h.w.api.kv {
		for _, secret := range []string{tok["access_token"].(string), tok["refresh_token"].(string)} {
			assert.NotContains(t, key, secret)
			assert.NotContains(t, string(e.value), secret)
		}
	}
}

// consentPage opens the consent page for alice with the given requested scope.
func (h *harness) consentPage(clientID, challenge, scope string) *httptest.ResponseRecorder {
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st-1"}}
	if scope != "" {
		q.Set("scope", scope)
	}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	require.Equal(h.t, http.StatusOK, rec.Code, rec.Body.String())
	return rec
}

// decide approves a consent page as alice with the given access choice.
func (h *harness) decide(page *httptest.ResponseRecorder, choice string) *httptest.ResponseRecorder {
	fields := url.Values{"decision": {"approve"}, "access": {choice}}
	for _, m := range hiddenField.FindAllStringSubmatch(page.Body.String(), -1) {
		fields.Set(m[1], m[2])
	}
	return h.postForm("/oauth/authorize", fields, h.w.alice)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
