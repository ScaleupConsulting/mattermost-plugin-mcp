package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var writeTools = []string{"post_message", "reply_in_thread", "add_reaction"}

// writeArgs are valid arguments for each write tool, aimed at a channel alice may post in.
func (h *harness) writeArgs() map[string]map[string]any {
	return map[string]map[string]any{
		"post_message":    {"channel": h.w.town.Id, "message": "hi"},
		"reply_in_thread": {"post": h.w.townPost.Id, "message": "hi"},
		"add_reaction":    {"post": h.w.townPost.Id, "emoji": "thumbsup"},
	}
}

func TestReadOnlyChoiceNarrowsAWriteRequest(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	h.choice = "read"
	_, tok := h.connect("mcp:read mcp:write")
	assert.Equal(t, "mcp:read", tok["scope"], "the user narrowed the client's request")
	access := tok["access_token"].(string)
	names := h.toolNames(access)
	for _, name := range writeTools {
		assert.NotContains(t, names, name)
	}
	for name, args := range h.writeArgs() {
		_, isErr := h.callTool(access, name, args)
		assert.True(t, isErr, "a read-scoped token cannot call %s", name)
	}
	assert.Empty(t, h.w.api.created)
	assert.Empty(t, h.w.api.reactions)
}

func TestNoChoiceMeansReadOnly(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	_, tok := h.connect("")
	assert.Equal(t, "mcp:read", tok["scope"])
}

func TestReadAndWriteChoiceCanPost(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	h.choice = "write"
	_, tok := h.connect("")
	assert.Equal(t, "mcp:read mcp:write", tok["scope"])
	access := tok["access_token"].(string)
	names := h.toolNames(access)
	for name, args := range h.writeArgs() {
		assert.Contains(t, names, name)
		text, isErr := h.callTool(access, name, args)
		assert.False(t, isErr, text)
	}
	text, isErr := h.callTool(access, "post_message", map[string]any{"channel": h.w.bobPriv.Id, "message": "hi"})
	assert.True(t, isErr, text)

	h.setConfig(func(c *configuration) { c.EnableWriteTools = false })
	assert.NotContains(t, h.toolNames(access), "post_message", "the admin ceiling hides write tools from existing grants")
}

func TestWriteGrantImpossibleWhenCeilingIsOff(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = false })

	var asm map[string]any
	rec := h.do(http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil, nil)
	require.NoError(t, jsonUnmarshal(rec.Body.Bytes(), &asm))
	assert.Equal(t, []any{"mcp:read"}, asm["scopes_supported"])

	// The client asks for write and the user tampers the form to choose it: refused.
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	page := h.consentPage(clientID, challenge, "mcp:read mcp:write")
	assert.NotContains(t, page.Body.String(), `value="write"`, "no write choice is offered")
	assert.Contains(t, page.Body.String(), "An administrator has turned posting off")
	rec = h.decide(page, "write")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"), "no code is issued")

	// Choosing read still works, and the token carries read only.
	h.choice = "read"
	_, tok := h.connect("mcp:read mcp:write")
	assert.Equal(t, "mcp:read", tok["scope"])
}

func TestWriteChoiceRefusedWhenClientAskedOnlyToRead(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	page := h.consentPage(clientID, challenge, "mcp:read")
	assert.NotContains(t, page.Body.String(), `value="write"`)
	assert.Contains(t, page.Body.String(), "did not ask for posting")
	rec := h.decide(page, "write")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCeilingTurnedOffDuringConsentRefusesWrite(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	page := h.consentPage(clientID, challenge, "")
	assert.Contains(t, page.Body.String(), `value="write"`)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = false })
	rec := h.decide(page, "write")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUnknownScopeIsRefused(t *testing.T) {
	h := newHarness(t)
	clientID := h.registerPublic()
	_, challenge := pkcePair()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "scope": {"mcp:read admin"},
	}
	rec := h.do(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, h.w.alice, nil)
	require.Equal(t, http.StatusFound, rec.Code)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	assert.Equal(t, "invalid_scope", loc.Query().Get("error"))
}

func TestRefreshKeepsTheChosenScope(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	h.choice = "read"
	clientID, tok := h.connect("")
	code, out := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}, "scope": {"mcp:read mcp:write"}})
	assert.Equal(t, http.StatusBadRequest, code, "a refresh cannot widen a read-only grant")
	assert.Equal(t, "invalid_scope", out["error"])
	code, out = h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}})
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "mcp:read", out["scope"])
}

func TestConnectionsPageShowsTheGrantedScope(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	h.choice = "write"
	h.connect("")
	body := h.do(http.MethodGet, "/connections", nil, h.w.alice, nil).Body.String()
	assert.Contains(t, body, "Read and write")
	assert.Contains(t, body, "<code>mcp:read mcp:write</code>")
}

// TestWriteToolsRecheckScopeOnEachCall builds a tool set as if for a write grant and calls it with no
// token at all: the per-call check must refuse, independent of how the tool set was built.
func TestWriteToolsRecheckScopeOnEachCall(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	server := h.p.newMCPServer(identity{UserID: h.w.alice.Id, ClientName: "c", Scopes: []string{scopeRead, scopeWrite}})
	ctx := context.Background()
	st, ct := mcp.NewInMemoryTransports()
	_, err := server.Connect(ctx, st, nil)
	require.NoError(t, err)
	session, err := mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(ctx, ct, nil)
	require.NoError(t, err)
	defer func() { _ = session.Close() }()
	for name, args := range h.writeArgs() {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		require.NoError(t, err)
		assert.True(t, res.IsError, name)
	}
	assert.Empty(t, h.w.api.created)
	assert.Empty(t, h.w.api.reactions)
}
