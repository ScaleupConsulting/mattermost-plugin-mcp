package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the findings of the v1.1 security review.

// codeFlow runs consent for alice and returns the client, verifier and the code exchange form.
func (h *harness) codeFlow() (clientID string, form url.Values) {
	clientID = h.registerPublic()
	verifier, challenge := pkcePair()
	loc := h.authorize(clientID, challenge, "", h.w.alice)
	return clientID, url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {loc.Query().Get("code")},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier}}
}

func TestSpentCodeFromAnotherClientDoesNotRevoke(t *testing.T) {
	h := newHarness(t)
	_, form := h.codeFlow()
	code, tok := h.token(form)
	require.Equal(t, http.StatusOK, code)
	access := tok["access_token"].(string)

	other := h.registerPublic()
	stolen := url.Values{}
	for k, v := range form {
		stolen[k] = v
	}
	stolen.Set("client_id", other)
	code, out := h.token(stolen)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
	assert.Equal(t, http.StatusOK, h.mcp(access, "tools/list", map[string]any{}).Code, "another client cannot disconnect alice with a spent code")

	code, _ = h.token(form)
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code, "a replay by the code's own client still revokes")
}

func TestReplayBeforeTheGrantIsSavedStillRevokes(t *testing.T) {
	h := newHarness(t)
	_, form := h.codeFlow()
	replayed := false
	var replayCode int
	h.w.api.afterSet = func(key string, value []byte) {
		// The moment the code is marked used, and before its grant is saved, the code is replayed.
		if !replayed && strings.HasPrefix(key, keyCode) && strings.Contains(string(value), `"used":true`) {
			replayed = true
			replayCode, _ = h.token(form)
		}
	}
	code, out := h.token(form)
	require.True(t, replayed)
	assert.Equal(t, http.StatusBadRequest, replayCode)
	assert.Equal(t, http.StatusBadRequest, code, "the first redemption must not hand out tokens after a replay")
	assert.Equal(t, "invalid_grant", out["error"])
	grants, err := h.p.oauth.store.listGrants(h.w.alice.Id)
	require.NoError(t, err)
	assert.Empty(t, grants)
}

func TestPasswordChangeEndsTheConnection(t *testing.T) {
	h := newHarness(t)
	clientID, tok := h.connect("")
	access := tok["access_token"].(string)
	require.Equal(t, http.StatusOK, h.mcp(access, "tools/list", map[string]any{}).Code)

	h.w.alice.LastPasswordUpdate += 1000
	assert.Equal(t, http.StatusUnauthorized, h.mcp(access, "tools/list", map[string]any{}).Code)
	code, out := h.token(url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {tok["refresh_token"].(string)}})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_grant", out["error"])
	grants, err := h.p.oauth.store.listGrants(h.w.alice.Id)
	require.NoError(t, err)
	assert.Empty(t, grants, "the refresh attempt revoked the grant")
}

func TestFindUsersHonoursShowFullName(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	out, err := ts.FindUsers("bob")
	require.NoError(t, err)
	assert.Contains(t, out, "Bob", "full names show by default")

	w.api.configure = func(c *model.Config) { c.PrivacySettings.ShowFullName = model.NewPointer(false) }
	out, err = w.asAlice().FindUsers("bob")
	require.NoError(t, err)
	assert.Contains(t, out, "@bob")
	assert.NotContains(t, out, "Bob")
}

func TestRegistrationCapPerAddress(t *testing.T) {
	h := newHarness(t)
	reg := func(ip string) int {
		body := `{"client_name":"x","redirect_uris":["` + testRedirect + `"],"token_endpoint_auth_method":"none"}`
		return h.do(http.MethodPost, "/oauth/register", strings.NewReader(body), nil, map[string]string{"Content-Type": "application/json", "X-Real-IP": ip}).Code
	}
	for range registrationsPerIPPerHour {
		require.Equal(t, http.StatusCreated, reg("203.0.113.7"))
	}
	assert.Equal(t, http.StatusTooManyRequests, reg("203.0.113.7"), "one address cannot use up the server-wide cap")
	assert.Equal(t, http.StatusCreated, reg("198.51.100.9"), "other addresses can still register")
}
