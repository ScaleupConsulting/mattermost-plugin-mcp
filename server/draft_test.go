package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveDraftRefusesChannelsTheUserIsNotIn(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	for name, ch := range w.forbidden() {
		_, err := ts.SaveDraft(ch.Id, "", "hello")
		assert.ErrorIs(t, err, errNoAccess, name)
		_, err = ts.DeleteDraft(ch.Id, "")
		assert.ErrorIs(t, err, errNoAccess, name)
	}
	for _, p := range []*model.Post{w.bobPrivPost, w.opsPost, w.dmBobPost, w.gmPost} {
		_, err := ts.SaveDraft("", p.Id, "hello")
		assert.ErrorIs(t, err, errNoAccess)
	}
	_, err := ts.SaveDraft(w.town.Id, w.bobPrivPost.Id, "hello")
	assert.ErrorIs(t, err, errNoAccess, "naming an allowed channel does not unlock a forbidden thread")
	_, err = ts.SaveDraft(w.alicePriv.Id, w.townPost.Id, "hello")
	assert.Error(t, err, "a thread in another channel is refused rather than drafted somewhere unexpected")
	assert.Empty(t, w.api.drafts)
	assert.Empty(t, w.api.created, "drafting never posts")
}

func TestSaveDraftNeedsCreatePost(t *testing.T) {
	w := newWorld()
	ts := newToolset(w.api, w.alice.Id, w.api.siteURL, "c")
	ts.drafts = w.api
	w.api.denied[w.alice.Id+"|"+w.town.Id+"|"+model.PermissionCreatePost.Id] = true
	_, err := ts.SaveDraft(w.town.Id, "", "hello")
	assert.ErrorIs(t, err, errNoAccess, "a read-only channel refuses drafts as it refuses posts")
	assert.Empty(t, w.api.drafts)
}

func TestDraftsInChannelAndThreadAreSavedListedAndDeleted(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	reply := w.api.addPost(w.town, w.bob, "a reply", w.townPost.Id)

	out, err := ts.SaveDraft(w.town.Id, "", "channel draft")
	require.NoError(t, err)
	assert.Contains(t, out, "has not been sent")
	_, err = ts.SaveDraft("", reply.Id, "thread draft") // any post in the thread drafts at its root
	require.NoError(t, err)
	_, err = ts.SaveDraft(w.dmAliceBob.Id, "", "dm draft")
	require.NoError(t, err)
	require.Len(t, w.api.drafts, 3)
	assert.Equal(t, "thread draft", w.api.drafts[w.alice.Id+"|"+w.town.Id+"|"+w.townPost.Id].Message)
	assert.Empty(t, w.api.created, "drafting never posts")

	// Bob's draft in his private channel must not show in alice's list.
	require.NoError(t, w.api.UpsertDraft(w.bob.Id, &model.Draft{ChannelId: w.bobPriv.Id, Message: "bob's secret draft"}))
	// A draft alice left in a channel she has since left must not show either.
	require.NoError(t, w.api.UpsertDraft(w.alice.Id, &model.Draft{ChannelId: w.bobPriv.Id, Message: "stale draft"}))

	list, err := ts.ListDrafts("")
	require.NoError(t, err)
	assert.Contains(t, list, "3 draft(s)")
	for _, want := range []string{"channel draft", "thread draft", "dm draft"} {
		assert.Contains(t, list, want)
	}
	assert.NotContains(t, list, "bob's secret draft")
	assert.NotContains(t, list, "stale draft")

	_, err = ts.DeleteDraft("", w.townPost.Id)
	require.NoError(t, err)
	_, ok := w.api.drafts[w.alice.Id+"|"+w.town.Id+"|"+w.townPost.Id]
	assert.False(t, ok, "the thread draft is gone")
	_, ok = w.api.drafts[w.alice.Id+"|"+w.town.Id+"|"]
	assert.True(t, ok, "the channel draft stays")
}

func TestReadScopedTokenCanDraftButNotPost(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableWriteTools = true })
	h.choice = "read"
	_, tok := h.connect("")
	access := tok["access_token"].(string)
	names := h.toolNames(access)
	for _, name := range []string{"save_draft", "list_drafts", "delete_draft"} {
		assert.Contains(t, names, name)
	}
	text, isErr := h.callTool(access, "save_draft", map[string]any{"channel": h.w.town.Id, "message": "draft from a read-only token"})
	assert.False(t, isErr, text)
	assert.Len(t, h.w.api.drafts, 1)
	text, isErr = h.callTool(access, "post_message", map[string]any{"channel": h.w.town.Id, "message": "hi"})
	assert.True(t, isErr, text)
	assert.Empty(t, h.w.api.created)

	h.setConfig(func(c *configuration) { c.ToolsDrafts = false })
	assert.NotContains(t, h.toolNames(access), "save_draft", "the drafts tool group can be turned off")
}

func TestLocalAPIURL(t *testing.T) {
	cfg := &model.Config{}
	cfg.SetDefaults()
	*cfg.ServiceSettings.SiteURL = "https://chat.example.com/mm/"
	*cfg.ServiceSettings.ListenAddress = ":8065"
	got, err := localAPIURL(cfg)
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8065/mm", got)
	*cfg.ServiceSettings.ListenAddress = "10.0.0.5:9000"
	got, _ = localAPIURL(cfg)
	assert.Equal(t, "http://10.0.0.5:9000/mm", got)
	*cfg.ServiceSettings.ConnectionSecurity = model.ConnSecurityTLS
	_, err = localAPIURL(cfg)
	assert.Error(t, err)
}

// sessionFake records sessions for restDrafts and points the config at a test server.
type sessionFake struct {
	*fakeAPI
	cfg     *model.Config
	created []*model.Session
	revoked []string
}

func (s *sessionFake) GetConfig() *model.Config { return s.cfg }
func (s *sessionFake) CreateSession(in *model.Session) (*model.Session, *model.AppError) {
	c := *in
	c.Id, c.Token = model.NewId(), "session-token-"+model.NewId()
	s.created = append(s.created, &c)
	return &c, nil
}
func (s *sessionFake) RevokeSession(id string) *model.AppError {
	s.revoked = append(s.revoked, id)
	return nil
}

// TestRestDraftsCallsTheAPIAsTheUserAndRevokesTheSession checks the REST client against a stand-in
// server: the right routes, the user's own short-lived session, a thread-aware delete, and revocation.
func TestRestDraftsCallsTheAPIAsTheUserAndRevokesTheSession(t *testing.T) {
	w := newWorld()
	var seen []string
	var tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		tokens = append(tokens, r.Header.Get("Authorization"))
		switch r.Method {
		case http.MethodPost:
			rw.WriteHeader(http.StatusCreated)
			_, _ = rw.Write([]byte(`{"channel_id":"c"}`))
		case http.MethodGet:
			_, _ = rw.Write([]byte(`[{"user_id":"u","channel_id":"c","message":"m"}]`))
		default:
			_, _ = rw.Write([]byte(`{"status":"OK"}`))
		}
	}))
	defer srv.Close()
	cfg := &model.Config{}
	cfg.SetDefaults()
	*cfg.ServiceSettings.ListenAddress = strings.TrimPrefix(srv.URL, "http://")
	sf := &sessionFake{fakeAPI: w.api, cfg: cfg}
	d := newRestDrafts(sf)

	require.NoError(t, d.UpsertDraft(w.alice.Id, &model.Draft{ChannelId: w.town.Id, Message: "m"}))
	drafts, err := d.GetDrafts(w.alice.Id, w.core.Id)
	require.NoError(t, err)
	assert.Len(t, drafts, 1)
	require.NoError(t, d.DeleteDraft(w.alice.Id, w.town.Id, w.townPost.Id))

	assert.Equal(t, []string{
		"POST /api/v4/drafts",
		"GET /api/v4/users/" + w.alice.Id + "/teams/" + w.core.Id + "/drafts",
		"DELETE /api/v4/users/" + w.alice.Id + "/channels/" + w.town.Id + "/drafts/" + w.townPost.Id,
	}, seen)
	require.Len(t, sf.created, 3)
	for i, s := range sf.created {
		assert.Equal(t, w.alice.Id, s.UserId)
		assert.True(t, strings.EqualFold(tokens[i], "Bearer "+s.Token), "the call used the session created for it")
		assert.Less(t, s.ExpiresAt-model.GetMillis(), int64(draftSessionTTL.Milliseconds())+1)
	}
	assert.Len(t, sf.revoked, 3, "every session is revoked after its call")
}
