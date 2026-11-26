package main

import (
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// world is a seeded workspace: alice and bob share team "core"; bob alone is in team "ops".
type world struct {
	api                   *fakeAPI
	alice, bob, carol     *model.User
	dave                  *model.User
	core, ops             *model.Team
	town, alicePriv       *model.Channel
	bobPriv, opsChan      *model.Channel
	dmAliceBob, dmBobCarl *model.Channel
	gmBobCarolDave        *model.Channel
	townPost, bobPrivPost *model.Post
	opsPost, dmBobPost    *model.Post
	gmPost, bobPrivReply  *model.Post
}

func newWorld() *world {
	f := newFakeAPI()
	w := &world{api: f}
	w.alice, w.bob, w.carol, w.dave = f.addUser("alice"), f.addUser("bob"), f.addUser("carol"), f.addUser("dave")
	w.core = f.addTeam("core", w.alice, w.bob, w.carol)
	w.ops = f.addTeam("ops", w.bob, w.dave)
	w.town = f.addChannel(w.core, "town-square", model.ChannelTypeOpen, w.alice, w.bob, w.carol)
	w.alicePriv = f.addChannel(w.core, "alice-private", model.ChannelTypePrivate, w.alice)
	w.bobPriv = f.addChannel(w.core, "bob-private", model.ChannelTypePrivate, w.bob)
	w.opsChan = f.addChannel(w.ops, "ops-public", model.ChannelTypeOpen, w.bob, w.dave)
	w.dmAliceBob = f.addChannel(nil, "", model.ChannelTypeDirect, w.alice, w.bob)
	w.dmBobCarl = f.addChannel(nil, "", model.ChannelTypeDirect, w.bob, w.carol)
	w.gmBobCarolDave = f.addChannel(nil, "bob, carol, dave", model.ChannelTypeGroup, w.bob, w.carol, w.dave)

	w.townPost = f.addPost(w.town, w.bob, "secret plan is public here", "")
	w.bobPrivPost = f.addPost(w.bobPriv, w.bob, "secret plan in bob's private channel", "")
	w.bobPrivReply = f.addPost(w.bobPriv, w.bob, "secret reply", w.bobPrivPost.Id)
	w.opsPost = f.addPost(w.opsChan, w.bob, "secret plan in a team alice is not in", "")
	w.dmBobPost = f.addPost(w.dmBobCarl, w.bob, "secret plan in bob and carol's DM", "")
	w.gmPost = f.addPost(w.gmBobCarolDave, w.carol, "secret plan in a group message", "")
	f.addPost(w.dmAliceBob, w.bob, "hi alice", "")
	f.addPost(w.alicePriv, w.alice, "note to self", "")
	return w
}

// as returns alice's toolset with HasPermissionToChannel answering true everywhere, as it would for
// a system admin, so only the plugin's own membership checks stand between alice and the data.
func (w *world) asAlice() *toolset {
	w.api.permissive = true
	ts := newToolset(w.api, w.alice.Id, w.api.siteURL, "test client")
	ts.drafts = w.api
	return ts
}

// forbidden are the channels alice must never reach, by every way of naming them.
func (w *world) forbidden() map[string]*model.Channel {
	return map[string]*model.Channel{
		"private channel":           w.bobPriv,
		"channel in another team":   w.opsChan,
		"someone else's DM":         w.dmBobCarl,
		"someone else's group chat": w.gmBobCarolDave,
	}
}

func TestReadChannelRefusesChannelsTheUserIsNotIn(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	for name, ch := range w.forbidden() {
		t.Run(name, func(t *testing.T) {
			_, err := ts.ReadChannel(ch.Id, "", "", 0)
			assert.ErrorIs(t, err, errNoAccess)
			if ch.TeamId != "" {
				_, err = ts.ReadChannel(w.api.teams[ch.TeamId].Name+"/"+ch.Name, "", "", 0)
				assert.ErrorIs(t, err, errNoAccess)
			}
		})
	}
	out, err := ts.ReadChannel(w.town.Id, "", "", 0)
	require.NoError(t, err)
	assert.Contains(t, out, "secret plan is public here")
	assert.Contains(t, out, "https://chat.example.com/core/pl/"+w.townPost.Id)
}

func TestMissingAndForbiddenLookTheSame(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	_, errMissing := ts.ReadChannel(model.NewId(), "", "", 0)
	_, errForbidden := ts.ReadChannel(w.bobPriv.Id, "", "", 0)
	require.Error(t, errMissing)
	require.Error(t, errForbidden)
	assert.Equal(t, errMissing.Error(), errForbidden.Error())
}

func TestReadThreadRefusesPostsInOtherChannels(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	for _, p := range []*model.Post{w.bobPrivPost, w.bobPrivReply, w.opsPost, w.dmBobPost, w.gmPost} {
		_, err := ts.ReadThread(p.Id)
		assert.ErrorIs(t, err, errNoAccess)
		_, err = ts.ReadThread("https://chat.example.com/core/pl/" + p.Id)
		assert.ErrorIs(t, err, errNoAccess)
	}
	out, err := ts.ReadThread(w.townPost.Id)
	require.NoError(t, err)
	assert.Contains(t, out, "secret plan is public here")
}

func TestSearchShowsOnlyReadableChannels(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	out, err := ts.SearchPosts("secret", "", 0)
	require.NoError(t, err)
	assert.Contains(t, out, w.townPost.Id)
	for _, p := range []*model.Post{w.bobPrivPost, w.bobPrivReply, w.opsPost, w.dmBobPost, w.gmPost} {
		assert.NotContains(t, out, p.Id)
		assert.NotContains(t, out, p.Message)
	}
	assert.Contains(t, out, "1 result(s)")

	_, err = ts.SearchPosts("secret", "ops", 0)
	assert.Error(t, err, "searching a team alice is not in")
}

func TestListingsShowOnlyTheUsersOwn(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()

	teams, err := ts.ListTeams()
	require.NoError(t, err)
	assert.Contains(t, teams, "core")
	assert.NotContains(t, teams, "ops")

	channels, err := ts.ListChannels("", true)
	require.NoError(t, err)
	assert.Contains(t, channels, w.town.Id)
	assert.Contains(t, channels, w.alicePriv.Id)
	assert.Contains(t, channels, "DM with @bob")
	for _, ch := range w.forbidden() {
		assert.NotContains(t, channels, ch.Id)
	}
	_, err = ts.ListChannels("ops", false)
	assert.Error(t, err)

	unreads, err := ts.GetUnreads()
	require.NoError(t, err)
	assert.Contains(t, unreads, w.town.Id)
	for _, ch := range w.forbidden() {
		assert.NotContains(t, unreads, ch.Id)
	}
}

func TestFindUsersOnlyInSharedTeams(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	out, err := ts.FindUsers("a")
	require.NoError(t, err)
	assert.Contains(t, out, "@carol")
	assert.NotContains(t, out, "@dave", "dave shares no team with alice")
}

func TestWriteToolsRefuseChannelsTheUserIsNotIn(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	for name, ch := range w.forbidden() {
		_, err := ts.PostMessage(ch.Id, "hello")
		assert.ErrorIs(t, err, errNoAccess, name)
	}
	for _, p := range []*model.Post{w.bobPrivPost, w.opsPost, w.dmBobPost, w.gmPost} {
		_, err := ts.ReplyInThread(p.Id, "hello")
		assert.ErrorIs(t, err, errNoAccess)
		_, err = ts.AddReaction(p.Id, "thumbsup")
		assert.ErrorIs(t, err, errNoAccess)
	}
	assert.Empty(t, w.api.created)
	assert.Empty(t, w.api.reactions)

	out, err := ts.ReplyInThread(w.townPost.Id, "on it")
	require.NoError(t, err)
	assert.Contains(t, out, "Posted in")
	require.Len(t, w.api.created, 1)
	assert.Equal(t, w.alice.Id, w.api.created[0].UserId)
	assert.Equal(t, w.townPost.Id, w.api.created[0].RootId)
	assert.Equal(t, "test client", w.api.created[0].GetProp("mcp_client"))
}

func TestRolePermissionStillApplies(t *testing.T) {
	w := newWorld()
	ts := newToolset(w.api, w.alice.Id, w.api.siteURL, "c")
	w.api.denied[w.alice.Id+"|"+w.town.Id+"|"+model.PermissionCreatePost.Id] = true
	_, err := ts.PostMessage(w.town.Id, "hello")
	assert.ErrorIs(t, err, errNoAccess, "a read-only channel refuses posting even to members")
	_, err = ts.ReadChannel(w.town.Id, "", "", 0)
	assert.NoError(t, err)
}

func TestLeavingTheTeamRevokesItsChannels(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	w.api.teamMembers[w.core.Id][w.alice.Id].DeleteAt = 1
	_, err := ts.ReadChannel(w.town.Id, "", "", 0)
	assert.ErrorIs(t, err, errNoAccess)
}

func TestReadChannelTimeRangeAndPaging(t *testing.T) {
	w := newWorld()
	ts := w.asAlice()
	var posts []*model.Post
	for range 5 {
		posts = append(posts, w.api.addPost(w.alicePriv, w.alice, "entry", ""))
	}
	out, err := ts.ReadChannel(w.alicePriv.Id, "", "", 2)
	require.NoError(t, err)
	assert.Contains(t, out, posts[4].Id)
	assert.Contains(t, out, posts[3].Id)
	assert.NotContains(t, out, posts[2].Id)
	assert.Contains(t, out, "Older posts exist: call again with before=")

	since := formatRFC3339(posts[1].CreateAt)
	before := formatRFC3339(posts[3].CreateAt)
	out, err = ts.ReadChannel(w.alicePriv.Id, since, before, 0)
	require.NoError(t, err)
	assert.Contains(t, out, posts[1].Id)
	assert.Contains(t, out, posts[2].Id)
	assert.NotContains(t, out, posts[0].Id)
	assert.NotContains(t, out, posts[3].Id)
}

func formatRFC3339(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano)
}
