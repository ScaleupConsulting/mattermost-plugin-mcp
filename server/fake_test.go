package main

import (
	"bytes"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
)

// fakeAPI is an in-memory Mattermost for tests. Its list and search methods are deliberately
// leaky: they return every matching object regardless of membership, the way the plugin API's
// system privileges would let a careless caller see them, so the tests prove the plugin filters.
type fakeAPI struct {
	mu sync.Mutex

	siteURL     string
	users       map[string]*model.User
	teams       map[string]*model.Team
	teamMembers map[string]map[string]*model.TeamMember // team -> user
	channels    map[string]*model.Channel
	chMembers   map[string]map[string]*model.ChannelMember // channel -> user
	posts       map[string]*model.Post
	sessions    map[string]*model.Session
	kv          map[string]kvEntry

	// permissive makes HasPermissionToChannel answer true for everyone, like a system admin's role.
	permissive bool
	// denied lists "user|channel|permission" triples HasPermissionToChannel refuses.
	denied map[string]bool

	created   []*model.Post
	reactions []*model.Reaction
	clock     time.Time
}

type kvEntry struct {
	value    []byte
	expireAt time.Time
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		siteURL:     "https://chat.example.com",
		users:       map[string]*model.User{},
		teams:       map[string]*model.Team{},
		teamMembers: map[string]map[string]*model.TeamMember{},
		channels:    map[string]*model.Channel{},
		chMembers:   map[string]map[string]*model.ChannelMember{},
		posts:       map[string]*model.Post{},
		sessions:    map[string]*model.Session{},
		kv:          map[string]kvEntry{},
		denied:      map[string]bool{},
		clock:       time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC),
	}
}

func (f *fakeAPI) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.clock }

func (f *fakeAPI) advance(d time.Duration) { f.mu.Lock(); f.clock = f.clock.Add(d); f.mu.Unlock() }

func notFound() *model.AppError {
	return model.NewAppError("fake", "not_found", nil, "", http.StatusNotFound)
}

// Seeding helpers.

func (f *fakeAPI) addUser(username string) *model.User {
	u := &model.User{Id: model.NewId(), Username: username, FirstName: strings.ToUpper(username[:1]) + username[1:]}
	f.users[u.Id] = u
	return u
}

func (f *fakeAPI) addTeam(name string, members ...*model.User) *model.Team {
	t := &model.Team{Id: model.NewId(), Name: name, DisplayName: strings.ToUpper(name)}
	f.teams[t.Id] = t
	f.teamMembers[t.Id] = map[string]*model.TeamMember{}
	for _, u := range members {
		f.teamMembers[t.Id][u.Id] = &model.TeamMember{TeamId: t.Id, UserId: u.Id}
	}
	return t
}

func (f *fakeAPI) addChannel(team *model.Team, name string, typ model.ChannelType, members ...*model.User) *model.Channel {
	ch := &model.Channel{Id: model.NewId(), Name: name, DisplayName: name, Type: typ}
	if team != nil {
		ch.TeamId = team.Id
	}
	if typ == model.ChannelTypeDirect {
		ch.Name = model.GetDMNameFromIds(members[0].Id, members[1].Id)
	}
	f.channels[ch.Id] = ch
	f.chMembers[ch.Id] = map[string]*model.ChannelMember{}
	for _, u := range members {
		f.chMembers[ch.Id][u.Id] = &model.ChannelMember{ChannelId: ch.Id, UserId: u.Id}
	}
	return ch
}

func (f *fakeAPI) addPost(ch *model.Channel, author *model.User, msg string, rootID string) *model.Post {
	f.clock = f.clock.Add(time.Minute)
	p := &model.Post{Id: model.NewId(), ChannelId: ch.Id, UserId: author.Id, Message: msg, RootId: rootID, CreateAt: f.clock.UnixMilli()}
	f.posts[p.Id] = p
	ch.TotalMsgCount++
	return p
}

// mmAPI implementation.

func (f *fakeAPI) GetConfig() *model.Config {
	c := &model.Config{}
	c.SetDefaults()
	c.ServiceSettings.SiteURL = model.NewPointer(f.siteURL)
	return c
}

func (f *fakeAPI) GetUser(id string) (*model.User, *model.AppError) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) GetUserByUsername(name string) (*model.User, *model.AppError) {
	for _, u := range f.users {
		if u.Username == name {
			return u, nil
		}
	}
	return nil, notFound()
}

func (f *fakeAPI) GetUsersByIds(ids []string) ([]*model.User, *model.AppError) {
	var out []*model.User
	for _, id := range ids {
		if u, ok := f.users[id]; ok {
			out = append(out, u)
		}
	}
	return out, nil
}

// SearchUsers ignores TeamId on purpose (leaky); the plugin must confirm team membership itself.
func (f *fakeAPI) SearchUsers(s *model.UserSearch) ([]*model.User, *model.AppError) {
	var out []*model.User
	for _, u := range f.users {
		if strings.Contains(u.Username, s.Term) {
			out = append(out, u)
		}
	}
	return out, nil
}

func (f *fakeAPI) GetTeam(id string) (*model.Team, *model.AppError) {
	if t, ok := f.teams[id]; ok {
		return t, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) GetTeamsForUser(userID string) ([]*model.Team, *model.AppError) {
	var out []*model.Team
	for id, members := range f.teamMembers {
		if m, ok := members[userID]; ok && m.DeleteAt == 0 {
			out = append(out, f.teams[id])
		}
	}
	return out, nil
}

func (f *fakeAPI) GetTeamMember(teamID, userID string) (*model.TeamMember, *model.AppError) {
	if m, ok := f.teamMembers[teamID][userID]; ok {
		return m, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) GetChannel(id string) (*model.Channel, *model.AppError) {
	if ch, ok := f.channels[id]; ok {
		return ch, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) GetChannelByNameForTeamName(teamName, channelName string, _ bool) (*model.Channel, *model.AppError) {
	for _, ch := range f.channels {
		if t, ok := f.teams[ch.TeamId]; ok && t.Name == teamName && ch.Name == channelName {
			return ch, nil
		}
	}
	return nil, notFound()
}

// GetChannelsForTeamForUser returns every channel in the team and every DM and GM (leaky).
func (f *fakeAPI) GetChannelsForTeamForUser(teamID, _ string, _ bool) ([]*model.Channel, *model.AppError) {
	var out []*model.Channel
	for _, ch := range f.channels {
		if ch.TeamId == teamID || ch.TeamId == "" {
			out = append(out, ch)
		}
	}
	return out, nil
}

func (f *fakeAPI) GetChannelMember(channelID, userID string) (*model.ChannelMember, *model.AppError) {
	if m, ok := f.chMembers[channelID][userID]; ok {
		return m, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) HasPermissionToChannel(userID, channelID string, perm *model.Permission) bool {
	if f.denied[userID+"|"+channelID+"|"+perm.Id] {
		return false
	}
	if f.permissive {
		return true
	}
	_, ok := f.chMembers[channelID][userID]
	return ok
}

func (f *fakeAPI) GetPost(id string) (*model.Post, *model.AppError) {
	if p, ok := f.posts[id]; ok {
		return p, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) GetPostThread(id string) (*model.PostList, *model.AppError) {
	root, ok := f.posts[id]
	if !ok {
		return nil, notFound()
	}
	list := model.NewPostList()
	list.AddPost(root)
	for _, p := range f.posts {
		if p.RootId == id {
			list.AddPost(p)
		}
	}
	return list, nil
}

func (f *fakeAPI) GetPostsForChannel(channelID string, page, perPage int) (*model.PostList, *model.AppError) {
	var posts []*model.Post
	for _, p := range f.posts {
		if p.ChannelId == channelID {
			posts = append(posts, p)
		}
	}
	sort.Slice(posts, func(i, j int) bool { return posts[i].CreateAt > posts[j].CreateAt })
	list := model.NewPostList()
	for i := page * perPage; i < len(posts) && i < (page+1)*perPage; i++ {
		list.AddPost(posts[i])
		list.AddOrder(posts[i].Id)
	}
	return list, nil
}

// SearchPostsInTeamForUser matches every post containing the terms, in any channel (leaky).
func (f *fakeAPI) SearchPostsInTeamForUser(_, _ string, params model.SearchParameter) (*model.PostSearchResults, *model.AppError) {
	list := model.NewPostList()
	for _, p := range f.posts {
		if strings.Contains(p.Message, *params.Terms) {
			list.AddPost(p)
			list.AddOrder(p.Id)
		}
	}
	return &model.PostSearchResults{PostList: list}, nil
}

func (f *fakeAPI) CreatePost(p *model.Post) (*model.Post, *model.AppError) {
	p.Id = model.NewId()
	p.CreateAt = f.clock.UnixMilli()
	f.posts[p.Id] = p
	f.created = append(f.created, p)
	return p, nil
}

func (f *fakeAPI) AddReaction(r *model.Reaction) (*model.Reaction, *model.AppError) {
	f.reactions = append(f.reactions, r)
	return r, nil
}

func (f *fakeAPI) GetSession(id string) (*model.Session, *model.AppError) {
	if s, ok := f.sessions[id]; ok {
		return s, nil
	}
	return nil, notFound()
}

func (f *fakeAPI) KVGet(key string) ([]byte, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.kv[key]
	if !ok || (!e.expireAt.IsZero() && !f.clock.Before(e.expireAt)) {
		return nil, nil
	}
	return e.value, nil
}

// KVSetWithOptions follows the server: atomic with a nil old value means insert-if-absent, and a
// nil new value deletes.
func (f *fakeAPI) KVSetWithOptions(key string, value []byte, opts model.PluginKVSetOptions) (bool, *model.AppError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, exists := f.kv[key]
	if exists && !e.expireAt.IsZero() && !f.clock.Before(e.expireAt) {
		exists = false
	}
	if opts.Atomic {
		if opts.OldValue == nil && exists {
			return false, nil
		}
		if opts.OldValue != nil && (!exists || !bytes.Equal(e.value, opts.OldValue)) {
			return false, nil
		}
	}
	if value == nil {
		delete(f.kv, key)
		return true, nil
	}
	ne := kvEntry{value: value}
	if opts.ExpireInSeconds > 0 {
		ne.expireAt = f.clock.Add(time.Duration(opts.ExpireInSeconds) * time.Second)
	}
	f.kv[key] = ne
	return true, nil
}

func (f *fakeAPI) KVDelete(key string) *model.AppError {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.kv, key)
	return nil
}

func (f *fakeAPI) LogWarn(string, ...any)  {}
func (f *fakeAPI) LogError(string, ...any) {}
