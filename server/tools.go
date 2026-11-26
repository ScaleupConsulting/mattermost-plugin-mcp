package main

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

const (
	defaultPostLimit = 50
	maxPostLimit     = 200
	scanPageSize     = 200
	maxScanPosts     = 5000
	maxSearchResults = 100
	maxUserResults   = 50
	maxMessageRunes  = model.PostMessageMaxRunesV2
)

// errNoAccess is the one answer for a channel or post that does not exist or that the user cannot
// see, so a tool cannot be used to probe for private channels.
var errNoAccess = errors.New("not found, or you do not have access to it")

// toolset runs the MCP tools for one user. The plugin API acts with system privileges, so every
// method checks the user's own access before it reads or writes anything.
type toolset struct {
	api        mmAPI
	userID     string
	siteURL    string
	clientName string
	now        func() time.Time
	// drafts reads and writes the user's own drafts; nil when the draft tools are off.
	drafts draftAPI

	usernames map[string]string
	teams     map[string]*model.Team
	members   map[string]bool
}

// newToolset prepares a toolset for one request.
func newToolset(api mmAPI, userID, siteURL, clientName string) *toolset {
	return &toolset{
		api: api, userID: userID, siteURL: strings.TrimRight(siteURL, "/"), clientName: clientName, now: time.Now,
		usernames: map[string]string{}, teams: map[string]*model.Team{}, members: map[string]bool{},
	}
}

var idPattern = regexp.MustCompile(`(?:^|/)([a-z0-9]{26})/?$`)

// extractID accepts a bare 26-character id or a URL ending in one, such as a permalink.
func extractID(ref string) (string, bool) {
	m := idPattern.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// resolveChannel finds a channel by id or "team-name/channel-name" without any access check.
func (t *toolset) resolveChannel(ref string) (*model.Channel, error) {
	ref = strings.TrimSpace(ref)
	if id, ok := extractID(ref); ok {
		ch, appErr := t.api.GetChannel(id)
		if appErr != nil {
			return nil, errNoAccess
		}
		return ch, nil
	}
	teamName, channelName, ok := strings.Cut(strings.TrimPrefix(ref, "~"), "/")
	if !ok || teamName == "" || channelName == "" {
		return nil, errors.New("give a channel id, or team-name/channel-name as list_channels shows it")
	}
	ch, appErr := t.api.GetChannelByNameForTeamName(teamName, strings.TrimPrefix(channelName, "~"), true)
	if appErr != nil {
		return nil, errNoAccess
	}
	return ch, nil
}

// canAccess reports whether the user is a member of the channel, still in its team, and holds perm
// there. Membership is required even when the role would allow more, such as a system admin reading
// someone else's direct messages.
func (t *toolset) canAccess(ch *model.Channel, perm *model.Permission) bool {
	cacheKey := ch.Id + "|" + perm.Id
	if ok, seen := t.members[cacheKey]; seen {
		return ok
	}
	ok := t.checkAccess(ch, perm)
	t.members[cacheKey] = ok
	return ok
}

// checkAccess does the uncached work for canAccess.
func (t *toolset) checkAccess(ch *model.Channel, perm *model.Permission) bool {
	member, appErr := t.api.GetChannelMember(ch.Id, t.userID)
	if appErr != nil || member == nil || member.UserId != t.userID || member.ChannelId != ch.Id {
		return false
	}
	if ch.TeamId != "" {
		tm, appErr := t.api.GetTeamMember(ch.TeamId, t.userID)
		if appErr != nil || tm == nil || tm.DeleteAt != 0 {
			return false
		}
	}
	return t.api.HasPermissionToChannel(t.userID, ch.Id, perm)
}

// authorizedChannel resolves ref and checks access, failing the same way for missing and forbidden.
func (t *toolset) authorizedChannel(ref string, perm *model.Permission) (*model.Channel, error) {
	ch, err := t.resolveChannel(ref)
	if err != nil {
		return nil, err
	}
	if !t.canAccess(ch, perm) {
		return nil, errNoAccess
	}
	return ch, nil
}

// authorizedPost loads a post by id or permalink and checks access to its channel.
func (t *toolset) authorizedPost(ref string, perm *model.Permission) (*model.Post, *model.Channel, error) {
	id, ok := extractID(ref)
	if !ok {
		return nil, nil, errors.New("give a post id or permalink")
	}
	post, appErr := t.api.GetPost(id)
	if appErr != nil || post.DeleteAt != 0 {
		return nil, nil, errNoAccess
	}
	ch, appErr := t.api.GetChannel(post.ChannelId)
	if appErr != nil || !t.canAccess(ch, perm) {
		return nil, nil, errNoAccess
	}
	return post, ch, nil
}

// username returns @name for a user id, cached for the request.
func (t *toolset) username(id string) string {
	if name, ok := t.usernames[id]; ok {
		return name
	}
	name := "unknown-user"
	if u, appErr := t.api.GetUser(id); appErr == nil {
		name = u.Username
	}
	t.usernames[id] = name
	return name
}

// myTeams lists the user's teams, cached for the request.
func (t *toolset) myTeams() ([]*model.Team, error) {
	teams, appErr := t.api.GetTeamsForUser(t.userID)
	if appErr != nil {
		return nil, errors.New("could not list your teams")
	}
	for _, team := range teams {
		t.teams[team.Id] = team
	}
	sort.Slice(teams, func(i, j int) bool { return teams[i].Name < teams[j].Name })
	return teams, nil
}

// teamName returns a team's URL name for permalinks. Direct and group messages have no team, and
// any of the user's teams works in their permalinks.
func (t *toolset) teamName(teamID string) string {
	if teamID == "" {
		if len(t.teams) == 0 {
			_, _ = t.myTeams()
		}
		names := make([]string, 0, len(t.teams))
		for _, team := range t.teams {
			names = append(names, team.Name)
		}
		sort.Strings(names)
		if len(names) > 0 {
			return names[0]
		}
		return "_redirect"
	}
	if team, ok := t.teams[teamID]; ok {
		return team.Name
	}
	team, appErr := t.api.GetTeam(teamID)
	if appErr != nil {
		return "_redirect"
	}
	t.teams[teamID] = team
	return team.Name
}

// permalink is the browser link to a post.
func (t *toolset) permalink(ch *model.Channel, postID string) string {
	return fmt.Sprintf("%s/%s/pl/%s", t.siteURL, t.teamName(ch.TeamId), postID)
}

// channelLabel names a channel the way the user would recognise it.
func (t *toolset) channelLabel(ch *model.Channel) string {
	switch ch.Type {
	case model.ChannelTypeDirect:
		other := ch.GetOtherUserIdForDM(t.userID)
		if other == "" {
			return "DM with yourself"
		}
		return "DM with @" + t.username(other)
	case model.ChannelTypeGroup:
		return "group message: " + ch.DisplayName
	}
	kind := "public"
	if ch.Type == model.ChannelTypePrivate {
		kind = "private"
	}
	label := fmt.Sprintf("%s/%s %q (%s)", t.teamName(ch.TeamId), ch.Name, ch.DisplayName, kind)
	if ch.DeleteAt != 0 {
		label += " [archived]"
	}
	return label
}

// formatTime renders a Mattermost millisecond timestamp in UTC.
func formatTime(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04Z")
}

// formatPost renders one post as a compact line with its permalink.
func (t *toolset) formatPost(p *model.Post, ch *model.Channel, showChannel bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] @%s", formatTime(p.CreateAt), t.username(p.UserId))
	if showChannel {
		fmt.Fprintf(&b, " in %s", t.channelLabel(ch))
	}
	if p.RootId != "" {
		fmt.Fprintf(&b, " (reply in thread %s)", p.RootId)
	}
	msg := strings.TrimSpace(p.Message)
	if msg == "" {
		msg = "(no text)"
	}
	b.WriteString(": ")
	b.WriteString(strings.ReplaceAll(msg, "\n", "\n    "))
	if n := len(p.FileIds); n > 0 {
		fmt.Fprintf(&b, " [%d attachment(s)]", n)
	}
	if p.EditAt != 0 {
		b.WriteString(" (edited)")
	}
	fmt.Fprintf(&b, "\n    id=%s %s", p.Id, t.permalink(ch, p.Id))
	return b.String()
}

// visiblePost drops deleted posts and system messages, which are noise for a reader.
func visiblePost(p *model.Post) bool {
	return p.DeleteAt == 0 && !strings.HasPrefix(p.Type, model.PostSystemMessagePrefix)
}

// ListTeams lists the teams the user belongs to.
func (t *toolset) ListTeams() (string, error) {
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	if len(teams) == 0 {
		return "You are not in any team.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "You are in %d team(s):\n", len(teams))
	for _, team := range teams {
		fmt.Fprintf(&b, "- %s %q id=%s\n", team.Name, team.DisplayName, team.Id)
	}
	return b.String(), nil
}

// ListChannels lists the channels the user belongs to, optionally in one team, plus their direct
// and group messages.
func (t *toolset) ListChannels(teamRef string, includeArchived bool) (string, error) {
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	if teamRef != "" {
		teams = slices.DeleteFunc(teams, func(team *model.Team) bool { return team.Id != teamRef && team.Name != teamRef })
		if len(teams) == 0 {
			return "", errors.New("team " + errNoAccess.Error())
		}
	}
	seen := map[string]bool{}
	var team, direct []string
	for _, tm := range teams {
		channels, appErr := t.api.GetChannelsForTeamForUser(tm.Id, t.userID, includeArchived)
		if appErr != nil {
			return "", errors.New("could not list your channels")
		}
		for _, ch := range channels {
			if seen[ch.Id] || !t.canAccess(ch, model.PermissionReadChannelContent) {
				continue
			}
			seen[ch.Id] = true
			line := fmt.Sprintf("- %s id=%s", t.channelLabel(ch), ch.Id)
			if ch.IsGroupOrDirect() {
				direct = append(direct, line)
			} else {
				team = append(team, line)
			}
		}
	}
	sort.Strings(team)
	sort.Strings(direct)
	var b strings.Builder
	fmt.Fprintf(&b, "%d channel(s) and %d direct or group message(s). Refer to a channel by id or team-name/channel-name.\n", len(team), len(direct))
	for _, l := range team {
		b.WriteString(l + "\n")
	}
	for _, l := range direct {
		b.WriteString(l + "\n")
	}
	return b.String(), nil
}

// parseWhen accepts RFC 3339 or a bare YYYY-MM-DD date (UTC midnight).
func parseWhen(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UnixMilli(), nil
	}
	if ts, err := time.Parse("2006-01-02", s); err == nil {
		return ts.UnixMilli(), nil
	}
	return 0, errors.Errorf("%q is not an RFC 3339 time or YYYY-MM-DD date", s)
}

// ReadChannel returns up to limit posts from a channel, newest first while scanning but printed
// oldest first, created at or after since and before before.
func (t *toolset) ReadChannel(ref, since, before string, limit int) (string, error) {
	ch, err := t.authorizedChannel(ref, model.PermissionReadChannelContent)
	if err != nil {
		return "", err
	}
	sinceMs, err := parseWhen(since)
	if err != nil {
		return "", err
	}
	beforeMs, err := parseWhen(before)
	if err != nil {
		return "", err
	}
	if limit <= 0 {
		limit = defaultPostLimit
	}
	limit = min(limit, maxPostLimit)

	var picked []*model.Post
	more := false
	scanned := 0
scan:
	for page := 0; scanned < maxScanPosts; page++ {
		list, appErr := t.api.GetPostsForChannel(ch.Id, page, scanPageSize)
		if appErr != nil {
			return "", errors.New("could not read the channel")
		}
		for _, id := range list.Order {
			p := list.Posts[id]
			if p == nil || p.ChannelId != ch.Id {
				continue
			}
			if sinceMs != 0 && p.CreateAt < sinceMs {
				break scan
			}
			if (beforeMs != 0 && p.CreateAt >= beforeMs) || !visiblePost(p) {
				continue
			}
			if len(picked) == limit {
				more = true
				break scan
			}
			picked = append(picked, p)
		}
		scanned += len(list.Order)
		if len(list.Order) < scanPageSize {
			break
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d post(s) in %s", len(picked), t.channelLabel(ch))
	if len(picked) > 0 {
		fmt.Fprintf(&b, ", %s to %s", formatTime(picked[len(picked)-1].CreateAt), formatTime(picked[0].CreateAt))
	}
	b.WriteString(".\n")
	if more {
		oldest := picked[len(picked)-1].CreateAt
		fmt.Fprintf(&b, "Older posts exist: call again with before=%s.\n", time.UnixMilli(oldest).UTC().Format(time.RFC3339Nano))
	}
	for i := len(picked) - 1; i >= 0; i-- {
		b.WriteString(t.formatPost(picked[i], ch, false) + "\n")
	}
	return b.String(), nil
}

// ReadThread returns every post in the thread containing the given post.
func (t *toolset) ReadThread(ref string) (string, error) {
	post, ch, err := t.authorizedPost(ref, model.PermissionReadChannelContent)
	if err != nil {
		return "", err
	}
	rootID := post.Id
	if post.RootId != "" {
		rootID = post.RootId
	}
	list, appErr := t.api.GetPostThread(rootID)
	if appErr != nil {
		return "", errNoAccess
	}
	posts := make([]*model.Post, 0, len(list.Posts))
	for _, p := range list.Posts {
		// Every post must be in the channel just checked; anything else is never shown.
		if p.ChannelId == ch.Id && (p.Id == rootID || p.RootId == rootID) && visiblePost(p) {
			posts = append(posts, p)
		}
	}
	sort.Slice(posts, func(i, j int) bool { return posts[i].CreateAt < posts[j].CreateAt })
	var b strings.Builder
	fmt.Fprintf(&b, "Thread in %s, %d post(s):\n", t.channelLabel(ch), len(posts))
	for _, p := range posts {
		b.WriteString(t.formatPost(p, ch, false) + "\n")
	}
	return b.String(), nil
}

// SearchPosts runs Mattermost search as the user in each of their teams (or one), then keeps only
// posts in channels the user can read.
func (t *toolset) SearchPosts(query, teamRef string, limit int) (string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return "", errors.New("give search terms")
	}
	if limit <= 0 {
		limit = 20
	}
	limit = min(limit, maxSearchResults)
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	if teamRef != "" {
		teams = slices.DeleteFunc(teams, func(team *model.Team) bool { return team.Id != teamRef && team.Name != teamRef })
		if len(teams) == 0 {
			return "", errors.New("team " + errNoAccess.Error())
		}
	}
	isOr, page, perPage, includeArchived, tz := false, 0, limit, true, 0
	found := map[string]*model.Post{}
	channels := map[string]*model.Channel{}
	for _, team := range teams {
		res, appErr := t.api.SearchPostsInTeamForUser(team.Id, t.userID, model.SearchParameter{
			Terms: &query, IsOrSearch: &isOr, Page: &page, PerPage: &perPage, IncludeDeletedChannels: &includeArchived, TimeZoneOffset: &tz,
		})
		if appErr != nil {
			return "", errors.New("search failed: check the search syntax")
		}
		if res == nil || res.PostList == nil {
			continue
		}
		for _, p := range res.Posts {
			if found[p.Id] != nil || !visiblePost(p) {
				continue
			}
			ch, ok := channels[p.ChannelId]
			if !ok {
				c, appErr := t.api.GetChannel(p.ChannelId)
				if appErr == nil && t.canAccess(c, model.PermissionReadChannelContent) {
					ch = c
				}
				channels[p.ChannelId] = ch
			}
			if ch != nil {
				found[p.Id] = p
			}
		}
	}
	posts := make([]*model.Post, 0, len(found))
	for _, p := range found {
		posts = append(posts, p)
	}
	sort.Slice(posts, func(i, j int) bool { return posts[i].CreateAt > posts[j].CreateAt })
	if len(posts) > limit {
		posts = posts[:limit]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d result(s) for %q, newest first:\n", len(posts), query)
	for _, p := range posts {
		b.WriteString(t.formatPost(p, channels[p.ChannelId], true) + "\n")
	}
	return b.String(), nil
}

// unreadRow is one channel with unread posts or mentions.
type unreadRow struct {
	ch       *model.Channel
	unread   int64
	mentions int64
	viewedAt int64
}

// GetUnreads lists the user's channels with unread posts or mentions.
func (t *toolset) GetUnreads() (string, error) {
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	var rows []unreadRow
	seen := map[string]bool{}
	for _, team := range teams {
		channels, appErr := t.api.GetChannelsForTeamForUser(team.Id, t.userID, false)
		if appErr != nil {
			return "", errors.New("could not list your channels")
		}
		for _, ch := range channels {
			if seen[ch.Id] {
				continue
			}
			seen[ch.Id] = true
			member, appErr := t.api.GetChannelMember(ch.Id, t.userID)
			if appErr != nil || member.UserId != t.userID || !t.canAccess(ch, model.PermissionReadChannelContent) {
				continue
			}
			unread := max(ch.TotalMsgCount-member.MsgCount, 0)
			if unread > 0 || member.MentionCount > 0 {
				rows = append(rows, unreadRow{ch: ch, unread: unread, mentions: member.MentionCount, viewedAt: member.LastViewedAt})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].mentions != rows[j].mentions {
			return rows[i].mentions > rows[j].mentions
		}
		return rows[i].unread > rows[j].unread
	})
	if len(rows) == 0 {
		return "No unread posts or mentions.", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d channel(s) with unread posts, those with mentions first. Read them with read_channel and since=<last read>.\n", len(rows))
	for _, r := range rows {
		lastRead := "never"
		if r.viewedAt > 0 {
			lastRead = time.UnixMilli(r.viewedAt).UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(&b, "- %s id=%s: %d unread, %d mention(s), last read %s\n", t.channelLabel(r.ch), r.ch.Id, r.unread, r.mentions, lastRead)
	}
	return b.String(), nil
}

// GetMe describes the signed-in user.
func (t *toolset) GetMe() (string, error) {
	u, appErr := t.api.GetUser(t.userID)
	if appErr != nil {
		return "", errors.New("could not load your profile")
	}
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(teams))
	for _, team := range teams {
		names = append(names, team.Name)
	}
	who := "@" + u.Username
	if name := strings.TrimSpace(u.GetFullName()); name != "" {
		who += " (" + name + ")"
	}
	return fmt.Sprintf("You are %s id=%s, in teams: %s. Server: %s", who, u.Id, strings.Join(names, ", "), t.siteURL), nil
}

// FindUsers searches for active users who share a team with the caller.
func (t *toolset) FindUsers(term string) (string, error) {
	term = strings.TrimPrefix(strings.TrimSpace(term), "@")
	if term == "" {
		return "", errors.New("give part of a username or name")
	}
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	// Full names are shown only where the server shows them to every user. The plugin API search
	// (12.0) does not match full names, so the search itself reveals none.
	showFullName := true
	if cfg := t.api.GetConfig(); cfg != nil && cfg.PrivacySettings.ShowFullName != nil {
		showFullName = *cfg.PrivacySettings.ShowFullName
	}
	found := map[string]*model.User{}
	for _, team := range teams {
		users, appErr := t.api.SearchUsers(&model.UserSearch{Term: term, TeamId: team.Id, Limit: maxUserResults})
		if appErr != nil {
			return "", errors.New("user search failed")
		}
		for _, u := range users {
			if u.DeleteAt != 0 {
				continue
			}
			// SearchUsers with a TeamId already restricts to that team; confirm it anyway.
			if tm, appErr := t.api.GetTeamMember(team.Id, u.Id); appErr != nil || tm.DeleteAt != 0 {
				continue
			}
			found[u.Id] = u
		}
	}
	users := make([]*model.User, 0, len(found))
	for _, u := range found {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	if len(users) > maxUserResults {
		users = users[:maxUserResults]
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d user(s) in your teams matching %q:\n", len(users), term)
	for _, u := range users {
		fmt.Fprintf(&b, "- @%s", u.Username)
		if name := strings.TrimSpace(u.GetFullName()); name != "" && showFullName {
			fmt.Fprintf(&b, " %s", name)
		}
		if u.Position != "" {
			fmt.Fprintf(&b, ", %s", u.Position)
		}
		if u.IsBot {
			b.WriteString(" [bot]")
		}
		fmt.Fprintf(&b, " id=%s\n", u.Id)
	}
	return b.String(), nil
}

// checkMessage validates text before posting.
func checkMessage(msg string) error {
	if strings.TrimSpace(msg) == "" {
		return errors.New("message is empty")
	}
	if len([]rune(msg)) > maxMessageRunes {
		return errors.Errorf("message is longer than %d characters", maxMessageRunes)
	}
	return nil
}

// createPost posts as the user and tags the post with the client that wrote it.
func (t *toolset) createPost(ch *model.Channel, rootID, msg string) (string, error) {
	if ch.DeleteAt != 0 {
		return "", errors.New("the channel is archived")
	}
	post := &model.Post{UserId: t.userID, ChannelId: ch.Id, RootId: rootID, Message: msg}
	post.AddProp("mcp_client", t.clientName)
	created, appErr := t.api.CreatePost(post)
	if appErr != nil {
		return "", errors.New("could not post: " + appErr.Message)
	}
	return fmt.Sprintf("Posted in %s: %s", t.channelLabel(ch), t.permalink(ch, created.Id)), nil
}

// PostMessage posts a new message in a channel the user can post in.
func (t *toolset) PostMessage(ref, msg string) (string, error) {
	if err := checkMessage(msg); err != nil {
		return "", err
	}
	ch, err := t.authorizedChannel(ref, model.PermissionCreatePost)
	if err != nil {
		return "", err
	}
	return t.createPost(ch, "", msg)
}

// ReplyInThread replies to the thread containing the given post.
func (t *toolset) ReplyInThread(ref, msg string) (string, error) {
	if err := checkMessage(msg); err != nil {
		return "", err
	}
	post, ch, err := t.authorizedPost(ref, model.PermissionCreatePost)
	if err != nil {
		return "", err
	}
	rootID := post.Id
	if post.RootId != "" {
		rootID = post.RootId
	}
	return t.createPost(ch, rootID, msg)
}

var emojiPattern = regexp.MustCompile(`^[a-z0-9_+\-]{1,64}$`)

// AddReaction reacts to a post as the user.
func (t *toolset) AddReaction(ref, emoji string) (string, error) {
	emoji = strings.Trim(strings.TrimSpace(strings.ToLower(emoji)), ":")
	if !emojiPattern.MatchString(emoji) {
		return "", errors.New("give an emoji name such as thumbsup or white_check_mark")
	}
	post, ch, err := t.authorizedPost(ref, model.PermissionAddReaction)
	if err != nil {
		return "", err
	}
	if ch.DeleteAt != 0 {
		return "", errors.New("the channel is archived")
	}
	if _, appErr := t.api.AddReaction(&model.Reaction{UserId: t.userID, PostId: post.Id, EmojiName: emoji}); appErr != nil {
		return "", errors.New("could not add the reaction: " + appErr.Message)
	}
	return fmt.Sprintf("Added :%s: to %s", emoji, t.permalink(ch, post.Id)), nil
}
