package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

// maxDraftPreviewRunes caps how much of each draft list_drafts shows.
const maxDraftPreviewRunes = 300

// draftTarget resolves where a draft lives: a thread (any post in it) or a channel. It applies the
// same checks as posting: membership of the channel and its team, and create_post there.
func (t *toolset) draftTarget(channelRef, threadRef string) (*model.Channel, string, error) {
	if threadRef != "" {
		post, ch, err := t.authorizedPost(threadRef, model.PermissionCreatePost)
		if err != nil {
			return nil, "", err
		}
		if channelRef != "" {
			other, err := t.authorizedChannel(channelRef, model.PermissionCreatePost)
			if err != nil {
				return nil, "", err
			}
			if other.Id != ch.Id {
				return nil, "", errors.New("the thread is not in that channel; give only the thread")
			}
		}
		rootID := post.Id
		if post.RootId != "" {
			rootID = post.RootId
		}
		return ch, rootID, nil
	}
	if channelRef == "" {
		return nil, "", errors.New("give a channel, or a post in the thread")
	}
	ch, err := t.authorizedChannel(channelRef, model.PermissionCreatePost)
	return ch, "", err
}

// draftPlace describes a draft's channel and thread for the assistant.
func (t *toolset) draftPlace(ch *model.Channel, rootID string) string {
	if rootID == "" {
		return fmt.Sprintf("%s (channel id %s)", t.channelLabel(ch), ch.Id)
	}
	return fmt.Sprintf("the thread %s in %s (channel id %s)", t.permalink(ch, rootID), t.channelLabel(ch), ch.Id)
}

// SaveDraft creates or replaces the user's own draft in a channel or thread. It never sends it.
func (t *toolset) SaveDraft(channelRef, threadRef, msg string) (string, error) {
	if err := checkMessage(msg); err != nil {
		return "", err
	}
	ch, rootID, err := t.draftTarget(channelRef, threadRef)
	if err != nil {
		return "", err
	}
	if ch.DeleteAt != 0 {
		return "", errors.New("the channel is archived")
	}
	draft := &model.Draft{UserId: t.userID, ChannelId: ch.Id, RootId: rootID, Message: msg}
	if err := t.drafts.UpsertDraft(t.userID, draft); err != nil {
		return "", err
	}
	return fmt.Sprintf("Saved your draft in %s. It has not been sent: it waits in the message box and in Drafts until you send or discard it.", t.draftPlace(ch, rootID)), nil
}

// ListDrafts lists the user's own drafts across their teams, or in one team, with direct and group
// messages included. Drafts in channels the user can no longer read are left out.
func (t *toolset) ListDrafts(teamRef string) (string, error) {
	teams, err := t.myTeams()
	if err != nil {
		return "", err
	}
	if teamRef != "" {
		teams = slices.DeleteFunc(teams, func(team *model.Team) bool { return team.Id != teamRef && team.Name != teamRef })
		if len(teams) == 0 {
			return "", errNoAccess
		}
	}
	seen := map[string]bool{}
	var b strings.Builder
	count := 0
	for _, team := range teams {
		drafts, err := t.drafts.GetDrafts(t.userID, team.Id)
		if err != nil {
			return "", err
		}
		for _, d := range drafts {
			key := d.ChannelId + "|" + d.RootId
			if d.UserId != t.userID || seen[key] {
				continue
			}
			seen[key] = true
			ch, appErr := t.api.GetChannel(d.ChannelId)
			if appErr != nil || !t.canAccess(ch, model.PermissionReadChannelContent) {
				continue
			}
			preview := []rune(d.Message)
			ellipsis := ""
			if len(preview) > maxDraftPreviewRunes {
				preview, ellipsis = preview[:maxDraftPreviewRunes], "..."
			}
			fmt.Fprintf(&b, "- in %s, updated %s: %s%s\n", t.draftPlace(ch, d.RootId), formatTime(d.UpdateAt), string(preview), ellipsis)
			count++
		}
	}
	if count == 0 {
		return "You have no drafts.", nil
	}
	return fmt.Sprintf("You have %d draft(s), none of them sent:\n%s", count, b.String()), nil
}

// DeleteDraft discards the user's own draft in a channel or thread.
func (t *toolset) DeleteDraft(channelRef, threadRef string) (string, error) {
	ch, rootID, err := t.draftTarget(channelRef, threadRef)
	if err != nil {
		return "", err
	}
	if err := t.drafts.DeleteDraft(t.userID, ch.Id, rootID); err != nil {
		return "", err
	}
	return fmt.Sprintf("Deleted your draft in %s, if there was one.", t.draftPlace(ch, rootID)), nil
}
