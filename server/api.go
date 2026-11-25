package main

import (
	"github.com/mattermost/mattermost/server/public/model"
)

// mmAPI is the subset of the plugin API this plugin uses. plugin.API satisfies it; tests use a fake.
type mmAPI interface {
	GetConfig() *model.Config

	GetUser(userID string) (*model.User, *model.AppError)
	GetUserByUsername(name string) (*model.User, *model.AppError)
	GetUsersByIds(userIDs []string) ([]*model.User, *model.AppError)
	SearchUsers(search *model.UserSearch) ([]*model.User, *model.AppError)

	GetTeam(teamID string) (*model.Team, *model.AppError)
	GetTeamsForUser(userID string) ([]*model.Team, *model.AppError)
	GetTeamMember(teamID, userID string) (*model.TeamMember, *model.AppError)

	GetChannel(channelID string) (*model.Channel, *model.AppError)
	GetChannelByNameForTeamName(teamName, channelName string, includeDeleted bool) (*model.Channel, *model.AppError)
	GetChannelsForTeamForUser(teamID, userID string, includeDeleted bool) ([]*model.Channel, *model.AppError)
	GetChannelMember(channelID, userID string) (*model.ChannelMember, *model.AppError)
	HasPermissionToChannel(userID, channelID string, permission *model.Permission) bool

	GetPost(postID string) (*model.Post, *model.AppError)
	GetPostThread(postID string) (*model.PostList, *model.AppError)
	GetPostsForChannel(channelID string, page, perPage int) (*model.PostList, *model.AppError)
	SearchPostsInTeamForUser(teamID string, userID string, searchParams model.SearchParameter) (*model.PostSearchResults, *model.AppError)
	CreatePost(post *model.Post) (*model.Post, *model.AppError)
	AddReaction(reaction *model.Reaction) (*model.Reaction, *model.AppError)

	GetSession(sessionID string) (*model.Session, *model.AppError)

	KVGet(key string) ([]byte, *model.AppError)
	KVSetWithOptions(key string, value []byte, options model.PluginKVSetOptions) (bool, *model.AppError)
	KVDelete(key string) *model.AppError

	LogWarn(msg string, keyValuePairs ...any)
	LogError(msg string, keyValuePairs ...any)
}
