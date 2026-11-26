package main

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkg/errors"
)

const serverInstructions = `Tools for one Mattermost user's workspace. Every tool sees only what that user can see in Mattermost.
Start with list_channels or get_unreads to find channel ids. Channels can be given by id or team-name/channel-name.
Times are UTC. Each post line ends with its id and a permalink; quote the permalink when citing a post.`

// identity is what a verified access token says about the caller.
type identity struct {
	UserID     string
	ClientName string
	Scopes     []string
}

// verifyToken resolves a bearer token to its user. It accepts only unexpired access tokens issued by
// this plugin for this resource whose grant has not been revoked and whose user is still active.
// Mattermost session tokens and cookies are never accepted here.
func (o *oauthServer) verifyToken(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if !o.config().EnableAccess {
		return nil, errors.Wrap(auth.ErrInvalidToken, "assistant access is turned off")
	}
	if !strings.HasPrefix(token, "mmcp_at_") {
		return nil, auth.ErrInvalidToken
	}
	rec, g, err := o.store.lookupToken(keyAccess, token)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}
	if rec.Resource != o.resourceURL() || g.UserID != rec.UserID {
		return nil, auth.ErrInvalidToken
	}
	user, appErr := o.api.GetUser(rec.UserID)
	if appErr != nil || user.DeleteAt != 0 {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{
		Scopes:     strings.Fields(rec.Scope),
		Expiration: time.UnixMilli(rec.ExpiresAt),
		UserID:     rec.UserID,
		Extra:      map[string]any{"client_name": g.ClientName},
	}, nil
}

// mcpHandler serves the streamable HTTP MCP endpoint behind bearer-token auth.
func (p *Plugin) mcpHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		info := auth.TokenInfoFromContext(r.Context())
		if info == nil {
			return nil
		}
		name, _ := info.Extra["client_name"].(string)
		return p.newMCPServer(identity{UserID: info.UserID, ClientName: name, Scopes: info.Scopes})
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	return auth.RequireBearerToken(p.oauth.verifyToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: p.oauth.resourceMetadataURL(),
		Scopes:              []string{scopeRead},
	})(streamable)
}

// readOnly and destructive annotate tools for clients that ask before acting.
var (
	readOnly    = &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: new(false), IdempotentHint: true, OpenWorldHint: new(false)}
	writeAction = &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: new(false), IdempotentHint: false, OpenWorldHint: new(true)}
)

// Tool inputs. The jsonschema tags become the descriptions clients show the model.
type (
	listChannelsIn struct {
		Team            string `json:"team,omitempty" jsonschema:"optional team name or id; omit for every team"`
		IncludeArchived bool   `json:"include_archived,omitempty" jsonschema:"also list archived channels"`
	}
	readChannelIn struct {
		Channel string `json:"channel" jsonschema:"channel id, or team-name/channel-name"`
		Since   string `json:"since,omitempty" jsonschema:"only posts at or after this RFC 3339 time or YYYY-MM-DD date"`
		Before  string `json:"before,omitempty" jsonschema:"only posts before this RFC 3339 time or YYYY-MM-DD date; use the value the previous page suggests to page back"`
		Limit   int    `json:"limit,omitempty" jsonschema:"maximum posts to return, default 50, at most 200"`
	}
	postRefIn struct {
		Post string `json:"post" jsonschema:"post id or permalink"`
	}
	searchIn struct {
		Query string `json:"query" jsonschema:"Mattermost search terms; supports from:username in:channel-name before:YYYY-MM-DD after:YYYY-MM-DD and \"exact phrases\""`
		Team  string `json:"team,omitempty" jsonschema:"optional team name or id; omit to search every team"`
		Limit int    `json:"limit,omitempty" jsonschema:"maximum results, default 20, at most 100"`
	}
	findUsersIn struct {
		Term string `json:"term" jsonschema:"part of a username, first name, last name or nickname"`
	}
	postMessageIn struct {
		Channel string `json:"channel" jsonschema:"channel id, or team-name/channel-name"`
		Message string `json:"message" jsonschema:"Markdown text to post"`
	}
	replyIn struct {
		Post    string `json:"post" jsonschema:"id or permalink of any post in the thread"`
		Message string `json:"message" jsonschema:"Markdown text to post"`
	}
	reactionIn struct {
		Post  string `json:"post" jsonschema:"post id or permalink"`
		Emoji string `json:"emoji" jsonschema:"emoji name such as thumbsup, without colons"`
	}
	noInput struct{}
)

// textResult wraps a tool's text answer.
func textResult(text string, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

// newMCPServer builds the tool set for one request: only the groups the admin enabled, and write
// tools only when both the admin and the user's grant allow them.
func (p *Plugin) newMCPServer(id identity) *mcp.Server {
	cfg := p.config.get()
	s := mcp.NewServer(&mcp.Implementation{Name: "mattermost", Title: "Mattermost", Version: manifest.Version}, &mcp.ServerOptions{Instructions: serverInstructions})
	ts := func() *toolset { return newToolset(p.mm, id.UserID, p.siteURL(), id.ClientName) }

	if cfg.ToolsChannels {
		mcp.AddTool(s, &mcp.Tool{Name: "list_teams", Description: "List the Mattermost teams you belong to.", Annotations: readOnly},
			func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
				return textResult(ts().ListTeams())
			})
		mcp.AddTool(s, &mcp.Tool{Name: "list_channels", Description: "List the channels, direct messages and group messages you belong to, with their ids.", Annotations: readOnly},
			func(_ context.Context, _ *mcp.CallToolRequest, in listChannelsIn) (*mcp.CallToolResult, any, error) {
				return textResult(ts().ListChannels(in.Team, in.IncludeArchived))
			})
	}
	if cfg.ToolsPosts {
		mcp.AddTool(s, &mcp.Tool{Name: "read_channel", Description: "Read posts in a channel or direct message you belong to, oldest first, optionally within a time range. Replies show their thread id.", Annotations: readOnly},
			func(_ context.Context, _ *mcp.CallToolRequest, in readChannelIn) (*mcp.CallToolResult, any, error) {
				return textResult(ts().ReadChannel(in.Channel, in.Since, in.Before, in.Limit))
			})
		mcp.AddTool(s, &mcp.Tool{Name: "read_thread", Description: "Read a whole thread, given any post in it.", Annotations: readOnly},
			func(_ context.Context, _ *mcp.CallToolRequest, in postRefIn) (*mcp.CallToolResult, any, error) {
				return textResult(ts().ReadThread(in.Post))
			})
	}
	if cfg.ToolsSearch {
		mcp.AddTool(s, &mcp.Tool{Name: "search_posts", Description: "Search posts in the channels and direct messages you belong to, newest first.", Annotations: readOnly},
			func(_ context.Context, _ *mcp.CallToolRequest, in searchIn) (*mcp.CallToolResult, any, error) {
				return textResult(ts().SearchPosts(in.Query, in.Team, in.Limit))
			})
	}
	if cfg.ToolsUnreads {
		mcp.AddTool(s, &mcp.Tool{Name: "get_unreads", Description: "List your channels and direct messages with unread posts and mentions.", Annotations: readOnly},
			func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
				return textResult(ts().GetUnreads())
			})
	}
	if cfg.ToolsUsers {
		mcp.AddTool(s, &mcp.Tool{Name: "get_me", Description: "Describe the Mattermost user these tools act as.", Annotations: readOnly},
			func(context.Context, *mcp.CallToolRequest, noInput) (*mcp.CallToolResult, any, error) {
				return textResult(ts().GetMe())
			})
		mcp.AddTool(s, &mcp.Tool{Name: "find_users", Description: "Find people in your teams by username or name.", Annotations: readOnly},
			func(_ context.Context, _ *mcp.CallToolRequest, in findUsersIn) (*mcp.CallToolResult, any, error) {
				return textResult(ts().FindUsers(in.Term))
			})
	}
	if cfg.EnableWriteTools && slices.Contains(id.Scopes, scopeWrite) {
		mcp.AddTool(s, &mcp.Tool{Name: "post_message", Description: "Post a new message in a channel or direct message, as you.", Annotations: writeAction},
			func(_ context.Context, req *mcp.CallToolRequest, in postMessageIn) (*mcp.CallToolResult, any, error) {
				if err := p.requireWrite(req); err != nil {
					return textResult("", err)
				}
				return textResult(ts().PostMessage(in.Channel, in.Message))
			})
		mcp.AddTool(s, &mcp.Tool{Name: "reply_in_thread", Description: "Reply in the thread containing a post, as you.", Annotations: writeAction},
			func(_ context.Context, req *mcp.CallToolRequest, in replyIn) (*mcp.CallToolResult, any, error) {
				if err := p.requireWrite(req); err != nil {
					return textResult("", err)
				}
				return textResult(ts().ReplyInThread(in.Post, in.Message))
			})
		mcp.AddTool(s, &mcp.Tool{Name: "add_reaction", Description: "Add an emoji reaction to a post, as you.", Annotations: writeAction},
			func(_ context.Context, req *mcp.CallToolRequest, in reactionIn) (*mcp.CallToolResult, any, error) {
				if err := p.requireWrite(req); err != nil {
					return textResult("", err)
				}
				return textResult(ts().AddReaction(in.Post, in.Emoji))
			})
	}
	return s
}

// requireWrite re-checks, on every call to a write tool, that the admin still allows posting and that
// the access token behind this very request carries mcp:write. Tool registration already filters on
// both, so this guards against a tool set built from anything other than the caller's own token.
func (p *Plugin) requireWrite(req *mcp.CallToolRequest) error {
	if !p.config.get().EnableWriteTools {
		return errors.New("an administrator has turned off posting")
	}
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil || !slices.Contains(req.Extra.TokenInfo.Scopes, scopeWrite) {
		return errors.New("this connection was approved read only; reconnect and choose Read and write to post")
	}
	return nil
}
