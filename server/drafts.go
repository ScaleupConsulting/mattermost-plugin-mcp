package main

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/pkg/errors"
)

// draftAPI reads and writes a user's own Mattermost drafts: the ones that show in the composer and
// the Drafts view. It never sends a draft. The plugin API has no draft methods (12.0), so the real
// implementation calls the server's drafts REST API as the user; tests use a fake.
type draftAPI interface {
	UpsertDraft(userID string, draft *model.Draft) error
	GetDrafts(userID, teamID string) ([]*model.Draft, error)
	DeleteDraft(userID, channelID, rootID string) error
}

// sessionAPI is the part of the plugin API that restDrafts needs.
type sessionAPI interface {
	GetConfig() *model.Config
	GetUser(userID string) (*model.User, *model.AppError)
	CreateSession(session *model.Session) (*model.Session, *model.AppError)
	RevokeSession(sessionID string) *model.AppError
	LogError(msg string, keyValuePairs ...any)
}

const (
	// draftSessionTTL bounds the short-lived session used for one drafts call, in case revoking it fails.
	draftSessionTTL  = 2 * time.Minute
	draftHTTPTimeout = 15 * time.Second
)

// restDrafts calls /api/v4 drafts endpoints on the server's own listen address, with a session
// created for the user just for that call and revoked straight after. The server then applies its
// own draft rules and pushes the change to the user's open clients over the websocket.
type restDrafts struct {
	api    sessionAPI
	client *http.Client
}

// newRestDrafts returns the REST-backed draftAPI.
func newRestDrafts(api sessionAPI) *restDrafts {
	return &restDrafts{api: api, client: &http.Client{Timeout: draftHTTPTimeout}}
}

// localAPIURL is the server's own address as seen from the plugin process, which runs on the same
// host: the listen address with a loopback host, plus any Site URL subpath.
func localAPIURL(cfg *model.Config) (string, error) {
	ss := cfg.ServiceSettings
	if ss.ConnectionSecurity != nil && *ss.ConnectionSecurity == model.ConnSecurityTLS {
		return "", errors.New("drafts need Mattermost to serve plain HTTP on its listen address, behind a TLS proxy")
	}
	listen := ":8065"
	if ss.ListenAddress != nil && *ss.ListenAddress != "" {
		listen = *ss.ListenAddress
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.Wrap(err, "parse ListenAddress")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	subpath := ""
	if ss.SiteURL != nil {
		if u, err := url.Parse(*ss.SiteURL); err == nil {
			subpath = strings.TrimRight(u.Path, "/")
		}
	}
	return "http://" + net.JoinHostPort(host, port) + subpath, nil
}

// asUser runs fn with an API client authenticated as the user through a short-lived session.
func (d *restDrafts) asUser(userID string, fn func(ctx context.Context, c *model.Client4) error) error {
	base, err := localAPIURL(d.api.GetConfig())
	if err != nil {
		return err
	}
	user, appErr := d.api.GetUser(userID)
	if appErr != nil || user.DeleteAt != 0 {
		return errors.New("your account could not be loaded")
	}
	s := &model.Session{UserId: userID, Roles: user.GetRawRoles(), ExpiresAt: model.GetMillis() + draftSessionTTL.Milliseconds()}
	s.AddProp(model.SessionPropIsGuest, strconv.FormatBool(user.IsGuest()))
	s.AddProp("mcp_plugin", "drafts")
	session, appErr := d.api.CreateSession(s)
	if appErr != nil {
		return errors.New("could not reach your drafts: " + appErr.Message)
	}
	defer func() {
		if appErr := d.api.RevokeSession(session.Id); appErr != nil {
			d.api.LogError("Failed to revoke the drafts session; it expires on its own", "err", appErr.Error())
		}
	}()
	c := model.NewAPIv4Client(base)
	c.HTTPClient = d.client
	c.SetToken(session.Token)
	ctx, cancel := context.WithTimeout(context.Background(), draftHTTPTimeout)
	defer cancel()
	return fn(ctx, c)
}

// draftError turns a REST failure into a message for the assistant.
func draftError(resp *model.Response, err error) error {
	if resp != nil && resp.StatusCode == http.StatusNotImplemented {
		return errors.New("an administrator has turned off synced drafts (Allow message drafts to sync with the server)")
	}
	var appErr *model.AppError
	if errors.As(err, &appErr) && appErr.Message != "" {
		return errors.New("drafts: " + appErr.Message)
	}
	return errors.New("drafts are not available right now")
}

// UpsertDraft creates or replaces the user's draft in a channel or thread.
func (d *restDrafts) UpsertDraft(userID string, draft *model.Draft) error {
	return d.asUser(userID, func(ctx context.Context, c *model.Client4) error {
		if _, resp, err := c.UpsertDraft(ctx, draft); err != nil {
			return draftError(resp, err)
		}
		return nil
	})
}

// GetDrafts lists the user's drafts in a team, including direct and group messages.
func (d *restDrafts) GetDrafts(userID, teamID string) ([]*model.Draft, error) {
	var out []*model.Draft
	err := d.asUser(userID, func(ctx context.Context, c *model.Client4) error {
		drafts, resp, err := c.GetDrafts(ctx, userID, teamID)
		if err != nil {
			return draftError(resp, err)
		}
		out = drafts
		return nil
	})
	return out, err
}

// DeleteDraft removes the user's draft in a channel or thread; deleting a missing draft succeeds.
// It builds the route itself because Client4.DeleteDraft (server/public v0.6.1) drops rootId and
// would delete the channel's draft instead of the thread's.
func (d *restDrafts) DeleteDraft(userID, channelID, rootID string) error {
	route := "/users/" + url.PathEscape(userID) + "/channels/" + url.PathEscape(channelID) + "/drafts"
	if rootID != "" {
		route += "/" + url.PathEscape(rootID)
	}
	return d.asUser(userID, func(ctx context.Context, c *model.Client4) error {
		r, err := c.DoAPIDelete(ctx, route)
		if err != nil {
			return draftError(model.BuildResponse(r), err)
		}
		_ = r.Body.Close()
		return nil
	})
}
