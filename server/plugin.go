package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/pkg/errors"
)

const pluginID = "com.scaleupconsulting.mcp"

// Plugin serves a remote MCP server and the OAuth authorization server that guards it.
type Plugin struct {
	plugin.MattermostPlugin

	config configStore
	mm     mmAPI
	oauth  *oauthServer
	drafts draftAPI

	routerOnce sync.Once
	router     http.Handler
}

// OnActivate checks the settings and Site URL and registers /mcp.
func (p *Plugin) OnActivate() error {
	if err := p.loadConfiguration(); err != nil {
		return err
	}
	p.setup(p.API, time.Now)
	p.drafts = newRestDrafts(p.API)
	if p.siteURL() == "" {
		return errors.New("set System Console > Environment > Web Server > Site URL: OAuth and permalinks need it")
	}
	return p.API.RegisterCommand(&model.Command{
		Trigger:          "mcp",
		AutoComplete:     true,
		AutoCompleteDesc: "List or disconnect the AI assistants connected to your account",
		AutoCompleteHint: "[list | disconnect <number> | disconnect all]",
		DisplayName:      "MCP connections",
	})
}

// setup wires the plugin to an API, which tests replace with a fake.
func (p *Plugin) setup(api mmAPI, now func() time.Time) {
	p.mm = api
	p.oauth = &oauthServer{api: api, store: &store{api: api, now: now}, config: p.config.get, siteURL: p.siteURL, now: now}
}

// siteURL is the server's configured Site URL without a trailing slash.
func (p *Plugin) siteURL() string {
	if s := p.mm.GetConfig().ServiceSettings.SiteURL; s != nil {
		return strings.TrimRight(*s, "/")
	}
	return ""
}

// ServeHTTP routes the plugin's endpoints. The MCP and token endpoints authenticate with this
// plugin's own tokens; only the consent and connections pages use the Mattermost session.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	p.routerOnce.Do(func() { p.router = p.newRouter() })
	sessionID := ""
	if c != nil {
		sessionID = c.SessionId
	}
	p.router.ServeHTTP(w, r.WithContext(withSessionID(r.Context(), sessionID)))
}

// newRouter builds the route table once.
func (p *Plugin) newRouter() http.Handler {
	o := p.oauth
	router := mux.NewRouter()
	preflight := func(w http.ResponseWriter, _ *http.Request) { allowCORS(w); w.WriteHeader(http.StatusNoContent) }
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		router.HandleFunc(path, o.handleProtectedResourceMetadata).Methods(http.MethodGet)
	}
	router.HandleFunc("/.well-known/oauth-authorization-server", o.handleAuthServerMetadata).Methods(http.MethodGet)
	router.HandleFunc("/oauth/register", o.handleRegister).Methods(http.MethodPost)
	router.HandleFunc("/oauth/token", o.handleToken).Methods(http.MethodPost)
	router.HandleFunc("/oauth/revoke", o.handleRevoke).Methods(http.MethodPost)
	router.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		o.handleAuthorize(w, r, p.sessionCSRF(r))
	}).Methods(http.MethodGet)
	router.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		o.handleAuthorizeDecision(w, r, p.sessionCSRF(r))
	}).Methods(http.MethodPost)
	router.HandleFunc("/connections", p.handleConnections).Methods(http.MethodGet)
	router.HandleFunc("/connections/revoke", p.handleConnectionRevoke).Methods(http.MethodPost)
	mcpHandler := p.mcpHandler()
	router.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowCORS(w)
		// The browser session must never reach the MCP endpoint, whatever cookie it carried.
		r.Header.Del("Mattermost-User-Id")
		mcpHandler.ServeHTTP(w, r)
	}))
	// Registered last: gorilla/mux answers 405 for a path an earlier method-specific route matched.
	router.PathPrefix("/").Methods(http.MethodOptions).HandlerFunc(preflight)
	return router
}

// sessionCSRF returns a function giving the CSRF token of the Mattermost session behind this request.
func (p *Plugin) sessionCSRF(r *http.Request) func() string {
	return func() string {
		id := sessionIDFrom(r.Context())
		if id == "" {
			return ""
		}
		s, appErr := p.mm.GetSession(id)
		if appErr != nil || s.UserId != r.Header.Get("Mattermost-User-Id") {
			return ""
		}
		return s.GetCSRF()
	}
}

// requirePageUser answers pages that need a signed-in user, redirecting to login when there is none.
func (p *Plugin) requirePageUser(w http.ResponseWriter, r *http.Request) (*model.User, bool) {
	userID := r.Header.Get("Mattermost-User-Id")
	if userID == "" {
		http.Redirect(w, r, p.oauth.loginURL(r), http.StatusFound)
		return nil, false
	}
	user, appErr := p.mm.GetUser(userID)
	if appErr != nil {
		renderError(w, http.StatusForbidden, "Your account could not be loaded.")
		return nil, false
	}
	return user, true
}

// handleConnections lists the user's connected assistants with a Disconnect button for each.
func (p *Plugin) handleConnections(w http.ResponseWriter, r *http.Request) {
	user, ok := p.requirePageUser(w, r)
	if !ok {
		return
	}
	grants, err := p.oauth.store.listGrants(user.Id)
	if err != nil {
		renderError(w, http.StatusInternalServerError, "Your connections could not be loaded.")
		return
	}
	page := connectionsPage{Username: user.Username, ResourceURL: p.oauth.resourceURL(), CSRF: p.sessionCSRF(r)(), Action: p.oauth.base() + "/connections/revoke"}
	for _, g := range grants {
		page.Grants = append(page.Grants, connectionRow{
			ID: g.GrantID, Name: g.ClientName, Access: accessLabel(g.Scope), Scope: g.Scope,
			Created: formatTime(g.CreatedAt), Refreshed: formatTime(g.RefreshedAt),
		})
	}
	renderPage(w, http.StatusOK, "connections", page)
}

// handleConnectionRevoke disconnects one of the user's own assistants.
func (p *Plugin) handleConnectionRevoke(w http.ResponseWriter, r *http.Request) {
	user, ok := p.requirePageUser(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil || !csrfMatches(r.PostForm.Get("csrf"), p.sessionCSRF(r)()) {
		renderError(w, http.StatusForbidden, "Your Mattermost session could not be confirmed. Reload the page and try again.")
		return
	}
	g, _, err := p.oauth.store.getGrant(r.PostForm.Get("grant_id"))
	if err == nil && g.UserID == user.Id {
		err = p.oauth.store.revokeGrant(g.GrantID)
	}
	if err != nil && !errors.Is(err, errNotFound) {
		renderError(w, http.StatusInternalServerError, "The assistant could not be disconnected. Try again.")
		return
	}
	http.Redirect(w, r, p.oauth.base()+"/connections", http.StatusSeeOther)
}

// accessLabel describes a grant's scope in words.
func accessLabel(scope string) string {
	if hasScope(scope, scopeWrite) {
		return "Read and write"
	}
	return "Read only"
}

// ExecuteCommand handles /mcp: list connections, or disconnect one or all.
func (p *Plugin) ExecuteCommand(_ *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	reply := func(text string) (*model.CommandResponse, *model.AppError) {
		return &model.CommandResponse{ResponseType: model.CommandResponseTypeEphemeral, Text: text}, nil
	}
	fields := strings.Fields(args.Command)[1:]
	grants, err := p.oauth.store.listGrants(args.UserId)
	if err != nil {
		return reply("Your connections could not be loaded.")
	}
	switch {
	case len(fields) == 0 || fields[0] == "list":
		var b strings.Builder
		fmt.Fprintf(&b, "MCP server address: `%s`\n", p.oauth.resourceURL())
		if len(grants) == 0 {
			b.WriteString("No assistants are connected to your account.")
			return reply(b.String())
		}
		b.WriteString("Assistants connected to your account:\n")
		for i, g := range grants {
			fmt.Fprintf(&b, "%d. **%s** (%s, `%s`), connected %s, last refreshed %s\n", i+1, g.ClientName, accessLabel(g.Scope), g.Scope, formatTime(g.CreatedAt), formatTime(g.RefreshedAt))
		}
		fmt.Fprintf(&b, "\nDisconnect with `/mcp disconnect <number>` or `/mcp disconnect all`, or on [this page](%s/connections).", p.oauth.base())
		return reply(b.String())
	case fields[0] == "disconnect" && len(fields) == 2:
		var targets []*grant
		if fields[1] == "all" {
			targets = grants
		} else {
			var n int
			if _, err := fmt.Sscanf(fields[1], "%d", &n); err != nil || n < 1 || n > len(grants) {
				return reply("Give a number from `/mcp list`, or `all`.")
			}
			targets = grants[n-1 : n]
		}
		for _, g := range targets {
			if err := p.oauth.store.revokeGrant(g.GrantID); err != nil {
				return reply("Disconnecting failed. Try again.")
			}
		}
		return reply(fmt.Sprintf("Disconnected %d assistant(s).", len(targets)))
	}
	return reply("Usage: `/mcp list`, `/mcp disconnect <number>` or `/mcp disconnect all`.")
}

// csrfMatches compares a submitted CSRF token with the session's in constant time; empty never matches.
func csrfMatches(sent, want string) bool {
	return sent != "" && want != "" && subtle.ConstantTimeCompare([]byte(sent), []byte(want)) == 1
}

type sessionIDKey struct{}

// withSessionID carries the Mattermost session id from the plugin context into the request context.
func withSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, id)
}

// sessionIDFrom reads the session id stored by withSessionID.
func sessionIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(sessionIDKey{}).(string)
	return id
}
