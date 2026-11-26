# MCP Server (com.scaleupconsulting.mcp)

A remote MCP server inside Mattermost, so Claude (a claude.ai custom connector, Claude Desktop or Claude Code) and other MCP clients can read and, if allowed, post in Mattermost as the signed-in user. Requires Mattermost 12.0+. It needs no Enterprise licence and does not use Mattermost's own OAuth service provider, which can stay off.

## Connecting

Add `<Site URL>/plugins/com.scaleupconsulting.mcp/mcp` as a remote MCP server (Streamable HTTP). The client registers itself, opens a browser, and the user approves it on a consent page while signed in to Mattermost, choosing **Read only** or **Read and write** for that connection. Inside Mattermost, users find these steps for claude.ai, Claude Desktop, Claude Code and other clients with `/mcp help` (and with `/mcp` until something is connected), or on the connect page that the app bar icon opens, `<Site URL>/plugins/com.scaleupconsulting.mcp/connections`. The steps follow the admin settings: with connecting turned off they say so, and with write access off they mention only Read only. The same page lists their assistants, with the access each was granted, and disconnects them, as do `/mcp`, `/mcp disconnect <number>` and `/mcp disconnect all`.

## Tools

- `list_teams`, `list_channels`: the user's teams, channels, direct and group messages.
- `read_channel`: posts in a channel, with `since`, `before` and `limit`, and a `before` value to page back.
- `read_thread`: a whole thread from any post id or permalink.
- `search_posts`: Mattermost search syntax, across the user's teams or one.
- `get_unreads`: channels with unread posts and mentions.
- `get_me`, `find_users`: the user, and people who share a team with them.
- `save_draft`, `list_drafts`, `delete_draft`: the user's own Mattermost drafts, in a channel or a thread, the same ones the message box and the Drafts view show. A draft is never sent: the user reviews and sends it. Drafts count as reading, so Read only connections get them, but saving or deleting one needs the same channel membership and post permission as posting. Mattermost 12.0's plugin API has no draft methods, so the plugin calls the server's own drafts REST API on its loopback listen address, with a session it creates for the user for that one call and revokes straight after. This needs Allow message drafts to sync with the server, and a listen address serving plain HTTP behind the TLS proxy.
- `post_message`, `reply_in_thread`, `add_reaction`: only for a Read and write connection, and only while the admin allows write access. Posts carry an `mcp_client` prop naming the assistant.

Every tool is annotated read-only or not. Output is compact text with a permalink per post.

## Access: read only or read and write

Each connection holds OAuth scopes: `mcp:read` always, and `mcp:write` only when the user chose Read and write. A client may ask for `mcp:read`, `mcp:read mcp:write`, or nothing (which offers both); the user can always narrow a request to Read only, and the consent page preselects it. Write is offered only when the client asked for it and the admin setting Allow write access is on. That setting is a ceiling: with it off nobody can grant write, and existing Read and write connections lose their write tools until it is back on. The granted scope is bound to the tokens, `tools/list` shows only the tools it allows, and each write tool checks the scope of the calling token again on every call. A refresh can never widen the scope.

## Security model

- The plugin API runs with system privileges, so every tool checks the user's own access first: channel membership, membership of the channel's team, and the channel permission (read content, create post, add reaction). Membership is required even where a role would allow more, so a system admin's assistant cannot read other people's private channels or direct messages. A channel or post that does not exist and one the user cannot see give the same answer. Search results and every listing are filtered the same way. `find_users` shows full names only when Show full name is on in the privacy settings.
- The plugin is its own OAuth 2.1 authorization server: dynamic client registration (RFC 7591), authorization code with PKCE S256 only, exact redirect URI matching (https, or http on loopback), `state`, the `iss` response parameter (RFC 9207), and RFC 8707 resource indicators. Tokens are bound to the MCP endpoint's URL.
- Access tokens last 60 minutes and refresh tokens 30 days by default. Each refresh issues a new refresh token; presenting an old one, or the same client redeeming an authorization code twice, revokes the whole connection. Changing the Mattermost password ends every connection, as it ends the user's sessions. Revocation follows RFC 7009.
- Codes and tokens are stored in the plugin KV store only as SHA-256 hashes. Unapproved client registrations expire after a day, and registrations are capped per hour, server-wide and per client address (`X-Real-IP` from the proxy).
- The MCP endpoint accepts only this plugin's tokens, never a Mattermost session or cookie. The consent and connect pages use the Mattermost session, refuse to be framed, and check the session's CSRF token on every form. Their CSP allows one script, the connect page's Copy button, by hash.

## Settings

Allow assistants to connect (a kill switch that keeps connections), Allow write access (the write ceiling, on by default), one switch per tool group, and access and refresh token lifetimes.

## Reverse proxy

MCP clients find the authorization server at `<Site URL>/.well-known/oauth-authorization-server/plugins/com.scaleupconsulting.mcp`, a path outside the plugin. Mattermost answers that path with 501 when its own OAuth provider is off, so the proxy in front of Mattermost must pass it, and the matching protected resource metadata path, to the plugin. For nginx:

```nginx
location ^~ /.well-known/oauth-authorization-server/plugins/com.scaleupconsulting.mcp {
  rewrite ^ /plugins/com.scaleupconsulting.mcp/.well-known/oauth-authorization-server break;
  proxy_set_header Host $http_host;
  proxy_pass http://mattermost_backend;
}
location ^~ /.well-known/oauth-protected-resource/plugins/com.scaleupconsulting.mcp {
  rewrite ^ /plugins/com.scaleupconsulting.mcp/.well-known/oauth-protected-resource break;
  proxy_set_header Host $http_host;
  proxy_pass http://mattermost_backend;
}
```

## Web app part

Mattermost's login page returns to its `redirect_to` with a client-side route change, which cannot show a server page. The plugin's small web app script reloads the page when the app routes onto a plugin path, so a signed-out user lands on the consent page after logging in. It also adds the "Connect an AI assistant" app bar icon, which opens the connect page in a new tab.

## Building and testing

Build with `build/docker-build.sh` (needs only Docker), or `make dist` with Go and Node installed, then upload `dist/com.scaleupconsulting.mcp-<version>.tar.gz` in System Console > Plugins > Plugin Management. Unit tests: `go test ./server/...`. They run every tool and the OAuth flow against a deliberately leaky fake API, to prove the plugin's own checks keep private channels, direct messages and other teams out of reach.
