# MCP Server (com.scaleupconsulting.mcp)

A remote MCP server inside Mattermost, so Claude (a claude.ai custom connector, Claude Desktop or Claude Code) and other MCP clients can read and, if allowed, post in Mattermost as the signed-in user. Requires Mattermost 12.0+. It needs no Enterprise licence and does not use Mattermost's own OAuth service provider, which can stay off.

## Connecting

Add `<Site URL>/plugins/com.scaleupconsulting.mcp/mcp` as a remote MCP server (Streamable HTTP). The client registers itself, opens a browser, and the user approves it on a consent page while signed in to Mattermost. Users list and disconnect their assistants at `<Site URL>/plugins/com.scaleupconsulting.mcp/connections` or with `/mcp`, `/mcp disconnect <number>` and `/mcp disconnect all`.

## Tools

- `list_teams`, `list_channels`: the user's teams, channels, direct and group messages.
- `read_channel`: posts in a channel, with `since`, `before` and `limit`, and a `before` value to page back.
- `read_thread`: a whole thread from any post id or permalink.
- `search_posts`: Mattermost search syntax, across the user's teams or one.
- `get_unreads`: channels with unread posts and mentions.
- `get_me`, `find_users`: the user, and people who share a team with them.
- `post_message`, `reply_in_thread`, `add_reaction`: only when an admin turns on posting and the user approved posting for that assistant. Posts carry an `mcp_client` prop naming the assistant.

Every tool is annotated read-only or not. Output is compact text with a permalink per post.

## Security model

- The plugin API runs with system privileges, so every tool checks the user's own access first: channel membership, membership of the channel's team, and the channel permission (read content, create post, add reaction). Membership is required even where a role would allow more, so a system admin's assistant cannot read other people's private channels or direct messages. A channel or post that does not exist and one the user cannot see give the same answer. Search results and every listing are filtered the same way.
- The plugin is its own OAuth 2.1 authorization server: dynamic client registration (RFC 7591), authorization code with PKCE S256 only, exact redirect URI matching (https, or http on loopback), `state`, the `iss` response parameter (RFC 9207), and RFC 8707 resource indicators. Tokens are bound to the MCP endpoint's URL.
- Access tokens last 60 minutes and refresh tokens 30 days by default. Each refresh issues a new refresh token; presenting an old one, or redeeming an authorization code twice, revokes the whole connection. Revocation follows RFC 7009.
- Codes and tokens are stored in the plugin KV store only as SHA-256 hashes. Unapproved client registrations expire after a day, and registrations are capped per hour.
- The MCP endpoint accepts only this plugin's tokens, never a Mattermost session or cookie. The consent and connections pages use the Mattermost session, refuse to be framed, and check the session's CSRF token on every form.

## Settings

Allow assistants to connect (a kill switch that keeps connections), Allow posting (off by default), one switch per tool group, and access and refresh token lifetimes.

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

Mattermost's login page returns to its `redirect_to` with a client-side route change, which cannot show a server page. The plugin's small web app script reloads the page when the app routes onto a plugin path, so a signed-out user lands on the consent page after logging in.

## Building and testing

Build with `build/docker-build.sh` (needs only Docker), or `make dist` with Go and Node installed, then upload `dist/com.scaleupconsulting.mcp-<version>.tar.gz` in System Console > Plugins > Plugin Management. Unit tests: `go test ./server/...`. They run every tool and the OAuth flow against a deliberately leaky fake API, to prove the plugin's own checks keep private channels, direct messages and other teams out of reach.
