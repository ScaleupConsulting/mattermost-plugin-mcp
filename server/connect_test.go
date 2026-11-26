package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// command runs /mcp with the given arguments as alice and returns the ephemeral reply.
func (h *harness) command(args string) string {
	resp, appErr := h.p.ExecuteCommand(nil, &model.CommandArgs{UserId: h.w.alice.Id, Command: strings.TrimSpace("/mcp " + args)})
	require.Nil(h.t, appErr)
	require.Equal(h.t, model.CommandResponseTypeEphemeral, resp.ResponseType)
	return resp.Text
}

func TestHelpWithWriteAllowed(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableAccess, c.EnableWriteTools = true, true })
	mcpURL := h.p.oauth.resourceURL()
	for _, text := range []string{h.command("help"), h.command(""), h.command("list")} {
		assert.Contains(t, text, "MCP server URL: `"+mcpURL+"`")
		assert.Contains(t, text, "Add custom connector")
		assert.Contains(t, text, "`claude mcp add --transport http mattermost "+mcpURL+"`")
		assert.Contains(t, text, "Streamable HTTP")
		assert.Contains(t, text, "**Read only** (the default)")
		assert.Contains(t, text, "**Read and write**")
		assert.Contains(t, text, "drafts")
		assert.Contains(t, text, h.p.oauth.base()+"/connections")
	}
	assert.Contains(t, h.command(""), "No assistants are connected")
	assert.NotContains(t, h.command("help"), "No assistants are connected")
}

func TestHelpWithWriteOff(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableAccess, c.EnableWriteTools = true, false })
	for _, text := range []string{h.command("help"), h.command("")} {
		assert.Contains(t, text, "`claude mcp add --transport http mattermost "+h.p.oauth.resourceURL()+"`")
		assert.Contains(t, text, "**Read only** access")
		assert.Contains(t, text, "cannot post")
		assert.NotContains(t, text, "Read and write")
	}
}

func TestHelpWithConnectionsOff(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableAccess = false })
	for _, text := range []string{h.command("help"), h.command("")} {
		assert.Contains(t, text, connectionsOffText)
		assert.NotContains(t, text, "claude mcp add")
		assert.NotContains(t, text, "MCP server URL")
	}
}

func TestListPointsToHelp(t *testing.T) {
	h := newHarness(t)
	h.connect("")
	text := h.command("")
	assert.Contains(t, text, "1. **Claude Code**")
	assert.Contains(t, text, "To connect another assistant, see `/mcp help`.")
	assert.NotContains(t, text, "claude mcp add", "with connections, /mcp lists them rather than the steps")
	assert.Contains(t, h.command("bogus"), "`/mcp help`")
}

func TestConnectPageInEachSetting(t *testing.T) {
	h := newHarness(t)
	h.setConfig(func(c *configuration) { c.EnableAccess, c.EnableWriteTools = true, true })
	h.connect("")
	page := func() string {
		rec := h.do(http.MethodGet, "/connections", nil, h.w.alice, nil)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		return rec.Body.String()
	}
	mcpURL := h.p.oauth.resourceURL()

	body := page()
	assert.Contains(t, body, "<h1>Connect an AI assistant</h1>")
	assert.Contains(t, body, `id="mcp-url" type="text" readonly value="`+mcpURL+`"`)
	assert.Contains(t, body, `id="copy-url"`)
	assert.Contains(t, body, "<code>claude mcp add --transport http mattermost "+mcpURL+"</code>")
	assert.Contains(t, body, "<strong>Read and write</strong>")
	assert.Contains(t, body, "Claude Code</td>", "the connected list stays below the steps")
	assert.Contains(t, body, ">Disconnect</button>")

	h.setConfig(func(c *configuration) { c.EnableWriteTools = false })
	body = page()
	assert.Contains(t, body, "claude mcp add")
	assert.NotContains(t, body, "Read and write")

	h.setConfig(func(c *configuration) { c.EnableAccess = false })
	body = page()
	assert.Contains(t, body, connectionsOffText)
	assert.NotContains(t, body, "claude mcp add")
	assert.NotContains(t, body, "<script>")
	assert.Contains(t, body, ">Disconnect</button>", "existing connections can still be disconnected")
}

func TestCopyScriptIsTheOnlyScriptAllowed(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodGet, "/connections", nil, h.w.alice, nil)
	body := rec.Body.String()
	start := strings.Index(body, "<script>") + len("<script>")
	end := strings.Index(body, "</script>")
	require.True(t, start > len("<script>")-1 && end > start)
	sum := sha256.Sum256([]byte(body[start:end]))
	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"';", "the served script must match its CSP hash byte for byte")
	assert.Equal(t, 1, strings.Count(body, "<script"))
}

func TestInlineHTMLEscapesFirst(t *testing.T) {
	assert.Equal(t, "<code>a&lt;b</code> and <strong>&lt;i&gt;</strong>", string(inlineHTML("`a<b` and **<i>**")))
}
