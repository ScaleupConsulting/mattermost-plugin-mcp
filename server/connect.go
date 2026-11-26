package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"regexp"
	"strings"
)

// guideStep is how to connect one kind of client. Text marks code with `backticks` and emphasis
// with **asterisks**, so the same words serve the Markdown reply and the HTML page.
type guideStep struct {
	Client string
	Text   string
}

// connectGuide is what a user needs to connect an assistant, worded for the admin settings in force.
type connectGuide struct {
	// Enabled is the admin's Allow assistants to connect switch; when off there are no steps.
	Enabled bool
	URL     string
	Steps   []guideStep
	Access  string
}

const connectionsOffText = "An administrator has turned off connecting AI assistants on this server."

// connectGuide builds the connect steps from the current settings.
func (p *Plugin) connectGuide() connectGuide {
	cfg := p.config.get()
	g := connectGuide{Enabled: cfg.EnableAccess, URL: p.oauth.resourceURL()}
	if !g.Enabled {
		return g
	}
	g.Access = "Each one asks you to approve it in Mattermost. Assistants get **Read only** access: they can read, search and save drafts that only you can send, but cannot post."
	if cfg.EnableWriteTools {
		g.Access = "Each one asks you to approve it in Mattermost, where you choose **Read only** (the default) or **Read and write**. Read only can read, search and save drafts that only you can send. Read and write can also post, reply and react as you."
	}
	g.Steps = []guideStep{
		{"claude.ai or Claude Desktop", "in Connectors, choose **Add custom connector**, paste the URL, then click **Connect**. On Team and Enterprise plans an Owner adds it first."},
		{"Claude Code", "run `claude mcp add --transport http mattermost " + g.URL + "`, then type `/mcp` in Claude Code and sign in."},
		{"Other MCP clients", "add the URL as a remote MCP server (Streamable HTTP) and sign in with OAuth."},
	}
	return g
}

// markdown renders the guide as the /mcp help reply.
func (g connectGuide) markdown(pageURL string) string {
	if !g.Enabled {
		return connectionsOffText
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#### Connect an AI assistant\nMCP server URL: `%s`\n\n", g.URL)
	for _, s := range g.Steps {
		fmt.Fprintf(&b, "- **%s:** %s\n", s.Client, s.Text)
	}
	fmt.Fprintf(&b, "\n%s\n\nSee and disconnect your assistants with `/mcp list` or on the [connect page](%s).", g.Access, pageURL)
	return b.String()
}

var (
	codeSpan   = regexp.MustCompile("`([^`]+)`")
	strongSpan = regexp.MustCompile(`\*\*([^*]+)\*\*`)
)

// inlineHTML escapes guide text, then turns its `code` and **bold** marks into HTML.
func inlineHTML(s string) template.HTML {
	s = template.HTMLEscapeString(s)
	s = codeSpan.ReplaceAllString(s, "<code>$1</code>")
	return template.HTML(strongSpan.ReplaceAllString(s, "<strong>$1</strong>")) // #nosec G203 -- escaped above
}

// copyScript is the connect page's only script; the page CSP allows it by hash and nothing else.
const copyScript = `const u=document.getElementById("mcp-url"),b=document.getElementById("copy-url");` +
	`b.addEventListener("click",()=>{u.select();navigator.clipboard.writeText(u.value).then(()=>{b.textContent="Copied"})});`

// copyScriptCSP is the CSP source expression for copyScript.
var copyScriptCSP = func() string {
	sum := sha256.Sum256([]byte(copyScript))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()
