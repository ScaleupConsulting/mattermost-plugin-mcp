package main

import (
	"html/template"
	"net/http"
)

const pageStyle = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;color:#1f2329;line-height:1.5}
h1{font-size:1.35rem}.box{border:1px solid #d0d4da;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
.muted{color:#5d6470;font-size:.9rem}ul{padding-left:1.2rem}button{font-size:1rem;padding:.55rem 1.1rem;border-radius:6px;border:1px solid #1c58d9;cursor:pointer;margin-right:.5rem}
.approve{background:#1c58d9;color:#fff}.deny{background:#fff;color:#1c58d9}.revoke{background:#fff;color:#c4313e;border-color:#c4313e;font-size:.9rem;padding:.3rem .8rem}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem .3rem;border-bottom:1px solid #e3e6ea;vertical-align:top}code{font-size:.85rem}`

var pageTemplates = template.Must(template.New("layout").Parse(`{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>{{.}}</title><style>` + pageStyle + `</style></head><body>{{end}}
{{define "consent"}}{{template "head" "Connect an assistant to Mattermost"}}
<h1>Connect <strong>{{.ClientName}}</strong> to Mattermost?</h1>
<div class="box">
<p>Signed in as <strong>@{{.Username}}</strong>. If you approve, this assistant can act as you:</p>
<ul>
<li>read the teams, channels, direct messages and posts you can see, and search them</li>
<li>see your unread messages and mentions, and look up people in your teams</li>
{{if .CanWrite}}<li><strong>post messages, reply in threads and add reactions as you</strong></li>{{else}}<li>it cannot post or change anything</li>{{end}}
</ul>
<p class="muted">The name "{{.ClientName}}" is chosen by the assistant itself{{if .ClientURI}} ({{.ClientURI}}){{end}}. After you approve, it continues at <code>{{.RedirectHost}}</code>. Only approve if you just started connecting it yourself.</p>
</div>
<form method="post" action="{{.Action}}">
<input type="hidden" name="request_id" value="{{.RequestID}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<button class="approve" type="submit" name="decision" value="approve">Approve</button>
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
</form>
<p class="muted">You can disconnect it at any time on <a href="{{.ConnectionsURL}}">your connected assistants</a> page or with <code>/mcp</code>.</p>
</body></html>{{end}}
{{define "error"}}{{template "head" "Mattermost assistant access"}}<h1>Cannot connect</h1><div class="box"><p>{{.}}</p></div></body></html>{{end}}
{{define "connections"}}{{template "head" "Connected assistants"}}
<h1>Assistants connected to your Mattermost account</h1>
<p class="muted">Signed in as <strong>@{{.Username}}</strong>. MCP server address: <code>{{.ResourceURL}}</code></p>
{{if .Grants}}<table><tr><th>Assistant</th><th>Access</th><th>Connected</th><th>Last refreshed</th><th></th></tr>
{{range .Grants}}<tr><td>{{.Name}}</td><td>{{.Access}}</td><td>{{.Created}}</td><td>{{.Refreshed}}</td>
<td><form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="grant_id" value="{{.ID}}"><button class="revoke" type="submit">Disconnect</button></form></td></tr>{{end}}
</table>{{else}}<div class="box"><p>No assistants are connected.</p></div>{{end}}
</body></html>{{end}}`))

// consentPage is the data for the consent template.
type consentPage struct {
	ClientName     string
	ClientURI      string
	RedirectHost   string
	Username       string
	CanWrite       bool
	RequestID      string
	CSRF           string
	Action         string
	ConnectionsURL string
}

// connectionRow is one connected client on the connections page.
type connectionRow struct {
	ID, Name, Access, Created, Refreshed string
}

// connectionsPage is the data for the connections template.
type connectionsPage struct {
	Username    string
	ResourceURL string
	Grants      []connectionRow
	CSRF        string
	Action      string
}

// setPageHeaders stops the pages being framed (clickjacking on Approve), cached or leaking their URL.
func setPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
}

// renderPage executes a named template with the security headers.
func renderPage(w http.ResponseWriter, status int, name string, data any) {
	setPageHeaders(w)
	w.WriteHeader(status)
	_ = pageTemplates.ExecuteTemplate(w, name, data)
}

// renderConsent shows the consent page.
func renderConsent(w http.ResponseWriter, data consentPage) {
	renderPage(w, http.StatusOK, "consent", data)
}

// renderError shows a plain error page; used where redirecting to the client would be unsafe.
func renderError(w http.ResponseWriter, status int, msg string) {
	renderPage(w, status, "error", msg)
}
