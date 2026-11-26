package main

import (
	"html/template"
	"net/http"
)

const pageStyle = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1f2329;line-height:1.5}
h1{font-size:1.35rem}h2{font-size:1.1rem;margin-top:2rem}.box{border:1px solid #d0d4da;border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
.muted{color:#5d6470;font-size:.9rem}ul{padding-left:1.2rem}button{font-family:inherit;font-size:1rem;padding:.55rem 1.1rem;border-radius:6px;border:1px solid #1c58d9;cursor:pointer;margin-right:.5rem}
.approve{background:#1c58d9;color:#fff}.deny{background:#fff;color:#1c58d9}.revoke{background:#fff;color:#c4313e;border-color:#c4313e;font-size:.9rem;padding:.3rem .8rem}
fieldset{margin:1rem 0}legend{font-weight:600}label{display:inline-block;margin:.3rem 0}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem .3rem;border-bottom:1px solid #e3e6ea;vertical-align:top}code{font-size:.85rem}li{margin:.4rem 0}
.url{display:flex;gap:.5rem;margin-top:.4rem}.url input{flex:1;min-width:0;font:inherit;font-size:.9rem;padding:.45rem .5rem;border:1px solid #d0d4da;border-radius:6px}
.copy{background:#1c58d9;color:#fff;margin:0}`

var pageTemplates = template.Must(template.New("layout").Funcs(template.FuncMap{"inline": inlineHTML}).Parse(`{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>{{.}}</title><style>` + pageStyle + `</style></head><body>{{end}}
{{define "consent"}}{{template "head" "Connect an assistant to Mattermost"}}
<h1>Connect <strong>{{.ClientName}}</strong> to Mattermost?</h1>
<div class="box">
<p>Signed in as <strong>@{{.Username}}</strong>. If you approve, this assistant can act as you:</p>
<ul>
<li>read the teams, channels, direct messages and posts you can see, and search them</li>
<li>see your unread messages and mentions, and look up people in your teams</li>
<li>save, list and delete your message drafts, which only you can send</li>
</ul>
<p class="muted">The name "{{.ClientName}}" is chosen by the assistant itself{{if .ClientURI}} ({{.ClientURI}}){{end}}. After you approve, it continues at <code>{{.RedirectHost}}</code>. Only approve if you just started connecting it yourself.</p>
</div>
<form method="post" action="{{.Action}}">
<input type="hidden" name="request_id" value="{{.RequestID}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .OfferWrite}}<fieldset class="box"><legend>Access for this assistant</legend>
<label><input type="radio" name="access" value="read" checked> <strong>Read only</strong>: it can read and draft, but cannot post anything</label><br>
<label><input type="radio" name="access" value="write"> <strong>Read and write</strong>: it can also post messages, reply in threads and add reactions as you</label>
</fieldset>{{else}}<input type="hidden" name="access" value="read">
<p class="box"><strong>Read only</strong>: it cannot post anything. {{if .WriteAllowed}}The assistant did not ask for posting.{{else}}An administrator has turned posting off.{{end}}</p>{{end}}
<button class="approve" type="submit" name="decision" value="approve">Approve</button>
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
</form>
<p class="muted">You can disconnect it at any time on <a href="{{.ConnectionsURL}}">your connected assistants</a> page or with <code>/mcp</code>.</p>
</body></html>{{end}}
{{define "error"}}{{template "head" "Mattermost assistant access"}}<h1>Cannot connect</h1><div class="box"><p>{{.}}</p></div></body></html>{{end}}
{{define "connections"}}{{template "head" "Connect an AI assistant"}}
<h1>Connect an AI assistant</h1>
<p class="muted">Signed in as <strong>@{{.Username}}</strong>.</p>
{{with .Guide}}{{if .Enabled}}<div class="box"><label for="mcp-url"><strong>MCP server URL</strong></label>
<div class="url"><input id="mcp-url" type="text" readonly value="{{.URL}}"><button id="copy-url" class="copy" type="button">Copy</button></div></div>
<ul>{{range .Steps}}<li><strong>{{.Client}}:</strong> {{inline .Text}}</li>{{end}}</ul>
<p>{{inline .Access}}</p>
<script>` + copyScript + `</script>{{else}}<div class="box"><p>` + connectionsOffText + `</p></div>{{end}}{{end}}
<h2>Connected assistants</h2>
{{if .Grants}}<table><tr><th>Assistant</th><th>Access</th><th>Connected</th><th>Last refreshed</th><th></th></tr>
{{range .Grants}}<tr><td>{{.Name}}</td><td>{{.Access}}<br><code>{{.Scope}}</code></td><td>{{.Created}}</td><td>{{.Refreshed}}</td>
<td><form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="grant_id" value="{{.ID}}"><button class="revoke" type="submit">Disconnect</button></form></td></tr>{{end}}
</table>{{else}}<p class="muted">None yet.</p>{{end}}
</body></html>{{end}}`))

// consentPage is the data for the consent template.
type consentPage struct {
	ClientName   string
	ClientURI    string
	RedirectHost string
	Username     string
	// OfferWrite shows the Read only / Read and write choice: the client asked for write and the admin allows it.
	OfferWrite bool
	// WriteAllowed is the admin's posting ceiling, used to explain why only reading is offered.
	WriteAllowed   bool
	RequestID      string
	CSRF           string
	Action         string
	ConnectionsURL string
}

// connectionRow is one connected client on the connections page.
type connectionRow struct {
	ID, Name, Access, Scope, Created, Refreshed string
}

// connectionsPage is the data for the connect page: the steps, then the connected assistants.
type connectionsPage struct {
	Username string
	Guide    connectGuide
	Grants   []connectionRow
	CSRF     string
	Action   string
}

// setPageHeaders stops the pages being framed (clickjacking on Approve), cached or leaking their URL.
func setPageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src "+copyScriptCSP+"; frame-ancestors 'none'; base-uri 'none'")
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
