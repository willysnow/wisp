package console

// indexHTML is the whole operator UI. It is inlined rather than served from an
// assets directory so the console stays a single binary with nothing to deploy
// alongside it.
const indexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{{if .Live}}<meta http-equiv="refresh" content="{{.Live}}">{{end}}
<title>wisp console</title>
<style>
:root{--bg:#14161a;--panel:#1c1f26;--line:#2a2f39;--fg:#dfe3ea;--dim:#8b95a6;
--hot:#ff6b6b;--warm:#ffb454;--cool:#5cc8ff;--ok:#5dd39e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:16px 20px;border-bottom:1px solid var(--line);
display:flex;flex-wrap:wrap;gap:16px;align-items:baseline}
h1{font-size:15px;margin:0;letter-spacing:.5px}
h1 span{color:var(--dim);font-weight:400}
.stat{color:var(--dim)}
.stat b{color:var(--fg);font-weight:600}
.live{color:var(--ok)}
main{padding:20px;display:grid;gap:20px;grid-template-columns:minmax(0,1fr) 260px}
@media(max-width:900px){main{grid-template-columns:1fr}}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
margin:0;padding:10px 14px;border-bottom:1px solid var(--line)}
table{width:100%;border-collapse:collapse}
td,th{padding:7px 10px;text-align:left;vertical-align:top;
border-bottom:1px solid var(--line)}
th{font-size:11px;color:var(--dim);font-weight:500;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:0}
.wrap{overflow-x:auto}
a{color:var(--cool);text-decoration:none}
a:hover{text-decoration:underline}
.t{color:var(--dim);white-space:nowrap}
.svc{color:var(--cool)}
.kind{white-space:nowrap}
.kind.cred{color:var(--hot);font-weight:600}
.kind.act{color:var(--warm)}
.src{white-space:nowrap}
.data{color:var(--dim);word-break:break-word}
.data i{color:var(--fg);font-style:normal}
.empty{padding:28px 14px;text-align:center;color:var(--dim)}
/* Event rows are each a single link into the detail page. No nested links, so
   the whole row is one target; filtering moves to the search box and the side
   panels. Two lines — a meta line that wraps and a summary that ellipsises —
   so the list never needs a horizontal scrollbar on a narrow screen. */
.ev{display:block;padding:9px 14px;border-bottom:1px solid var(--line);
color:var(--fg);text-decoration:none}
.ev:last-child{border-bottom:0}
.ev:hover{background:#232732;text-decoration:none}
.ev .meta{display:flex;flex-wrap:wrap;gap:3px 12px;align-items:baseline}
.ev .meta .t{color:var(--dim);white-space:nowrap}
.ev .meta .svc{color:var(--cool)}
.ev .meta .kind{white-space:nowrap}
.ev .meta .kind.cred{color:var(--hot);font-weight:600}
.ev .meta .kind.act{color:var(--warm)}
.ev .meta .src{color:var(--dim);white-space:nowrap}
.ev .sum{display:block;margin-top:2px;color:var(--dim);
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.side table td{font-size:12px}
.num{text-align:right;color:var(--dim)}
.filters{padding:10px 14px;border-bottom:1px solid var(--line);color:var(--dim)}
.filters a{margin-left:8px}
.dot{color:var(--ok)}
.dot.stale{color:var(--dim)}
.who{margin-left:auto;color:var(--dim)}
.who b{color:var(--fg);font-weight:600}
form.inline{display:inline;margin-left:10px}
button.link{background:none;border:0;padding:0;font:inherit;color:var(--cool);cursor:pointer}
button.link:hover{text-decoration:underline}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;
padding:10px 14px;border-bottom:1px solid var(--line)}
.bar form{display:flex;gap:6px;flex:1;min-width:200px}
.bar input[type=search]{flex:1;padding:5px 8px;border-radius:3px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}
.bar input[type=search]:focus{outline:none;border-color:var(--cool)}
.bar button{padding:5px 12px;border:1px solid var(--line);border-radius:3px;
background:var(--bg);color:var(--fg);font:inherit;cursor:pointer}
.bar button:hover{border-color:var(--cool);color:var(--cool)}
.bar .sep{color:var(--dim)}
.pager{display:flex;gap:14px;align-items:center;padding:10px 14px;color:var(--dim)}
.pager a{padding:2px 8px;border:1px solid var(--line);border-radius:3px}
.pager .right{margin-left:auto}
.silent{color:var(--hot)}
.dot.silent{color:var(--hot)}
mark{background:none;color:var(--warm);font-weight:600}
</style></head><body>

<header>
  <h1>wisp <span>console</span></h1>
  <span class="stat"><b>{{.Total}}</b> events / last {{.Since}}</span>
  <span class="stat"><b>{{len .Sensors}}</b> sensors</span>
  {{if .Live}}<span class="stat live">&bull; live &middot; {{.Live}}s</span>{{end}}
  <a href="/tokens" class="nav">tokens &rarr;</a>
  <span class="who">signed in as <b>{{.User}}</b>
    <form class="inline" method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="link" type="submit">sign out</button>
    </form>
  </span>
</header>

<main>
  <section>
    <h2>Events</h2>

    <div class="bar">
      <form method="get" action="/">
        <input type="search" name="q" value="{{.Filter.Query}}" autofocus
               placeholder="Search everything &mdash; username, path, prompt, address">
        {{/* The other filters ride along, so searching narrows the view
             instead of replacing it. */}}
        {{with .Filter.Node}}<input type="hidden" name="node" value="{{.}}">{{end}}
        {{with .Filter.Service}}<input type="hidden" name="service" value="{{.}}">{{end}}
        {{with .Filter.Kind}}<input type="hidden" name="kind" value="{{.}}">{{end}}
        {{with .Filter.SrcIP}}<input type="hidden" name="src_ip" value="{{.}}">{{end}}
        <input type="hidden" name="hours" value="{{.Hours}}">
        <button type="submit">Search</button>
      </form>
      <span class="sep">export</span>
      <a href="{{.ExportCSV}}">CSV</a>
      <a href="{{.ExportJSON}}">JSON</a>
    </div>

    {{if .Filtered}}
    <div class="filters">
      {{.Matched}} matching
      {{with .Filter.Query}}&middot; search=&ldquo;{{.}}&rdquo;{{end}}
      {{with .Filter.Node}}&middot; node={{.}}{{end}}
      {{with .Filter.Service}}&middot; service={{.}}{{end}}
      {{with .Filter.Kind}}&middot; kind={{.}}{{end}}
      {{with .Filter.SrcIP}}&middot; src={{.}}{{end}}
      <a href="/">clear</a>
    </div>
    {{end}}
    <div class="rows">
      {{range .Events}}
      <a class="ev" href="/event/{{.ID}}">
        <span class="meta">
          <span class="t">{{.Time.Format "01-02 15:04:05"}}</span>
          <span class="node">{{.Node}}</span>
          <span class="svc">{{.Service}}</span>
          <span class="kind {{if credential .Kind}}cred{{else if highvalue .Kind}}act{{end}}">{{.Kind}}</span>
          <span class="src">{{.SrcIP}}:{{.SrcPort}} &rarr; :{{.DstPort}}</span>
        </span>
        {{$pairs := kv .Data}}{{if $pairs}}<span class="sum">{{range $pairs}}{{.}}&nbsp; {{end}}</span>{{end}}
      </a>
      {{else}}
      <div class="empty">
        {{if .Filtered}}
        Nothing matches. Try a wider time window, or <a href="/">clear the filters</a>.
        {{else}}
        No events yet. Point a sensor at this console and wait for something to
        touch it &mdash; silence here is the expected state.
        {{end}}
      </div>
      {{end}}
    </div>

    {{if gt .Pages 1}}
    <div class="pager">
      {{if .PrevURL}}<a href="{{.PrevURL}}">&larr; newer</a>{{end}}
      <span>page {{.Page}} of {{.Pages}}</span>
      {{if .NextURL}}<a href="{{.NextURL}}">older &rarr;</a>{{end}}
      <span class="right">{{.Matched}} events match</span>
    </div>
    {{end}}
  </section>

  <div class="side" style="display:grid;gap:20px;align-content:start">
    <section>
      <h2>Sensors</h2>
      <table>
        {{range .Sensors}}
        <tr>
          <td>
            <span class="dot{{if .Silent}} silent{{end}}">&bull;</span>
            <a href="/?node={{.Node}}">{{.Node}}</a><br>
            {{/* A sensor that has gone quiet is the one thing on this page
                 that is interesting because nothing happened. */}}
            <span class="t{{if .Silent}} silent{{end}}">
              {{if .Silent}}silent {{end}}{{ago .LastSeen}}
            </span>
          </td>
          <td class="num">{{.EventCount}}</td>
        </tr>
        {{else}}
        <tr><td class="empty">No sensors have reported.</td></tr>
        {{end}}
      </table>
    </section>

    <section>
      <h2>By service</h2>
      <table>
        {{range .Counts}}
        <tr>
          <td><a href="/?service={{.Service}}">{{.Service}}</a></td>
          <td class="num">{{.Count}}</td>
        </tr>
        {{else}}
        <tr><td class="empty">&mdash;</td></tr>
        {{end}}
      </table>
    </section>
  </div>
</main>
</body></html>
`

// eventHTML is the single-event detail page. It exists so the list can show a
// summary and this can show everything: every data field in full, and the
// source, service and sensor as links back into a filtered view. Like the rest
// of the UI it is server-rendered and scriptless — a page, not a modal.
const eventHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>event &middot; wisp console</title>
<style>
:root{--bg:#14161a;--panel:#1c1f26;--line:#2a2f39;--fg:#dfe3ea;--dim:#8b95a6;
--hot:#ff6b6b;--warm:#ffb454;--cool:#5cc8ff;--ok:#5dd39e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:16px 20px;border-bottom:1px solid var(--line);
display:flex;flex-wrap:wrap;gap:16px;align-items:baseline}
h1{font-size:15px;margin:0;letter-spacing:.5px}
h1 span{color:var(--dim);font-weight:400}
a{color:var(--cool);text-decoration:none}
a:hover{text-decoration:underline}
.who{margin-left:auto;color:var(--dim)}
.who b{color:var(--fg);font-weight:600}
form.inline{display:inline;margin-left:10px}
button.link{background:none;border:0;padding:0;font:inherit;color:var(--cool);cursor:pointer}
button.link:hover{text-decoration:underline}
main{padding:20px;max-width:900px}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;
overflow:hidden;margin-bottom:20px}
h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
margin:0;padding:10px 14px;border-bottom:1px solid var(--line)}
.head{padding:14px;border-bottom:1px solid var(--line);
display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.head .kind{font-size:16px;font-weight:600}
.head .kind.cred{color:var(--hot)}
.head .kind.act{color:var(--warm)}
.head .on{color:var(--dim)}
.head .t{color:var(--dim);margin-left:auto;white-space:nowrap}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1px;background:var(--line)}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
.cell{background:var(--panel);padding:12px 14px}
.cell .label{font-size:11px;text-transform:uppercase;letter-spacing:1px;
color:var(--dim);margin-bottom:4px}
.cell .value{color:var(--fg);word-break:break-word}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
td{padding:8px 14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
.k{color:var(--dim);white-space:nowrap;width:1%;padding-right:20px}
.v{color:var(--fg);word-break:break-word;white-space:pre-wrap}
.empty{padding:22px 14px;text-align:center;color:var(--dim)}
</style></head><body>

<header>
  <h1>wisp <span>console</span> &middot; event</h1>
  <a href="/">&larr; events</a>
  <span class="who">signed in as <b>{{.User}}</b>
    <form class="inline" method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="link" type="submit">sign out</button>
    </form>
  </span>
</header>

<main>
  <section>
    <div class="head">
      <span class="kind {{if credential .Event.Kind}}cred{{else if highvalue .Event.Kind}}act{{end}}">{{.Event.Kind}}</span>
      <span class="on">on</span>
      <a href="/?service={{.Event.Service}}">{{.Event.Service}}</a>
      <span class="t">{{.Event.Time.Format "2006-01-02 15:04:05 MST"}} &middot; {{ago .Event.Time}}</span>
    </div>
    <div class="grid">
      <div class="cell">
        <div class="label">Sensor</div>
        <div class="value"><a href="/?node={{.Event.Node}}">{{.Event.Node}}</a></div>
      </div>
      <div class="cell">
        <div class="label">Service</div>
        <div class="value"><a href="/?service={{.Event.Service}}">{{.Event.Service}}</a></div>
      </div>
      <div class="cell">
        <div class="label">Source</div>
        <div class="value"><a href="/?src_ip={{.Event.SrcIP}}">{{.Event.SrcIP}}</a>:{{.Event.SrcPort}}</div>
      </div>
      <div class="cell">
        <div class="label">Destination port</div>
        <div class="value">:{{.Event.DstPort}}</div>
      </div>
    </div>
  </section>

  <section>
    <h2>Captured data</h2>
    <div class="wrap">
    <table>
      {{range .Data}}
      <tr><td class="k">{{.Key}}</td><td class="v">{{.Value}}</td></tr>
      {{else}}
      <tr><td class="empty">No data fields on this event &mdash; the connection itself was the signal.</td></tr>
      {{end}}
    </table>
    </div>
  </section>
</main>
</body></html>
`

// loginHTML is the sign-in page. The console holds every credential the fleet
// has captured, so the UI is behind a login for the same reason ingest is
// behind a token — locking the front door and leaving the back one open
// protects nothing.
const loginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sign in &middot; wisp console</title>
<style>
:root{--bg:#14161a;--panel:#1c1f26;--line:#2a2f39;--fg:#dfe3ea;--dim:#8b95a6;
--hot:#ff6b6b;--cool:#5cc8ff}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
background:var(--bg);color:var(--fg);
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
form{background:var(--panel);border:1px solid var(--line);border-radius:6px;
padding:26px;width:min(340px,92vw)}
h1{font-size:15px;margin:0 0 4px;letter-spacing:.5px}
h1 span{color:var(--dim);font-weight:400}
p.sub{color:var(--dim);margin:0 0 20px}
label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:1px;
color:var(--dim);margin-bottom:5px}
input{width:100%;margin-bottom:16px;padding:9px 10px;border-radius:4px;
border:1px solid var(--line);background:var(--bg);color:var(--fg);font:inherit}
input:focus{outline:none;border-color:var(--cool)}
button{width:100%;padding:9px;border:0;border-radius:4px;cursor:pointer;
background:var(--cool);color:#08121a;font:inherit;font-weight:600}
.err{color:var(--hot);margin:0 0 16px}
</style></head><body>
<form method="post" action="/login">
  <h1>wisp <span>console</span></h1>
  <p class="sub">Sign in to view captured events.</p>
  {{with .Error}}<p class="err">{{.}}</p>{{end}}
  <input type="hidden" name="csrf_token" value="{{.CSRF}}">
  <input type="hidden" name="next" value="{{.Next}}">
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" autofocus required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
</form>
</body></html>
`

// tokensHTML lists the planted honeytokens and how often each has fired. Like
// sensors and operators, tokens are minted from the CLI and only monitored
// here — the console holds no form that mutates state, which keeps the whole UI
// scriptless and behind the same login as everything else.
const tokensHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tokens &middot; wisp console</title>
<style>
:root{--bg:#14161a;--panel:#1c1f26;--line:#2a2f39;--fg:#dfe3ea;--dim:#8b95a6;
--hot:#ff6b6b;--warm:#ffb454;--cool:#5cc8ff;--ok:#5dd39e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:16px 20px;border-bottom:1px solid var(--line);
display:flex;flex-wrap:wrap;gap:16px;align-items:baseline}
h1{font-size:15px;margin:0;letter-spacing:.5px}
h1 span{color:var(--dim);font-weight:400}
.stat{color:var(--dim)}
.stat b{color:var(--fg);font-weight:600}
main{padding:20px}
section{background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
h2{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--dim);
margin:0;padding:10px 14px;border-bottom:1px solid var(--line)}
table{width:100%;border-collapse:collapse}
td,th{padding:7px 10px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
th{font-size:11px;color:var(--dim);font-weight:500;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:0}
.wrap{overflow-x:auto}
a{color:var(--cool);text-decoration:none}
a:hover{text-decoration:underline}
.id{color:var(--fg)}
.kind{color:var(--cool);white-space:nowrap}
.loc{color:var(--dim);word-break:break-all;max-width:360px}
.memo{color:var(--fg)}
.t{color:var(--dim);white-space:nowrap}
.fired{color:var(--hot);font-weight:600;white-space:nowrap}
.never{color:var(--dim)}
.off{color:var(--dim)}
.empty{padding:28px 14px;text-align:center;color:var(--dim)}
.note{padding:10px 14px;color:var(--dim);border-bottom:1px solid var(--line)}
.note code{color:var(--warm)}
.who{margin-left:auto;color:var(--dim)}
.who b{color:var(--fg);font-weight:600}
form.inline{display:inline;margin-left:10px}
button.link{background:none;border:0;padding:0;font:inherit;color:var(--cool);cursor:pointer}
button.link:hover{text-decoration:underline}
</style></head><body>

<header>
  <h1>wisp <span>console</span> &middot; tokens</h1>
  <a href="/">&larr; events</a>
  <span class="who">signed in as <b>{{.User}}</b>
    <form class="inline" method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{.CSRF}}">
      <button class="link" type="submit">sign out</button>
    </form>
  </span>
</header>

<main>
  <section>
    <h2>Honeytokens</h2>
    <div class="note">
      A token is a lure planted inside data &mdash; a document, a kubeconfig, an
      MCP config &mdash; that calls home when opened or used. Mint one with
      <code>wisp-console token add -kind &lt;kind&gt; -memo "where you put it"</code>.
      {{if not .Configured}}<br>Set <code>tokens.base_url</code> in the console
      config so a callback URL can be shown here.{{end}}
    </div>
    <div class="wrap">
    <table>
      <tr><th>Token</th><th>Kind</th><th>Memo</th><th>Locator</th><th>Triggered</th><th>Created</th><th>Status</th></tr>
      {{range .Tokens}}
      <tr>
        <td class="id">{{.ID}}</td>
        <td class="kind">{{.Kind}}</td>
        <td class="memo">{{with .Memo}}{{.}}{{else}}<span class="never">&mdash;</span>{{end}}</td>
        <td class="loc">{{with .Locator}}{{.}}{{else}}<span class="never">&mdash;</span>{{end}}</td>
        <td>
          {{if .Triggered}}
            <span class="fired">{{.TriggerCount}}&times;</span>
            <span class="t">last {{ago .LastTriggered}}</span>
          {{else}}
            <span class="never">never</span>
          {{end}}
        </td>
        <td class="t">{{.CreatedAt.Format "2006-01-02"}}</td>
        <td>{{if .Disabled}}<span class="off">disabled</span>{{else}}active{{end}}</td>
      </tr>
      {{else}}
      <tr><td class="empty" colspan="7">
        No tokens yet. Mint one with
        <code>wisp-console token add -kind docx -memo "finance share"</code>,
        plant it, and a firing shows up here and in the events timeline.
      </td></tr>
      {{end}}
    </table>
    </div>
  </section>
</main>
</body></html>
`
