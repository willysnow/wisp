package gitlabsvc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// The instance's fabricated contents.
//
// The public project list is the bait, and its job is to supply a project id.
// An intruder holding a stolen token needs somewhere to point it, and the
// request they point it at — `/projects/14/variables`, usually — is the one
// that says what they believed the token was worth.

var catalogue = []struct {
	id                int
	path, name, descr string
}{
	{7, "platform/payments-api", "payments-api", "Payment processing service"},
	{14, "platform/infrastructure", "infrastructure", "Terraform and Ansible for all environments"},
	{22, "platform/deploy-scripts", "deploy-scripts", "Release automation"},
	{31, "data/etl-pipelines", "etl-pipelines", "Nightly warehouse loads"},
}

func publicProjects() []map[string]any {
	out := make([]map[string]any, 0, len(catalogue))
	for _, p := range catalogue {
		out = append(out, project(p.id, p.path, p.name, p.descr))
	}
	return out
}

// projectByID answers for any id, including ones the decoy has never heard of.
// A GitLab that 404s the id an intruder guessed teaches them the id space; one
// that answers consistently teaches them nothing.
func projectByID(id string) map[string]any {
	unescaped, err := url.PathUnescape(id)
	if err != nil {
		unescaped = id
	}

	for _, p := range catalogue {
		if id == strconv.Itoa(p.id) || unescaped == p.path {
			return project(p.id, p.path, p.name, p.descr)
		}
	}
	return project(0, "platform/"+unescaped, unescaped, "")
}

func project(id int, path, name, descr string) map[string]any {
	namespace, _, _ := strings.Cut(path, "/")

	return map[string]any{
		"id":                  id,
		"description":         descr,
		"name":                name,
		"name_with_namespace": namespace + " / " + name,
		"path":                name,
		"path_with_namespace": path,
		"created_at":          "2024-08-14T09:22:41.118Z",
		"default_branch":      "main",
		"ssh_url_to_repo":     "git@gitlab.internal:" + path + ".git",
		"http_url_to_repo":    "https://gitlab.internal/" + path + ".git",
		"web_url":             "https://gitlab.internal/" + path,
		"readme_url":          "https://gitlab.internal/" + path + "/-/blob/main/README.md",
		"avatar_url":          nil,
		"forks_count":         0,
		"star_count":          0,
		"last_activity_at":    "2026-07-24T16:03:58.442Z",
		"visibility":          "internal",
		"namespace": map[string]any{
			"id": 4, "name": namespace, "path": namespace, "kind": "group",
			"full_path": namespace,
		},
	}
}

func jsonObject(body []byte) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m
}

func (s *Service) signInPage(w http.ResponseWriter, failed bool) {
	errorBlock := ""
	if failed {
		errorBlock = `<div class="gl-alert gl-alert-danger"><div class="gl-alert-body">Invalid login or password.</div></div>`
	}

	// The session cookie is part of the disguise: a GitLab that never sets one
	// is not a GitLab, and tooling that follows the sign-in flow expects to be
	// given one.
	w.Header().Set("Set-Cookie",
		"_gitlab_session="+httpdecoy.StableID("session", 32)+"; path=/; HttpOnly; SameSite=None")
	httpdecoy.WriteText(w, http.StatusOK,
		strings.Replace(signInPage, "{{ERROR}}", errorBlock, 1))
}

const signInPage = `<!DOCTYPE html><html class="devise-layout-html" lang="en"><head>
<meta charset="utf-8">
<meta content="width=device-width, initial-scale=1" name="viewport">
<meta content="GitLab" name="application-name">
<meta content="GitLab" property="og:site_name">
<meta content="origin-when-cross-origin" name="referrer">
<title>Sign in &middot; GitLab</title>
<link rel="shortcut icon" type="image/png" href="/assets/favicon-7901bd695fb93edb.png">
<style>
body{font:14px/1.5 -apple-system,"Segoe UI",Roboto,Helvetica,sans-serif;background:#fff;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.login-box{border:1px solid #dbdbdb;border-radius:4px;padding:28px 32px;width:320px}
h1{font-size:18px;margin:0 0 6px;color:#303030}
.sub{color:#666;font-size:13px;margin:0 0 18px}
label{display:block;font-size:13px;color:#303030;margin:12px 0 4px}
input[type=text],input[type=password]{width:100%;padding:8px 10px;border:1px solid #bfbfbf;border-radius:4px;box-sizing:border-box}
button{width:100%;margin-top:18px;padding:9px;background:#1f75cb;color:#fff;border:0;border-radius:4px;cursor:pointer}
.gl-alert-danger{color:#c91c00;font-size:13px;margin:12px 0 0}
.foot{color:#999;font-size:12px;text-align:center;margin-top:16px}
</style></head>
<body class="login-page">
<div class="login-box">
<h1>GitLab</h1>
<p class="sub">A complete DevOps platform</p>
<form class="gl-show-field-errors" method="post" action="/users/sign_in" accept-charset="UTF-8">
<input type="hidden" name="authenticity_token" value="csrf-token-placeholder">
<label for="user_login">Username or email</label>
<input type="text" name="user[login]" id="user_login" autocomplete="username" autocapitalize="off" autocorrect="off">
<label for="user_password">Password</label>
<input type="password" name="user[password]" id="user_password" autocomplete="current-password">
<button type="submit" name="commit">Sign in</button>
{{ERROR}}
</form>
<p class="foot"><a href="/users/password/new">Forgot your password?</a></p>
</div>
</body></html>
`
