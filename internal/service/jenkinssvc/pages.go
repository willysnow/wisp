package jenkinssvc

import "github.com/willysnow/wisp/internal/service/httpdecoy"

// The controller's fabricated contents.
//
// The job names are the bait. An intruder reading `/api/json` is choosing which
// pipeline to look inside, and they choose the one whose name sounds like it
// holds a deployment credential — which is also the one whose name tells you
// what they were after when they ask for it.

var jobs = []struct{ name, colour string }{
	{"deploy-production", "blue"},
	{"payments-api-build", "blue"},
	{"infra-terraform-apply", "yellow"},
	{"nightly-integration", "blue_anime"},
	{"backup-restore-drill", "notbuilt"},
}

func (s *Service) root() map[string]any {
	list := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		list = append(list, map[string]any{
			"_class": "hudson.model.FreeStyleProject",
			"name":   j.name,
			"url":    "http://jenkins.internal:8080/job/" + j.name + "/",
			"color":  j.colour,
		})
	}

	return map[string]any{
		"_class":          "hudson.model.Hudson",
		"assignedLabels":  []map[string]any{{"name": "built-in"}},
		"mode":            "NORMAL",
		"nodeDescription": "the Jenkins controller's built-in node",
		"nodeName":        "",
		"numExecutors":    2,
		"description":     nil,
		"jobs":            list,
		"quietDownReason": nil,
		"quietingDown":    false,
		"slaveAgentPort":  50000,
		"useCrumbs":       true,
		"useSecurity":     true,
		"views": []map[string]any{
			{"_class": "hudson.model.AllView", "name": "all", "url": "http://jenkins.internal:8080/"},
		},
	}
}

func (s *Service) job(name string) map[string]any {
	if name == "" {
		name = "deploy-production"
	}

	return map[string]any{
		"_class":      "hudson.model.FreeStyleProject",
		"actions":     []any{},
		"description": "",
		"displayName": name,
		"fullName":    name,
		"name":        name,
		"url":         "http://jenkins.internal:8080/job/" + name + "/",
		"buildable":   true,
		"builds": []map[string]any{
			{"_class": "hudson.model.FreeStyleBuild", "number": 412,
				"url": "http://jenkins.internal:8080/job/" + name + "/412/"},
		},
		"color": "blue",
		"lastSuccessfulBuild": map[string]any{
			"_class": "hudson.model.FreeStyleBuild", "number": 412,
			"url": "http://jenkins.internal:8080/job/" + name + "/412/",
		},
		"nextBuildNumber": 413,
		"inQueue":         false,
		"concurrentBuild": false,
	}
}

func (s *Service) computerList() map[string]any {
	return map[string]any{
		"_class":         "hudson.model.ComputerSet",
		"busyExecutors":  0,
		"displayName":    "Nodes",
		"totalExecutors": 6,
		"computer": []map[string]any{
			{"_class": "hudson.model.Hudson$MasterComputer", "displayName": "Built-In Node",
				"numExecutors": 2, "offline": false, "temporarilyOffline": false, "idle": true},
			{"_class": "hudson.slaves.SlaveComputer", "displayName": "linux-agent-01",
				"numExecutors": 4, "offline": false, "temporarilyOffline": false, "idle": true},
		},
	}
}

func (s *Service) pluginList() map[string]any {
	specs := []struct{ shortName, version, longName string }{
		{"credentials", "1319.v7eb_51b_3a_c97b_", "Credentials Plugin"},
		{"git", "5.2.1", "Git plugin"},
		{"workflow-aggregator", "596.v8c21c963d92d", "Pipeline"},
		{"kubernetes", "4186.v1d804571d5d4", "Kubernetes plugin"},
		{"script-security", "1326.vdb_c154de8669", "Script Security Plugin"},
	}

	list := make([]map[string]any, 0, len(specs))
	for _, p := range specs {
		list = append(list, map[string]any{
			"shortName": p.shortName, "version": p.version, "longName": p.longName,
			"active": true, "enabled": true, "hasUpdate": false,
		})
	}
	return map[string]any{"_class": "hudson.PluginManager", "plugins": list}
}

// instanceIdentity is the controller's public key, sent on every response. It is
// public by design — the CLI uses it — and it has to be stable, because one
// that changed on every restart would identify the box as a honeypot to
// anything that connected twice.
var instanceIdentity = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" +
	httpdecoy.StableID("instance-identity", 300) + "IDAQAB"

const loginPage = `<!DOCTYPE html><html lang="en" class="no-decoration"><head>
<meta charset="utf-8"><meta name="ROBOTS" content="INDEX,NOFOLLOW">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in [Jenkins]</title>
<link rel="stylesheet" href="/static/8a5f2c1e/jsbundles/base-styles-v2.css" type="text/css">
<meta name="jenkins-version" content="%s">
<style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,sans-serif;background:#f8f8f8;margin:0;
display:flex;min-height:100vh;align-items:center;justify-content:center}
.app-sign-in-register{background:#fff;padding:30px 34px;border:1px solid #e6e6e6;border-radius:5px;width:320px}
h1{font-size:20px;margin:0 0 18px;color:#1a1a1a}
label{display:block;font-size:13px;color:#4d4d4d;margin:12px 0 4px}
input{width:100%%;padding:8px 10px;border:1px solid #cfcfcf;border-radius:4px;box-sizing:border-box}
button{width:100%%;margin-top:18px;padding:9px;background:#1a5fb4;color:#fff;border:0;border-radius:4px;cursor:pointer}
.app-sign-in-register__error{color:#c00;font-size:13px;margin:12px 0 0}
.foot{color:#8e8e8e;font-size:11px;text-align:center;margin-top:16px}
</style></head><body>
<form class="app-sign-in-register" method="post" action="j_spring_security_check" name="login">
<h1>Sign in to Jenkins</h1>
<label for="j_username">Username</label>
<input id="j_username" name="j_username" type="text" autocapitalize="off" autocorrect="off">
<label for="j_password">Password</label>
<input id="j_password" name="j_password" type="password">
<input name="from" type="hidden" value="/">
<button type="submit" name="Submit">Sign in</button>
%s
<p class="foot">Jenkins %s</p>
</form></body></html>
`

const scriptConsolePage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Jenkins</title></head><body>
<div id="main-panel">
<h1>Script Console</h1>
<p>Type in an arbitrary <a href="https://www.groovy-lang.org/">Groovy</a> script and
execute it on the server. Useful for trouble-shooting and diagnostics. Use the
<code>println</code> command to see the output (if you use <code>System.out</code>,
it will go to the server&#039;s stdout, which is harder to see.) Example:</p>
<pre>println(Jenkins.instance.pluginManager.plugins)</pre>
<p>All the classes from all the plugins are visible. <code>jenkins.*</code>,
<code>jenkins.model.*</code>, <code>hudson.*</code>, and <code>hudson.model.*</code> are pre-imported.</p>
<form method="post" action="script">
<textarea name="script" rows="10" cols="80"></textarea>
<input type="submit" value="Run">
</form>
<h2>Result</h2>
<pre></pre>
</div></body></html>
`

const managePage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Manage Jenkins</title></head><body>
<div id="main-panel"><h1>Manage Jenkins</h1>
<p>You do not have permission to view this page.</p>
</div></body></html>
`

const notFoundPage = `<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/>
<script>window.location.replace('/login?from=%2F');</script></head>
<body style='background-color:white; color:white;'>
Authentication required
</body></html>
`
