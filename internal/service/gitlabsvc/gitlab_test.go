package gitlabsvc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, string) {
	t.Helper()

	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "16.11.2")
	})
	return h, "http://" + h.Addr
}

// client does not follow redirects: the decoy sends unauthenticated browsers to
// the sign-in page, and a test that followed the 302 would assert on the wrong
// response.
func client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()

	resp, err := client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func get(t *testing.T, target string, header map[string]string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return do(t, req)
}

func postForm(t *testing.T, target string, form url.Values) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, req)
}

// stolenToken stands in for a personal access token. It deliberately does not
// have a real one's shape — `glpat-` followed by exactly twenty characters from
// [A-Za-z0-9_-] — because that shape is what every secret scanner looks for,
// and a fixture matching it gets this repository's pushes rejected. The decoy
// records whatever arrives, so the fixture only has to be distinctive.
const stolenToken = "glpat-EXAMPLE.only.in.tests"

// TestStolenTokenIsCaptured is what the decoy exists for. Knowing which token
// was used is what turns an alert into an incident with a scope: the token
// names its owner, and the path names what they believed it would open.
func TestStolenTokenIsCaptured(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/api/v4/projects/14/variables",
		map[string]string{"PRIVATE-TOKEN": stolenToken})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — no token is ever accepted", resp.StatusCode)
	}
	if !strings.Contains(body, "401 Unauthorized") {
		t.Errorf("body = %q, want GitLab's own refusal", body)
	}

	ev := h.WaitFor(t, "resource_read")
	if ev.Data["private_token"] != stolenToken {
		t.Errorf("private_token = %v, want the presented credential", ev.Data["private_token"])
	}
	if ev.Data["project"] != "14" || ev.Data["resource"] != "variables" {
		t.Errorf("target = %v/%v, want the CI/CD variables of project 14",
			ev.Data["project"], ev.Data["resource"])
	}
}

// TestTokenInTheQueryStringIsCaptured. GitLab accepts `?private_token=`, which
// is how tokens end up in proxy logs and browser history — and therefore how
// they get stolen in the first place.
func TestTokenInTheQueryStringIsCaptured(t *testing.T) {
	h, base := start(t)

	get(t, base+"/api/v4/user?private_token="+stolenToken, nil)

	ev := h.WaitFor(t, "resource_read")
	if ev.Data["private_token"] != stolenToken {
		t.Errorf("private_token = %v, want the credential from the query string",
			ev.Data["private_token"])
	}
}

// TestJobTokenIsCaptured. A CI job token is the credential a compromised
// pipeline runs with, and it is a different thing to have stolen than a
// personal one.
func TestJobTokenIsCaptured(t *testing.T) {
	h, base := start(t)

	get(t, base+"/api/v4/projects/7/repository/files/config%2Fsecrets.yml",
		map[string]string{"JOB-TOKEN": "64_kqL8vX2mTfR1pZ"})

	ev := h.WaitFor(t, "resource_read")
	if ev.Data["job_token"] != "64_kqL8vX2mTfR1pZ" {
		t.Errorf("job_token = %v, want the presented credential", ev.Data["job_token"])
	}
	if res, _ := ev.Data["resource"].(string); !strings.Contains(res, "secrets.yml") {
		t.Errorf("resource = %q, want the file they were after", res)
	}
}

// TestPublicProjectListAnswers. A real GitLab gives anonymous callers its
// public projects, and that list is what supplies the project id for the
// request that carries the token.
func TestPublicProjectListAnswers(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/api/v4/projects", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/v4/projects returned %d, want 200", resp.StatusCode)
	}

	var list []struct {
		ID                int    `json:"id"`
		PathWithNamespace string `json:"path_with_namespace"`
		DefaultBranch     string `json:"default_branch"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("project list is not JSON: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("no projects — nothing for an intruder to point a token at")
	}
	for _, p := range list {
		if p.ID == 0 || p.PathWithNamespace == "" || p.DefaultBranch == "" {
			t.Errorf("project is missing fields a real one has: %+v", p)
		}
	}

	h.WaitFor(t, "resource_access")
}

// TestUnknownProjectIdStillAnswers. A GitLab that 404s the id an intruder
// guessed teaches them the id space; one that answers consistently teaches them
// nothing.
func TestUnknownProjectIdStillAnswers(t *testing.T) {
	_, base := start(t)

	resp, body := get(t, base+"/api/v4/projects/9182", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "path_with_namespace") {
		t.Errorf("body = %q, want a project document", body)
	}
}

// TestSignInFormCredentialIsCaptured. GitLab nests its fields as `user[login]`
// and `user[password]`, which is exactly the shape a generic credential scraper
// misses.
func TestSignInFormCredentialIsCaptured(t *testing.T) {
	h, base := start(t)

	resp, body := postForm(t, base+"/users/sign_in", url.Values{
		"user[login]":    {"root"},
		"user[password]": {"5iveL!fe"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the sign-in page back", resp.StatusCode)
	}
	if !strings.Contains(body, "Invalid login or password") {
		t.Errorf("page does not report a failed login:\n%s", body)
	}

	ev := h.WaitFor(t, "login_form")
	if ev.Data["username"] != "root" || ev.Data["password"] != "5iveL!fe" {
		t.Errorf("credential = %v/%v, want the submitted pair",
			ev.Data["username"], ev.Data["password"])
	}
}

// TestOauthPasswordGrantIsCaptured. Tooling holding a username and password
// rather than a token comes here, and the pair arrives in the request body.
func TestOauthPasswordGrantIsCaptured(t *testing.T) {
	h, base := start(t)

	resp, _ := postForm(t, base+"/oauth/token", url.Values{
		"grant_type": {"password"},
		"username":   {"deploy"},
		"password":   {"Autumn-2026!"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — nothing is ever granted", resp.StatusCode)
	}

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "deploy" || ev.Data["password"] != "Autumn-2026!" {
		t.Errorf("credential = %v/%v, want the submitted pair",
			ev.Data["username"], ev.Data["password"])
	}
	if ev.Data["grant_type"] != "password" {
		t.Errorf("grant_type = %v, want password", ev.Data["grant_type"])
	}
}

// TestOauthAcceptsJsonToo, because half the tooling sends JSON.
func TestOauthAcceptsJsonToo(t *testing.T) {
	h, base := start(t)

	req, err := http.NewRequest(http.MethodPost, base+"/oauth/token",
		strings.NewReader(`{"grant_type":"password","username":"svc-ci","password":"hunter2"}`))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	do(t, req)

	ev := h.WaitFor(t, "login_password")
	if ev.Data["username"] != "svc-ci" || ev.Data["password"] != "hunter2" {
		t.Errorf("credential = %v/%v, want the JSON body decoded",
			ev.Data["username"], ev.Data["password"])
	}
}

// TestSignInPageLooksLikeGitLab. The page and the session cookie are what
// identify the host, and tooling that follows the sign-in flow expects both.
func TestSignInPageLooksLikeGitLab(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/users/sign_in", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"user[login]", "user[password]", "authenticity_token"} {
		if !strings.Contains(body, want) {
			t.Errorf("sign-in page is missing %q", want)
		}
	}
	if cookie := resp.Header.Get("Set-Cookie"); !strings.Contains(cookie, "_gitlab_session") {
		t.Errorf("Set-Cookie = %q, want a _gitlab_session", cookie)
	}
	if resp.Header.Get("Server") != "nginx" {
		t.Errorf("Server = %q, want nginx", resp.Header.Get("Server"))
	}

	h.WaitFor(t, "probe")
}

// TestVersionIsReadable. A scanner that cannot tell which GitLab this is has no
// reason to come back, and the version is what decides that.
func TestVersionIsReadable(t *testing.T) {
	_, base := start(t)

	_, body := get(t, base+"/api/v4/version", nil)

	var version struct{ Version, Revision string }
	if err := json.Unmarshal([]byte(body), &version); err != nil {
		t.Fatalf("/api/v4/version is not JSON: %v", err)
	}
	if version.Version != "16.11.2" {
		t.Errorf("version = %q, want the configured one", version.Version)
	}
}

// TestHealthEndpointAnswers, because a load balancer check that fails is one
// more reason for somebody to look closely at this host.
func TestHealthEndpointAnswers(t *testing.T) {
	_, base := start(t)

	resp, body := get(t, base+"/-/health", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "GitLab OK") {
		t.Errorf("/-/health = %d %q, want 200 \"GitLab OK\"", resp.StatusCode, body)
	}
}
