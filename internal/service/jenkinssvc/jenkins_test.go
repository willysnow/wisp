package jenkinssvc

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
		return New(addr, "2.440.3")
	})
	return h, "http://" + h.Addr
}

// client does not follow redirects: the decoy answers several endpoints with a
// 302, and a test that followed them would assert on the wrong response.
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

func get(t *testing.T, target string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
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

// TestGroovyScriptIsCaptured is what the decoy exists for. The script console
// turns read access into code execution on the controller, and the script an
// intruder submits says which credential store they already knew to ask for.
func TestGroovyScriptIsCaptured(t *testing.T) {
	h, base := start(t)

	const script = `println new File("/var/lib/jenkins/credentials.xml").text`
	postForm(t, base+"/scriptText", url.Values{"script": {script}})

	ev := h.WaitFor(t, "command")
	if got, _ := ev.Data["script"].(string); got != script {
		t.Errorf("script = %q, want the submitted Groovy", got)
	}
}

// TestRawScriptBodyIsCaptured. Not every client form-encodes; a decoy that only
// understood `script=` would lose the ones that do not.
func TestRawScriptBodyIsCaptured(t *testing.T) {
	h, base := start(t)

	const payload = `"id".execute().text`
	req, err := http.NewRequest(http.MethodPost, base+"/scriptText", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	do(t, req)

	ev := h.WaitFor(t, "command")
	if got, _ := ev.Data["script"].(string); !strings.Contains(got, `"id".execute()`) {
		t.Errorf("script = %q, want the raw body", got)
	}
}

// TestScriptConsoleExecutesNothing. There is no Groovy interpreter here and
// there must never be one; the reply is empty because an empty result is what a
// script that printed nothing returns.
func TestScriptConsoleExecutesNothing(t *testing.T) {
	_, base := start(t)

	resp, body := postForm(t, base+"/scriptText",
		url.Values{"script": {`println "wisp-should-not-print-this"`}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if strings.Contains(body, "wisp-should-not-print-this") {
		t.Fatal("the decoy evaluated a submitted script")
	}
	if body != "" {
		t.Errorf("body = %q, want nothing", body)
	}
}

// TestLoginCredentialIsCaptured, along with where they were trying to get to —
// which is very often /script.
func TestLoginCredentialIsCaptured(t *testing.T) {
	h, base := start(t)

	resp, _ := postForm(t, base+"/j_spring_security_check", url.Values{
		"j_username": {"admin"},
		"j_password": {"jenkins123"},
		"from":       {"/script"},
	})
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want a 302 to the error page", resp.StatusCode)
	}

	ev := h.WaitFor(t, "login_form")
	if ev.Data["username"] != "admin" || ev.Data["password"] != "jenkins123" {
		t.Errorf("credential = %v/%v, want the submitted pair",
			ev.Data["username"], ev.Data["password"])
	}
	if ev.Data["from"] != "/script" {
		t.Errorf("from = %v, want where they were headed", ev.Data["from"])
	}
}

// TestNoCredentialIsEverAccepted, and the refusal never says which half was
// wrong — anything else lets an intruder enumerate accounts for free.
func TestNoCredentialIsEverAccepted(t *testing.T) {
	_, base := start(t)

	for _, pair := range [][2]string{
		{"admin", "admin"}, {"admin", ""}, {"", ""}, {"jenkins", "jenkins"},
	} {
		resp, _ := postForm(t, base+"/j_spring_security_check", url.Values{
			"j_username": {pair[0]}, "j_password": {pair[1]},
		})
		location := resp.Header.Get("Location")
		if location != "/loginError" {
			t.Errorf("%q/%q was sent to %q, want /loginError", pair[0], pair[1], location)
		}
	}

	_, body := get(t, base+"/loginError")
	if !strings.Contains(body, "Invalid username or password") {
		t.Errorf("error page does not say the login failed:\n%s", body)
	}
	if strings.Contains(strings.ToLower(body), "no such user") {
		t.Error("the error distinguishes a bad username from a bad password")
	}
}

// TestVersionIsInTheHeader. X-Jenkins is on every response of every real
// controller, and it is how every scanner in existence identifies one.
func TestVersionIsInTheHeader(t *testing.T) {
	h, base := start(t)

	resp, _ := get(t, base+"/")
	if got := resp.Header.Get("X-Jenkins"); got != "2.440.3" {
		t.Errorf("X-Jenkins = %q, want the configured version", got)
	}
	if got := resp.Header.Get("X-Jenkins-Session"); got == "" {
		t.Error("no X-Jenkins-Session header")
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") == "" {
		t.Errorf("root = %d, want a redirect to the login page", resp.StatusCode)
	}

	h.WaitFor(t, "probe")
}

// TestJobListNamesSomethingWorthOpening. An intruder reading /api/json is
// choosing which pipeline to look inside, and the one they choose is the one
// whose name sounds like it holds a deployment credential.
func TestJobListNamesSomethingWorthOpening(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/api/json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/json returned %d, want 200", resp.StatusCode)
	}

	var root struct {
		UseSecurity bool `json:"useSecurity"`
		Jobs        []struct{ Name, Color string }
	}
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatalf("/api/json is not JSON: %v", err)
	}
	if len(root.Jobs) == 0 {
		t.Fatal("no jobs — a controller with nothing on it is not worth a second request")
	}
	if !root.UseSecurity {
		t.Error("useSecurity is false while the decoy has a login form")
	}

	h.WaitFor(t, "resource_access")
}

// TestApiTokenIsCaptured. Jenkins API tokens are presented as HTTP basic auth
// with the token in place of the password, so a stolen one arrives in the
// clear — and an otherwise ordinary API read that carries one is recorded as
// the credential event it is.
func TestApiTokenIsCaptured(t *testing.T) {
	h, base := start(t)

	req, err := http.NewRequest(http.MethodGet, base+"/api/json", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.SetBasicAuth("ci-bot", "11a4f8c2e93b74d0516ac8e2f7b190d4cb")
	do(t, req)

	ev := h.WaitFor(t, "login_basic")
	if ev.Data["username"] != "ci-bot" {
		t.Errorf("username = %v, want the account the token belongs to", ev.Data["username"])
	}
	if pass, _ := ev.Data["password"].(string); !strings.HasPrefix(pass, "11a4f8c2") {
		t.Errorf("password = %q, want the presented token", pass)
	}
}

// TestCliPayloadIsCaptured. The CLI endpoint's argument parser is what
// CVE-2024-23897 turned into an arbitrary file read, and scanners still hammer
// it — the payload names the file they wanted.
func TestCliPayloadIsCaptured(t *testing.T) {
	h, base := start(t)

	req, err := http.NewRequest(http.MethodPost, base+"/cli?remoting=false",
		strings.NewReader("@/etc/passwd"))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	do(t, req)

	ev := h.WaitFor(t, "command")
	if got, _ := ev.Data["cli_payload"].(string); !strings.Contains(got, "/etc/passwd") {
		t.Errorf("cli_payload = %q, want the file they asked for", got)
	}
}

// TestBuildTriggerIsACommand. Starting a job runs whatever its pipeline says on
// whatever agent picks it up; it is the slower road to where /script goes.
func TestBuildTriggerIsACommand(t *testing.T) {
	h, base := start(t)

	postForm(t, base+"/job/deploy-production/build", nil)

	ev := h.WaitFor(t, "command")
	if ev.Data["job"] != "deploy-production" {
		t.Errorf("job = %v, want deploy-production", ev.Data["job"])
	}
}
