package imdssvc

import (
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
		return New(addr, "us-east-1", "prod-app-instance-role")
	})
	return h, "http://" + h.Addr
}

func do(t *testing.T, method, url string, header map[string]string) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

func get(t *testing.T, url string) (*http.Response, string) {
	return do(t, http.MethodGet, url, nil)
}

// TestRoleCredentialsAreHandedOver is the interaction the decoy exists for.
//
// Two requests, and the second one is the finding. Listing the role is
// something a misconfigured scanner might do; coming back for the credentials
// under that specific role name is a decision.
func TestRoleCredentialsAreHandedOver(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/latest/meta-data/iam/security-credentials/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("role listing returned %d, want 200", resp.StatusCode)
	}
	role := strings.TrimSpace(body)
	if role != "prod-app-instance-role" {
		t.Fatalf("role = %q, want the configured one", role)
	}

	ev := h.WaitFor(t, "credential_request")
	if ev.Data["cloud"] != "aws" {
		t.Errorf("cloud = %v, want aws", ev.Data["cloud"])
	}

	_, body = get(t, base+"/latest/meta-data/iam/security-credentials/"+role)

	var creds struct {
		Code            string
		AccessKeyId     string
		SecretAccessKey string
		Token           string
		Expiration      string
	}
	if err := json.Unmarshal([]byte(body), &creds); err != nil {
		t.Fatalf("credentials are not JSON: %v\n%s", err, body)
	}
	if creds.Code != "Success" {
		t.Errorf("Code = %q, want Success — tooling checks this before anything else", creds.Code)
	}
	if !strings.HasPrefix(creds.AccessKeyId, "ASIA") || len(creds.AccessKeyId) != 20 {
		t.Errorf("AccessKeyId = %q, want a 20-character temporary key", creds.AccessKeyId)
	}
	if len(creds.SecretAccessKey) != 40 {
		t.Errorf("SecretAccessKey is %d characters, want 40", len(creds.SecretAccessKey))
	}
	if len(creds.Token) < 200 {
		t.Errorf("session token is %d characters — a short one is the tell", len(creds.Token))
	}
	if creds.Expiration == "" {
		t.Error("credentials with no expiry are not temporary credentials")
	}
}

// TestCredentialsDoNotChangeBetweenRestarts. An intruder who asks twice and
// gets two different key IDs for the same role learns that nothing behind this
// address is real.
func TestCredentialsDoNotChangeBetweenRestarts(t *testing.T) {
	first := New("127.0.0.1:0", "us-east-1", "prod-app-instance-role").credentials()
	second := New("127.0.0.1:0", "us-east-1", "prod-app-instance-role").credentials()

	if first["AccessKeyId"] != second["AccessKeyId"] {
		t.Error("the access key changed between restarts — that is a honeypot fingerprint")
	}
	if first["SecretAccessKey"] != second["SecretAccessKey"] {
		t.Error("the secret key changed between restarts")
	}
}

// TestImdsV2SessionFlow. Current tooling asks for a session token first;
// copy-pasted one-liners do not. Recording which happened separates a modern
// implant from an opportunistic curl.
func TestImdsV2SessionFlow(t *testing.T) {
	h, base := start(t)

	resp, token := do(t, http.MethodPut, base+"/latest/api/token",
		map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
	if resp.StatusCode != http.StatusOK || token == "" {
		t.Fatalf("token request = %d %q, want a session token", resp.StatusCode, token)
	}
	if got := resp.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"); got != "21600" {
		t.Errorf("ttl header = %q, want the requested 21600", got)
	}

	do(t, http.MethodGet, base+"/latest/meta-data/iam/security-credentials/",
		map[string]string{"X-aws-ec2-metadata-token": token})

	ev := h.WaitFor(t, "credential_request")
	if ev.Data["imds_version"] != "v2" {
		t.Errorf("imds_version = %v, want v2 for a request carrying a session token", ev.Data["imds_version"])
	}
}

// TestV1RequestsStillAnswer. A decoy that enforced IMDSv2 would silence exactly
// the naive tooling and SSRF payloads most worth recording — and refusing them
// would also cost the event, not just the reply.
func TestV1RequestsStillAnswer(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/latest/meta-data/iam/security-credentials/prod-app-instance-role")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("v1-style request returned %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "ASIA") {
		t.Errorf("body = %q, want credentials", body)
	}

	h.WaitFor(t, "credential_request")
}

// TestForwardedRequestIsMarkedAsSuch. An IMDS request is supposed to come from
// the instance itself; a forwarded-for chain means something else was made to
// ask, which is what server-side request forgery looks like from this side.
func TestForwardedRequestIsMarkedAsSuch(t *testing.T) {
	h, base := start(t)

	do(t, http.MethodGet, base+"/latest/meta-data/iam/security-credentials/",
		map[string]string{"X-Forwarded-For": "203.0.113.44"})

	ev := h.WaitFor(t, "credential_request")
	if xff, _ := ev.Data["x_forwarded_for"].(string); xff != "203.0.113.44" {
		t.Errorf("x_forwarded_for = %q, want the address the request was made for", xff)
	}
}

// TestGoogleRefusesWithoutTheFlavorHeader, and records the attempt anyway.
//
// GCP's header requirement exists to stop a browser or a naive SSRF reaching
// the metadata server by URL alone. Reproducing the refusal keeps the decoy
// honest; recording the request is the point — a request that arrives without
// the header is almost always something that was tricked into asking.
func TestGoogleRefusesWithoutTheFlavorHeader(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/computeMetadata/v1/instance/service-accounts/default/token")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(body, "Metadata-Flavor") {
		t.Errorf("body = %q, want the refusal a real metadata server gives", body)
	}

	ev := h.WaitFor(t, "credential_request")
	if ev.Data["cloud"] != "gcp" {
		t.Errorf("cloud = %v, want gcp", ev.Data["cloud"])
	}
	if ev.Data["metadata_flavor"] != "missing" {
		t.Errorf("metadata_flavor = %v, want it noted as missing", ev.Data["metadata_flavor"])
	}
}

// TestGoogleTokenIsIssuedWithTheHeader.
func TestGoogleTokenIsIssuedWithTheHeader(t *testing.T) {
	h, base := start(t)

	resp, body := do(t, http.MethodGet,
		base+"/computeMetadata/v1/instance/service-accounts/default/token",
		map[string]string{"Metadata-Flavor": "Google"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		t.Fatalf("token response is not JSON: %v", err)
	}
	if !strings.HasPrefix(tok.AccessToken, "ya29.") || tok.TokenType != "Bearer" {
		t.Errorf("token = %+v, want the shape a real one has", tok)
	}

	ev := h.WaitFor(t, "credential_request")
	if ev.Data["metadata_flavor"] != nil {
		t.Errorf("metadata_flavor = %v on a request that carried it", ev.Data["metadata_flavor"])
	}
}

// TestAzureTokenNamesTheResource. Which service the managed-identity token was
// requested for is the next step written down: management.azure.com is
// control-plane takeover, vault.azure.net is the secret store.
func TestAzureTokenNamesTheResource(t *testing.T) {
	h, base := start(t)

	resp, body := do(t, http.MethodGet,
		base+"/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net",
		map[string]string{"Metadata": "true"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "access_token") {
		t.Errorf("body = %q, want a token response", body)
	}

	ev := h.WaitFor(t, "credential_request")
	if ev.Data["cloud"] != "azure" {
		t.Errorf("cloud = %v, want azure", ev.Data["cloud"])
	}
	if res, _ := ev.Data["resource"].(string); !strings.Contains(res, "vault.azure.net") {
		t.Errorf("resource = %q, want the service they wanted a token for", res)
	}
}

// TestAzureRefusesWithoutTheMetadataHeader, in the same words a real one uses.
func TestAzureRefusesWithoutTheMetadataHeader(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/metadata/instance?api-version=2021-02-01")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(body, "Required metadata header not specified") {
		t.Errorf("body = %q, want the real error", body)
	}

	h.WaitFor(t, "probe")
}

// TestUserDataIsARead, not a probe. Deployment scripts are where secrets end
// up, so fetching one belongs with the events that wake somebody.
func TestUserDataIsARead(t *testing.T) {
	h, base := start(t)

	resp, body := get(t, base+"/latest/user-data")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "#cloud-config") {
		t.Errorf("body = %q, want a boot script", body)
	}

	h.WaitFor(t, "resource_read")
}

// TestDatedApiVersionsWork. Tooling uses `/latest/` and a pinned date
// interchangeably; a decoy that only understood one would 404 half of it.
func TestDatedApiVersionsWork(t *testing.T) {
	_, base := start(t)

	for _, prefix := range []string{"/latest", "/2021-07-15", "/2016-09-02"} {
		resp, body := get(t, base+prefix+"/meta-data/instance-id")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d, want 200", prefix, resp.StatusCode)
		}
		if !strings.HasPrefix(body, "i-") {
			t.Errorf("%s returned %q, want an instance id", prefix, body)
		}
	}
}
