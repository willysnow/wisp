// Package imdssvc emulates a cloud instance metadata service.
//
// 169.254.169.254 is the same address on every cloud, it answers without
// authentication to anything running on the instance, and what it hands out is
// a set of credentials for the role the instance runs as. That combination is
// why it is the first thing a foothold reaches for and the target of nearly
// every server-side request forgery worth the name: one unvalidated URL
// parameter and a web application will fetch the role credentials on the
// attacker's behalf.
//
// There is no benign reason for an unfamiliar process to ask this address for
// `iam/security-credentials`. That makes it one of the rare honeypot signals
// with almost no false-positive story — not "someone scanned a port" but
// "something on this network is collecting cloud credentials right now".
//
// All three clouds are served from one listener, because they share the address
// and an intruder's tooling usually tries all three. Which one they reach for
// first is itself intelligence: it says what they believed they had landed on.
//
// The credentials returned are well-formed and inert. They authenticate to
// nothing, and they exist so that the request after the credential request —
// the one that says what the intruder meant to do with them — still happens.
package imdssvc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "imds"

type Service struct {
	addr   string
	region string
	role   string
}

// New builds the decoy. region and role are worth matching to the organisation
// being imitated: an instance in `us-east-1` running `prod-app-instance-role`
// is unremarkable in one company and obviously fake in another.
func New(addr, region, role string) *Service {
	if region == "" {
		region = "us-east-1"
	}
	if role == "" {
		role = "app-instance-role"
	}
	return &Service{addr: addr, region: region, role: role}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	rec := httpdecoy.NewRecorder(name, ln, emit)
	return httpdecoy.Serve(ctx, ln, s.handler(rec), nil)
}

func (s *Service) handler(rec *httpdecoy.Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/computeMetadata/"):
			s.google(w, r, rec)
		case strings.HasPrefix(path, "/metadata"):
			s.azure(w, r, rec)
		default:
			s.amazon(w, r, rec)
		}
	})
	return mux
}

// event builds the record, tagging which cloud's API was used and noting the
// two headers that give away a request made through something else.
func (s *Service) event(rec *httpdecoy.Recorder, r *http.Request, kind, cloud string) event.Event {
	ev := rec.Event(r, kind)
	ev.Data["cloud"] = cloud

	// An IMDS request is supposed to come from the instance itself. A
	// forwarded-for chain means it came through a proxy or a vulnerable
	// application, which is what server-side request forgery looks like from
	// this side.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ev.Data["x_forwarded_for"] = httpdecoy.Truncate(xff, httpdecoy.FieldLimit)
	}
	// The Host header survives an SSRF that rewrote only the path, and it often
	// still names the application that was tricked into making the request.
	if r.Host != "" {
		ev.Data["host"] = httpdecoy.Truncate(r.Host, httpdecoy.FieldLimit)
	}
	return ev
}

// amazon serves the EC2 metadata API, in both its versions.
func (s *Service) amazon(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	w.Header().Set("Server", "EC2ws")

	// IMDSv2 requires a session token obtained by PUT before anything else will
	// answer. This decoy issues one and then does not insist on it: refusing
	// v1-style requests would silence exactly the naive tooling and SSRF
	// payloads most worth recording, and every one of those requests is a
	// finding on its own.
	if r.URL.Path == "/latest/api/token" {
		ev := s.event(rec, r, "probe", "aws")
		ev.Data["imds_version"] = "v2"
		ev.Data["ttl"] = r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
		rec.Emit(ev)

		if r.Method != http.MethodPut {
			httpdecoy.WriteText(w, http.StatusMethodNotAllowed, "")
			return
		}
		w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", ttlOrDefault(r))
		httpdecoy.WriteText(w, http.StatusOK, sessionToken)
		return
	}

	rest, ok := apiVersion(r.URL.Path)
	if !ok {
		// The root lists the API versions, which is a fingerprint in itself —
		// nothing else on a network answers a bare GET with this.
		ev := s.event(rec, r, "probe", "aws")
		rec.Emit(ev)
		httpdecoy.WriteText(w, http.StatusOK, apiVersions)
		return
	}

	kind := "probe"
	switch {
	// The whole reason this decoy exists.
	case strings.HasPrefix(rest, "meta-data/iam"):
		kind = "credential_request"
	// User data is where deployment scripts, and the secrets they were given,
	// end up. Reading it is a credential hunt by a different route.
	case strings.HasPrefix(rest, "user-data"):
		kind = "resource_read"
	}

	ev := s.event(rec, r, kind, "aws")
	if tok := r.Header.Get("X-aws-ec2-metadata-token"); tok != "" {
		// Not a stolen credential — one this decoy handed out a moment ago —
		// but it records that the client did the v2 dance, which separates
		// current tooling from a copy-pasted curl one-liner.
		ev.Data["imds_version"] = "v2"
	}
	rec.Emit(ev)

	body, code := s.amazonBody(rest)
	httpdecoy.WriteText(w, code, body)
}

func (s *Service) amazonBody(rest string) (string, int) {
	switch {
	case rest == "", rest == "/":
		return "dynamic\nmeta-data\nuser-data\n", http.StatusOK

	case rest == "meta-data", rest == "meta-data/":
		return metaDataIndex, http.StatusOK

	case rest == "meta-data/iam/security-credentials",
		rest == "meta-data/iam/security-credentials/":
		// The role name. A scanner that gets this always comes back for the
		// credentials themselves, and that second request is the confirmation
		// that this was theft rather than a sweep.
		return s.role + "\n", http.StatusOK

	case rest == "meta-data/iam/security-credentials/"+s.role:
		return jsonText(s.credentials()), http.StatusOK

	case rest == "meta-data/iam/info":
		return jsonText(map[string]any{
			"Code":               "Success",
			"LastUpdated":        stamp(-4 * time.Hour),
			"InstanceProfileArn": "arn:aws:iam::" + accountID + ":instance-profile/" + s.role,
			"InstanceProfileId":  "AIPA" + strings.ToUpper(httpdecoy.StableID(s.role, 17)),
		}), http.StatusOK

	case rest == "user-data", rest == "user-data/":
		return userData, http.StatusOK

	case rest == "dynamic/instance-identity/document":
		return jsonText(s.identityDocument()), http.StatusOK

	case strings.HasPrefix(rest, "dynamic/"):
		return "", http.StatusNotFound
	}

	if v, ok := s.metaData()[strings.TrimPrefix(rest, "meta-data/")]; ok {
		return v, http.StatusOK
	}
	// A real IMDS 404s with an HTML body. Anything that parses the response
	// rather than the status code should see the same thing.
	return notFoundHTML, http.StatusNotFound
}

// google serves the GCP metadata server.
func (s *Service) google(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	w.Header().Set("Server", "Metadata Server for VM")
	w.Header().Set("Metadata-Flavor", "Google")

	path := strings.TrimPrefix(r.URL.Path, "/computeMetadata/v1")

	kind := "probe"
	switch {
	case strings.Contains(path, "service-accounts") && (strings.HasSuffix(path, "/token") || strings.HasSuffix(path, "/identity")):
		kind = "credential_request"
	case strings.Contains(path, "attributes"):
		// startup-script and the rest of the instance attributes: the GCP
		// equivalent of user-data, with the same habit of holding secrets.
		kind = "resource_read"
	}

	ev := s.event(rec, r, kind, "gcp")

	// GCP refuses any request without this header, specifically so that a
	// browser or a naive SSRF cannot reach the metadata server by URL alone.
	// A request that arrives without it is therefore worth its own note: it is
	// almost always something being tricked into asking rather than something
	// asking on purpose.
	if r.Header.Get("Metadata-Flavor") != "Google" {
		ev.Data["metadata_flavor"] = "missing"
		rec.Emit(ev)
		httpdecoy.WriteText(w, http.StatusForbidden, googleMissingFlavor(r.URL.Path))
		return
	}
	rec.Emit(ev)

	switch {
	case strings.HasSuffix(path, "/service-accounts/default/token"),
		strings.HasSuffix(path, "/token"):
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": googleAccessToken,
			"expires_in":   3599,
			"token_type":   "Bearer",
		})
	case strings.HasSuffix(path, "/identity"):
		httpdecoy.WriteText(w, http.StatusOK, googleIdentityToken)
	default:
		body, ok := s.googleMetadata()[strings.Trim(path, "/")]
		if !ok {
			httpdecoy.WriteText(w, http.StatusNotFound, "")
			return
		}
		httpdecoy.WriteText(w, http.StatusOK, body)
	}
}

// azure serves the Azure Instance Metadata Service.
func (s *Service) azure(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	w.Header().Set("Server", "IMDS/150.870.65.1324")

	kind := "probe"
	if strings.Contains(r.URL.Path, "/identity/oauth2/token") {
		kind = "credential_request"
	}

	ev := s.event(rec, r, kind, "azure")

	// Azure's equivalent guard, and the same reasoning: a request without it is
	// most likely something that was made to ask.
	if !strings.EqualFold(r.Header.Get("Metadata"), "true") {
		ev.Data["metadata_header"] = "missing"
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": "Required metadata header not specified",
		})
		return
	}

	if resource := r.URL.Query().Get("resource"); resource != "" {
		// Which Azure service the token was requested for names the next step:
		// management.azure.com is control-plane takeover, vault.azure.net is
		// the secret store.
		ev.Data["resource"] = httpdecoy.Truncate(resource, httpdecoy.FieldLimit)
	}
	rec.Emit(ev)

	switch {
	case strings.Contains(r.URL.Path, "/identity/oauth2/token"):
		resource := r.URL.Query().Get("resource")
		if resource == "" {
			resource = "https://management.azure.com/"
		}
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":   azureAccessToken,
			"client_id":      "8f2a1c07-4d3e-4a19-9c6b-7e0d1f5a2b83",
			"expires_in":     "3599",
			"expires_on":     unixStamp(time.Hour),
			"ext_expires_in": "3599",
			"not_before":     unixStamp(0),
			"resource":       resource,
			"token_type":     "Bearer",
		})
	case strings.HasPrefix(r.URL.Path, "/metadata/attested"):
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{
			"encoding":  "pkcs7",
			"signature": azureAttestedSignature,
		})
	case strings.HasPrefix(r.URL.Path, "/metadata/versions"):
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"apiVersions": azureAPIVersions})
	default:
		httpdecoy.WriteJSON(w, http.StatusOK, s.azureInstance())
	}
}

// apiVersion splits an EC2 metadata path into its version segment and the rest.
// Both `/latest/…` and a dated `/2021-07-15/…` are valid, and tooling uses
// both.
func apiVersion(path string) (string, bool) {
	trimmed := strings.TrimPrefix(path, "/")
	version, rest, _ := strings.Cut(trimmed, "/")

	if version == "latest" {
		return rest, true
	}
	// A dated version: four digits, a dash, and so on. Checking the shape is
	// enough — the decoy answers the same thing whichever date is asked for.
	if len(version) == 10 && version[4] == '-' && version[7] == '-' {
		return rest, true
	}
	return "", false
}

func ttlOrDefault(r *http.Request) string {
	if ttl := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"); ttl != "" {
		return ttl
	}
	return "21600"
}

// jsonText renders a document as the text/plain body IMDS actually serves.
// Clients parse the body as JSON regardless of the content type, and matching
// the real content type costs nothing.
func jsonText(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b) + "\n"
}

func stamp(offset time.Duration) string {
	return time.Now().UTC().Add(offset).Format("2006-01-02T15:04:05Z")
}

// unixStamp is Azure's preferred form: seconds since the epoch, as a string.
func unixStamp(offset time.Duration) string {
	return strconv.FormatInt(time.Now().Add(offset).Unix(), 10)
}
