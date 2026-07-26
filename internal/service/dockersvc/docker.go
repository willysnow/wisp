// Package dockersvc emulates the Docker Engine API on 2375.
//
// An exposed Docker socket is not a vulnerability, it is a shell. Anyone who
// can reach it can create a container that bind-mounts the host's root
// filesystem, start it, and read or write anything on the machine as root — no
// exploit, no credential, just the API working as designed. That is why
// `-H tcp://0.0.0.0:2375` keeps appearing on internal networks and why
// automated cryptomining campaigns have scanned for it for a decade.
//
// The decoy answers like a daemon with a handful of ordinary containers on it,
// and the capture that matters is the container spec:
//
//	docker  container_create  image=alpine  cmd=[chroot /host sh]
//	        binds=[/:/host]  privileged=true  escape=[host_filesystem privileged]
//
// A spec is a written-down plan. It says what the intruder intended to reach,
// and unlike a connection log it is not ambiguous: nobody bind-mounts `/` into
// a container by accident. The `escape` field names the reasons the spec would
// have given away the host, so the alert is readable without parsing JSON at
// three in the morning.
//
// Nothing is created, started, pulled, or deleted. Every identifier in a reply
// is derived from the request.
package dockersvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/willysnow/wisp/internal/event"
	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

const name = "docker"

type Service struct {
	addr string
	// version is the daemon version reported by /version and /info; apiVersion
	// is the API level, which clients negotiate against and which appears in
	// the path of nearly every request.
	version    string
	apiVersion string
}

func New(addr, version, apiVersion string) *Service {
	return &Service{addr: addr, version: version, apiVersion: apiVersion}
}

func (s *Service) Name() string { return name }
func (s *Service) Addr() string { return s.addr }

// Serve runs the decoy in plaintext. That is not an oversight: a daemon
// listening on 2376 with TLS and client-certificate authentication is the
// configuration nobody gets attacked through, and 2375 in the clear is the one
// this decoy is imitating.
func (s *Service) Serve(ctx context.Context, ln net.Listener, emit event.Emitter) error {
	rec := httpdecoy.NewRecorder(name, ln, emit)
	return httpdecoy.Serve(ctx, ln, s.handler(rec), nil)
}

func (s *Service) handler(rec *httpdecoy.Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.header(w)

		seg := segments(stripAPIVersion(r.URL.Path))
		if len(seg) == 0 {
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusNotFound, map[string]any{"message": "page not found"})
			return
		}

		switch seg[0] {
		case "_ping":
			// The client's first call, and every scanner's fingerprint: the
			// answer is two letters, but the headers name the daemon.
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteText(w, http.StatusOK, "OK")

		case "version":
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.versionInfo())

		case "info":
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusOK, s.info())

		case "containers":
			s.containers(w, r, rec, seg[1:])

		case "exec":
			s.exec(w, r, rec, seg[1:])

		case "images":
			s.images(w, r, rec, seg[1:])

		case "build":
			// A build runs arbitrary RUN lines on the daemon's host. Same
			// outcome as a privileged container, different paperwork.
			ev := rec.Event(r, "container_create")
			ev.Data["build"] = true
			registryAuth(&ev, r.Header.Get("X-Registry-Config"))
			rec.Emit(ev)
			httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"stream": "Sending build context to Docker daemon\n"})

		// Swarm secrets and configs are the credentials the cluster runs on,
		// readable through this API by anyone the manager will talk to.
		case "secrets", "configs":
			rec.Emit(rec.Event(r, "resource_read"))
			httpdecoy.WriteJSON(w, http.StatusOK, secretList(seg[0]))

		case "networks", "volumes", "nodes", "services", "tasks", "swarm", "plugins", "system":
			rec.Emit(rec.Event(r, "resource_access"))
			httpdecoy.WriteJSON(w, http.StatusOK, inventoryFor(seg[0]))

		case "events":
			// A real /events hangs until something happens. Holding the
			// connection open would tie up a goroutine for as long as the
			// client cared to leave it there, so this one returns nothing and
			// closes — which is what a daemon with an `until` filter does.
			rec.Emit(rec.Event(r, "resource_access"))
			httpdecoy.WriteText(w, http.StatusOK, "")

		default:
			rec.Emit(rec.Event(r, "probe"))
			httpdecoy.WriteJSON(w, http.StatusNotFound, map[string]any{
				"message": "page not found",
			})
		}
	})
	return mux
}

// containers handles /containers/… — the subtree the escape happens in.
func (s *Service) containers(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	switch {
	case len(seg) == 1 && seg[0] == "json":
		rec.Emit(rec.Event(r, "container_list"))
		httpdecoy.WriteJSON(w, http.StatusOK, containerList)

	case len(seg) == 1 && seg[0] == "create":
		s.create(w, r, rec)

	case len(seg) == 1 && seg[0] == "prune":
		rec.Emit(rec.Event(r, "delete_request"))
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"ContainersDeleted": []string{}, "SpaceReclaimed": 0})

	case len(seg) == 2 && seg[1] == "exec":
		// Exec against an existing container. The command is the artifact.
		body := httpdecoy.JSONBody(w, r)
		ev := rec.Event(r, "command")
		ev.Data["container"] = seg[0]
		if cmd := httpdecoy.StringsField(body, "Cmd", "cmd"); len(cmd) > 0 {
			ev.Data["cmd"] = httpdecoy.Truncate(strings.Join(cmd, " "), httpdecoy.FieldLimit)
		}
		if user := httpdecoy.StringField(body, "User", "user"); user != "" {
			ev.Data["user"] = user
		}
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusCreated, map[string]any{"Id": idFor(seg[0] + "exec")})

	case len(seg) == 2 && seg[1] == "archive":
		// GET reads a path out of a container; PUT writes one in. The second is
		// how a payload gets onto a host through a bind-mounted container.
		kind := "resource_read"
		if r.Method == http.MethodPut {
			kind = "write_request"
		}
		ev := rec.Event(r, kind)
		ev.Data["container"] = seg[0]
		ev.Data["container_path"] = r.URL.Query().Get("path")
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{})

	case len(seg) == 2 && (seg[1] == "start" || seg[1] == "restart" || seg[1] == "unpause"):
		// Starting the container they just described is the moment the plan
		// would have become an intrusion.
		ev := rec.Event(r, "container_start")
		ev.Data["container"] = seg[0]
		rec.Emit(ev)
		w.WriteHeader(http.StatusNoContent)

	case len(seg) == 1 || len(seg) == 2:
		if r.Method == http.MethodDelete {
			ev := rec.Event(r, "delete_request")
			ev.Data["container"] = seg[0]
			rec.Emit(ev)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		ev := rec.Event(r, "resource_access")
		ev.Data["container"] = seg[0]
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, inspect(seg[0]))

	default:
		rec.Emit(rec.Event(r, "resource_access"))
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{})
	}
}

// create records a container specification and never creates anything.
func (s *Service) create(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder) {
	body := httpdecoy.JSONBody(w, r)

	ev := rec.Event(r, "container_create")
	if v := httpdecoy.StringField(body, "Image", "image"); v != "" {
		ev.Data["image"] = httpdecoy.Truncate(v, httpdecoy.FieldLimit)
	}
	if v := r.URL.Query().Get("name"); v != "" {
		ev.Data["name"] = v
	}
	if cmd := httpdecoy.StringsField(body, "Cmd", "cmd"); len(cmd) > 0 {
		ev.Data["cmd"] = httpdecoy.Truncate(strings.Join(cmd, " "), httpdecoy.FieldLimit)
	}
	if ep := httpdecoy.StringsField(body, "Entrypoint", "entrypoint"); len(ep) > 0 {
		ev.Data["entrypoint"] = httpdecoy.Truncate(strings.Join(ep, " "), httpdecoy.FieldLimit)
	}
	if env := httpdecoy.StringsField(body, "Env", "env"); len(env) > 0 {
		ev.Data["env"] = httpdecoy.Truncate(strings.Join(env, " "), httpdecoy.FieldLimit)
	}

	host := httpdecoy.MapField(body, "HostConfig", "hostConfig")
	binds := hostPaths(host)
	if len(binds) > 0 {
		ev.Data["binds"] = httpdecoy.Truncate(strings.Join(binds, " "), httpdecoy.FieldLimit)
	}
	for field, key := range map[string]string{
		"pid_mode":     "PidMode",
		"network_mode": "NetworkMode",
		"ipc_mode":     "IpcMode",
	} {
		if v := httpdecoy.StringField(host, key); v != "" {
			ev.Data[field] = v
		}
	}
	if httpdecoy.BoolField(host, "Privileged") {
		ev.Data["privileged"] = true
	}
	if caps := httpdecoy.StringsField(host, "CapAdd"); len(caps) > 0 {
		ev.Data["cap_add"] = strings.Join(caps, " ")
	}

	// The summary an analyst reads first. A spec with none of these reasons is
	// someone running a container; a spec with any of them is someone leaving.
	if reasons := escapeReasons(binds, host); len(reasons) > 0 {
		ev.Data["escape"] = strings.Join(reasons, " ")
	}
	rec.Emit(ev)

	httpdecoy.WriteJSON(w, http.StatusCreated, map[string]any{
		"Id":       idFor(httpdecoy.StringField(body, "Image", "image") + r.URL.Query().Get("name")),
		"Warnings": []string{},
	})
}

func (s *Service) exec(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	ev := rec.Event(r, "resource_access")
	if len(seg) > 0 {
		ev.Data["exec_id"] = seg[0]
	}
	// /exec/{id}/start hijacks the connection to stream output. Answering with
	// an empty stream is enough: the command was captured when the exec was
	// created, and there is nothing running to produce output.
	rec.Emit(ev)
	httpdecoy.WriteText(w, http.StatusOK, "")
}

func (s *Service) images(w http.ResponseWriter, r *http.Request, rec *httpdecoy.Recorder, seg []string) {
	switch {
	case len(seg) == 1 && seg[0] == "json":
		rec.Emit(rec.Event(r, "resource_access"))
		httpdecoy.WriteJSON(w, http.StatusOK, imageList)

	case len(seg) == 1 && seg[0] == "create":
		// A pull. The image name is the whole story — a miner, a shell, or a
		// toolkit — and the registry credential travels with it.
		ev := rec.Event(r, "write_request")
		if img := r.URL.Query().Get("fromImage"); img != "" {
			ev.Data["image"] = httpdecoy.Truncate(img, httpdecoy.FieldLimit)
			if tag := r.URL.Query().Get("tag"); tag != "" {
				ev.Data["tag"] = tag
			}
		}
		registryAuth(&ev, r.Header.Get("X-Registry-Auth"))
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{"status": "Download complete"})

	case r.Method == http.MethodDelete:
		ev := rec.Event(r, "delete_request")
		ev.Data["image"] = strings.Join(seg, "/")
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, []any{})

	default:
		ev := rec.Event(r, "resource_access")
		ev.Data["image"] = strings.Join(seg, "/")
		registryAuth(&ev, r.Header.Get("X-Registry-Auth"))
		rec.Emit(ev)
		httpdecoy.WriteJSON(w, http.StatusOK, map[string]any{})
	}
}

// registryAuth decodes Docker's X-Registry-Auth header, which carries a
// registry username and password base64-encoded in the clear.
//
// This is a real credential, offered voluntarily, and it is usually the
// intruder's own — someone pulling their tooling from a private registry hands
// over the account it lives in. Four encodings are tried because Docker clients
// disagree about padding and alphabet, and a credential lost to a `=` would be
// a poor reason to miss it.
func registryAuth(ev *event.Event, header string) {
	if header == "" {
		return
	}

	var raw []byte
	for _, enc := range []*base64.Encoding{
		base64.URLEncoding, base64.RawURLEncoding,
		base64.StdEncoding, base64.RawStdEncoding,
	} {
		if decoded, err := enc.DecodeString(header); err == nil {
			raw = decoded
			break
		}
	}
	if raw == nil {
		// Undecodable, but still a presented credential.
		httpdecoy.Credential(ev, "registry_auth", header)
		return
	}

	var auth struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Email         string `json:"email"`
		ServerAddress string `json:"serveraddress"`
		IdentityToken string `json:"identitytoken"`
	}
	if err := json.Unmarshal(raw, &auth); err != nil {
		httpdecoy.Credential(ev, "registry_auth", string(raw))
		return
	}

	httpdecoy.Promote(ev, "login_basic")
	if auth.Username != "" {
		ev.Data["username"] = httpdecoy.Truncate(auth.Username, httpdecoy.FieldLimit)
	}
	if auth.Password != "" {
		ev.Data["password"] = httpdecoy.Truncate(auth.Password, httpdecoy.FieldLimit)
	}
	if auth.IdentityToken != "" {
		ev.Data["registry_token"] = httpdecoy.Truncate(auth.IdentityToken, httpdecoy.TokenLimit)
	}
	if auth.ServerAddress != "" {
		ev.Data["registry"] = httpdecoy.Truncate(auth.ServerAddress, httpdecoy.FieldLimit)
	}
	if auth.Email != "" {
		ev.Data["email"] = httpdecoy.Truncate(auth.Email, httpdecoy.FieldLimit)
	}
}

// hostPaths collects every host path the spec asks to mount, from both the old
// `Binds` list and the newer `Mounts` array.
func hostPaths(host map[string]any) []string {
	var out []string
	out = append(out, httpdecoy.StringsField(host, "Binds")...)

	if mounts, ok := host["Mounts"].([]any); ok {
		for _, raw := range mounts {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			source := httpdecoy.StringField(m, "Source", "source")
			target := httpdecoy.StringField(m, "Target", "target")
			if source == "" && target == "" {
				continue
			}
			out = append(out, source+":"+target)
		}
	}
	return out
}

// escapeReasons names the parts of a specification that would have handed over
// the host. Each is a thing an ordinary `docker run` never asks for.
func escapeReasons(binds []string, host map[string]any) []string {
	var reasons []string
	seen := map[string]bool{}
	add := func(r string) {
		if !seen[r] {
			seen[r] = true
			reasons = append(reasons, r)
		}
	}

	for _, bind := range binds {
		source, _, _ := strings.Cut(bind, ":")
		switch {
		case source == "/":
			add("host_filesystem")
		case strings.HasPrefix(source, "/var/run/docker.sock"), strings.HasSuffix(source, "docker.sock"):
			// A container holding the socket can create the next container.
			add("docker_socket")
		case source == "/etc", source == "/root", source == "/home",
			strings.HasPrefix(source, "/etc/"), strings.HasPrefix(source, "/root/"),
			strings.HasPrefix(source, "/proc"), strings.HasPrefix(source, "/sys"):
			add("host_path")
		}
	}

	if httpdecoy.BoolField(host, "Privileged") {
		add("privileged")
	}
	for key, reason := range map[string]string{
		"PidMode":     "host_pid",
		"NetworkMode": "host_network",
		"IpcMode":     "host_ipc",
	} {
		if strings.EqualFold(httpdecoy.StringField(host, key), "host") {
			add(reason)
		}
	}
	for _, c := range httpdecoy.StringsField(host, "CapAdd") {
		switch strings.ToUpper(c) {
		case "ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE":
			add("cap_" + strings.ToLower(c))
		}
	}

	return reasons
}

// stripAPIVersion removes the `/v1.43` prefix Docker clients put in front of
// every path. The daemon accepts requests with and without it, so a decoy that
// only understood one form would answer half the clients and 404 the rest.
func stripAPIVersion(path string) string {
	rest, ok := strings.CutPrefix(path, "/v")
	if !ok {
		return path
	}
	version, remainder, found := strings.Cut(rest, "/")
	if !found {
		return path
	}
	major, minor, ok := strings.Cut(version, ".")
	if !ok || !digits(major) || !digits(minor) {
		return path
	}
	return "/" + remainder
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func segments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// header sets what a daemon puts on every response. Scanners read these
// without looking at the body at all.
func (s *Service) header(w http.ResponseWriter) {
	w.Header().Set("Server", fmt.Sprintf("Docker/%s (linux)", s.version))
	w.Header().Set("Api-Version", s.apiVersion)
	w.Header().Set("Docker-Experimental", "false")
	w.Header().Set("Ostype", "linux")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}
