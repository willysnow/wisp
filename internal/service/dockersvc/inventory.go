package dockersvc

import (
	"strings"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// The daemon's fabricated contents.
//
// A host with no containers on it is a host nobody has bothered to use, and an
// intruder who finds one moves on. So this daemon runs an application, its
// database, a cache, and a CI runner — the shape of a small internal box that
// somebody exposed 2375 on because it was easier than configuring TLS.
//
// Nothing here exists. Identifiers are derived from names so they stay the same
// across restarts.

func idFor(seed string) string { return httpdecoy.StableID(seed, 64) }

func (s *Service) versionInfo() map[string]any {
	return map[string]any{
		"Platform":      map[string]any{"Name": "Docker Engine - Community"},
		"Version":       s.version,
		"ApiVersion":    s.apiVersion,
		"MinAPIVersion": "1.24",
		"GitCommit":     "311b9ff",
		"GoVersion":     "go1.21.9",
		"Os":            "linux",
		"Arch":          "amd64",
		"KernelVersion": "5.15.0-113-generic",
		"BuildTime":     "2026-03-12T10:44:07.000000000+00:00",
		"Components": []map[string]any{
			{"Name": "Engine", "Version": s.version, "Details": map[string]any{
				"ApiVersion": s.apiVersion, "Os": "linux", "Arch": "amd64",
				"GitCommit": "311b9ff", "GoVersion": "go1.21.9", "Experimental": "false",
			}},
			{"Name": "containerd", "Version": "1.7.13", "Details": map[string]any{"GitCommit": "7c3aca7a610df76212171d200ca3811ff6096eb8"}},
			{"Name": "runc", "Version": "1.1.12", "Details": map[string]any{"GitCommit": "v1.1.12-0-g51d5e94"}},
		},
	}
}

func (s *Service) info() map[string]any {
	return map[string]any{
		"ID":                 idFor("daemon"),
		"Containers":         4,
		"ContainersRunning":  4,
		"ContainersPaused":   0,
		"ContainersStopped":  0,
		"Images":             11,
		"Driver":             "overlay2",
		"MemoryLimit":        true,
		"SwapLimit":          true,
		"CpuCfsPeriod":       true,
		"KernelMemoryTCP":    true,
		"IPv4Forwarding":     true,
		"Debug":              false,
		"NFd":                42,
		"NGoroutines":        61,
		"LoggingDriver":      "json-file",
		"CgroupDriver":       "systemd",
		"CgroupVersion":      "2",
		"NEventsListener":    0,
		"KernelVersion":      "5.15.0-113-generic",
		"OperatingSystem":    "Ubuntu 22.04.4 LTS",
		"OSVersion":          "22.04",
		"OSType":             "linux",
		"Architecture":       "x86_64",
		"NCPU":               8,
		"MemTotal":           int64(33567182848),
		"DockerRootDir":      "/var/lib/docker",
		"Name":               "build-01",
		"ServerVersion":      s.version,
		"LiveRestoreEnabled": false,
		"SecurityOptions":    []string{"name=apparmor", "name=seccomp,profile=builtin"},
		"DefaultRuntime":     "runc",
		"Swarm":              map[string]any{"NodeID": "", "LocalNodeState": "inactive", "ControlAvailable": false},
		// A real daemon reports exactly this when it is listening in the clear.
		// Leaving it out would be the tell: the intruder already knows what
		// they connected to.
		"Warnings": []string{
			"WARNING: API is accessible on http://0.0.0.0:2375 without encryption.",
			"         Access to the remote API is equivalent to root access on the host. Refer",
			"         to the 'Docker daemon attack surface' section in the documentation for",
			"         more information: https://docs.docker.com/go/attack-surface/",
		},
	}
}

var containerList = []map[string]any{
	container("payments-api", "registry.internal.example/payments/api:1.8.2",
		"/app/serve --config /etc/payments/config.yaml", 8080, "10.0.4.31"),
	container("postgres", "postgres:15.4-alpine",
		"docker-entrypoint.sh postgres", 5432, "10.0.4.31"),
	container("redis", "redis:7.2-alpine",
		"docker-entrypoint.sh redis-server", 6379, "10.0.4.31"),
	container("gitlab-runner", "gitlab/gitlab-runner:v16.10.0",
		"/usr/bin/dumb-init /entrypoint run", 0, "10.0.4.31"),
}

func container(name, image, command string, port int, host string) map[string]any {
	ports := []map[string]any{}
	if port != 0 {
		ports = append(ports, map[string]any{
			"IP": host, "PrivatePort": port, "PublicPort": port, "Type": "tcp",
		})
	}

	return map[string]any{
		"Id":      idFor(name),
		"Names":   []string{"/" + name},
		"Image":   image,
		"ImageID": "sha256:" + idFor(image),
		"Command": command,
		"Created": 1784511240,
		"Ports":   ports,
		"Labels":  map[string]any{"com.docker.compose.service": name},
		"State":   "running",
		"Status":  "Up 7 days",
		"HostConfig": map[string]any{
			"NetworkMode": "internal_default",
		},
		"NetworkSettings": map[string]any{
			"Networks": map[string]any{
				"internal_default": map[string]any{
					"NetworkID": idFor("internal_default"),
					"IPAddress": "172.19.0." + string(rune('2'+len(name)%6)),
					"Gateway":   "172.19.0.1",
				},
			},
		},
		"Mounts": []map[string]any{},
	}
}

var imageList = []map[string]any{
	image("registry.internal.example/payments/api:1.8.2", 214883120),
	image("postgres:15.4-alpine", 247483904),
	image("redis:7.2-alpine", 41288312),
	image("gitlab/gitlab-runner:v16.10.0", 812340480),
	image("alpine:3.19", 7671808),
	image("ubuntu:22.04", 77835264),
}

func image(tag string, size int64) map[string]any {
	return map[string]any{
		"Id":          "sha256:" + idFor(tag),
		"ParentId":    "",
		"RepoTags":    []string{tag},
		"RepoDigests": []string{strings.SplitN(tag, ":", 2)[0] + "@sha256:" + idFor(tag+"digest")},
		"Created":     1782004247,
		"Size":        size,
		"SharedSize":  -1,
		"Containers":  -1,
		"Labels":      nil,
	}
}

// inspect answers /containers/{id}/json for anything asked about. The identity
// is derived from whatever id the client used, so a container the decoy
// "created" a moment ago inspects consistently.
func inspect(id string) map[string]any {
	return map[string]any{
		"Id":      id,
		"Created": "2026-07-19T04:11:39.281735Z",
		"Path":    "/bin/sh",
		"Args":    []string{},
		"State": map[string]any{
			"Status": "running", "Running": true, "Paused": false, "Restarting": false,
			"Pid": 4128, "ExitCode": 0, "StartedAt": "2026-07-19T04:11:39.402813Z",
		},
		"Image":           "sha256:" + idFor(id+"image"),
		"Name":            "/" + id[:min(12, len(id))],
		"RestartCount":    0,
		"Driver":          "overlay2",
		"Platform":        "linux",
		"HostConfig":      map[string]any{"NetworkMode": "internal_default", "Privileged": false},
		"Config":          map[string]any{"Hostname": id[:min(12, len(id))], "Image": "alpine:3.19", "Tty": false},
		"NetworkSettings": map[string]any{"IPAddress": "172.19.0.8", "Gateway": "172.19.0.1"},
	}
}

// secretList answers /secrets and /configs. The values are never returned by a
// real daemon either — only the names — but the names alone tell an intruder
// what the cluster holds, and asking for them says what they were after.
func secretList(kind string) []map[string]any {
	names := []string{"payments_db_password", "stripe_api_key", "registry_pull_token"}
	if kind == "configs" {
		names = []string{"payments_config", "nginx_conf"}
	}

	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{
			"ID":        idFor(n)[:25],
			"Version":   map[string]any{"Index": 214},
			"CreatedAt": "2026-02-11T08:31:04.118Z",
			"UpdatedAt": "2026-02-11T08:31:04.118Z",
			"Spec":      map[string]any{"Name": n, "Labels": map[string]any{}},
		})
	}
	return out
}

// inventoryFor answers the enumeration endpoints that do not deserve their own
// handler. Each returns the shape its client expects — an array or an object —
// because a client that fails to parse the answer stops asking questions.
func inventoryFor(resource string) any {
	switch resource {
	case "networks":
		return []map[string]any{
			{"Name": "bridge", "Id": idFor("bridge"), "Driver": "bridge", "Scope": "local"},
			{"Name": "host", "Id": idFor("host"), "Driver": "host", "Scope": "local"},
			{"Name": "internal_default", "Id": idFor("internal_default"), "Driver": "bridge", "Scope": "local"},
		}
	case "volumes":
		return map[string]any{
			"Volumes": []map[string]any{
				{"Name": "internal_pgdata", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/internal_pgdata/_data"},
				{"Name": "internal_redis", "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/internal_redis/_data"},
			},
			"Warnings": []string{},
		}
	case "swarm":
		// This daemon is not in a swarm, and says so the way a real one does.
		return map[string]any{"message": "This node is not a swarm manager. Use \"docker swarm init\" or \"docker swarm join\" to connect this node to swarm and try again."}
	case "nodes", "services", "tasks", "plugins":
		return []any{}
	default:
		return map[string]any{}
	}
}
