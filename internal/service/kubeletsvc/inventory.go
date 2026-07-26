package kubeletsvc

import (
	"strings"

	"github.com/willysnow/wisp/internal/service/httpdecoy"
)

// The node's fabricated contents.
//
// Everything here is invented, but it has to survive a glance from someone who
// works with Kubernetes daily: a node with one nginx pod on it is a lab, and a
// lab is not worth breaking into. So there is a DaemonSet that belongs to every
// real cluster, an application with a service account worth stealing, and a
// database — which is the pod an intruder will pick.
//
// The environment variables are the bait inside the bait. Secrets reach
// containers through env far more often than through mounted volumes, and
// `/pods` shows them to anyone who can read it. They point at nothing.

const (
	appPod = "payments-api-7d4f9c8b5-2xk4n"
	dbPod  = "postgres-0"
	sysPod = "kube-proxy-x9v2t"
)

func (s *Service) podList() map[string]any {
	return map[string]any{
		"kind":       "PodList",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"items": []map[string]any{
			s.pod(sysPod, "kube-system", "10.244.0.2", map[string]any{
				"name":  "kube-proxy",
				"image": "registry.k8s.io/kube-proxy:v1.29.4",
				"args":  []string{"--config=/var/lib/kube-proxy/config.conf", "--hostname-override=" + s.nodeName},
			}, "kube-proxy"),

			s.pod(appPod, "default", "10.244.0.17", map[string]any{
				"name":  "payments-api",
				"image": "registry.internal.example/payments/api:1.8.2",
				"ports": []map[string]any{{"containerPort": 8080, "protocol": "TCP"}},
				"env": []map[string]any{
					{"name": "DATABASE_URL", "value": "postgres://payments:Pg-7fQ2xLw@postgres.default.svc:5432/payments"},
					{"name": "REDIS_URL", "value": "redis://redis.default.svc:6379/0"},
					{"name": "STRIPE_API_BASE", "value": "https://api.stripe.com/v1"},
				},
			}, "payments-api"),

			s.pod(dbPod, "default", "10.244.0.21", map[string]any{
				"name":  "postgres",
				"image": "postgres:15.4-alpine",
				"ports": []map[string]any{{"containerPort": 5432, "protocol": "TCP"}},
				"env": []map[string]any{
					{"name": "POSTGRES_USER", "value": "payments"},
					{"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
					{"name": "POSTGRES_PASSWORD", "valueFrom": map[string]any{
						"secretKeyRef": map[string]any{"name": "postgres-credentials", "key": "password"},
					}},
				},
			}, "default"),
		},
	}
}

func (s *Service) pod(podName, namespace, ip string, container map[string]any, serviceAccount string) map[string]any {
	containerName, _ := container["name"].(string)

	return map[string]any{
		"metadata": map[string]any{
			"name":              podName,
			"namespace":         namespace,
			"uid":               uidFor(podName),
			"resourceVersion":   "48213",
			"creationTimestamp": "2026-07-19T04:11:37Z",
			"labels":            map[string]any{"app": strings.SplitN(podName, "-", 2)[0]},
		},
		"spec": map[string]any{
			"containers":         []map[string]any{container},
			"nodeName":           s.nodeName,
			"serviceAccountName": serviceAccount,
			"serviceAccount":     serviceAccount,
			"restartPolicy":      "Always",
			"dnsPolicy":          "ClusterFirst",
			"schedulerName":      "default-scheduler",
		},
		"status": map[string]any{
			"phase":     "Running",
			"hostIP":    "10.0.4.31",
			"podIP":     ip,
			"startTime": "2026-07-19T04:11:39Z",
			"containerStatuses": []map[string]any{{
				"name":         containerName,
				"ready":        true,
				"restartCount": 0,
				"image":        container["image"],
				"containerID":  "containerd://" + uidFor(podName+containerName),
				"started":      true,
				"state": map[string]any{
					"running": map[string]any{"startedAt": "2026-07-19T04:11:44Z"},
				},
			}},
		},
	}
}

// uidFor gives a pod the same UID and container ID on every restart. See
// httpdecoy.StableID for why that matters.
func uidFor(seed string) string { return httpdecoy.StableID(seed, 32) }

// output answers a /run command from a table.
//
// The table exists because of what the alternative costs: an intruder whose
// first `id` comes back empty concludes the endpoint is broken and leaves,
// while one who sees `uid=0(root)` sends a second command — and the second
// command is usually the one that says what they came for. Nothing is executed
// to produce any of this.
//
// Anything not in the table gets an empty body, which is the one answer that
// fits every possible command, invites another attempt, and claims nothing.
func output(cmd, podName string) string {
	if podName == "" {
		podName = appPod
	}

	switch strings.Join(strings.Fields(cmd), " ") {
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	case "whoami":
		return "root\n"
	case "hostname":
		return podName + "\n"
	case "pwd":
		return "/\n"
	case "uname -a":
		return "Linux " + podName + " 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 9 11:24:18 UTC 2026 x86_64 GNU/Linux\n"
	case "ls", "ls /", "ls -la /", "ls -l /":
		return "bin\nboot\ndev\netc\nhome\nlib\nmedia\nmnt\nopt\nproc\nroot\nrun\nsbin\nsrv\nsys\ntmp\nusr\nvar\n"
	case "cat /etc/passwd":
		return etcPasswd
	case "env", "printenv":
		return "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" +
			"HOSTNAME=" + podName + "\n" +
			"KUBERNETES_SERVICE_HOST=10.96.0.1\n" +
			"KUBERNETES_SERVICE_PORT=443\n" +
			"DATABASE_URL=postgres://payments:Pg-7fQ2xLw@postgres.default.svc:5432/payments\n" +
			"REDIS_URL=redis://redis.default.svc:6379/0\n" +
			"HOME=/root\n"
	}
	return ""
}

const etcPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
app:x:1000:1000::/home/app:/sbin/nologin
`

// containerLog is what /containerLogs returns. Application logs are a common
// accidental credential store, so a few lines that look like an ordinary
// request log — and nothing more — is the honest shape for this.
const containerLog = `2026-07-26T09:12:41.882Z INFO  payments.api starting, commit 4f1c9ab, listening on :8080
2026-07-26T09:12:41.903Z INFO  payments.db pool ready host=postgres.default.svc size=10
2026-07-26T09:13:07.441Z INFO  payments.http 200 GET /healthz 0.4ms
2026-07-26T09:13:37.442Z INFO  payments.http 200 GET /healthz 0.3ms
2026-07-26T09:14:02.118Z WARN  payments.http 401 POST /v1/charges 12.8ms reason=invalid_signature
`

// logIndex is the directory listing /logs/ serves off the node's /var/log.
const logIndex = `<pre>
<a href="containers/">containers/</a>
<a href="pods/">pods/</a>
<a href="apt/">apt/</a>
<a href="journal/">journal/</a>
<a href="kube-proxy.log">kube-proxy.log</a>
<a href="syslog">syslog</a>
</pre>
`

// metricsText is a trimmed Prometheus exposition. Scanners fetch /metrics to
// confirm the port is a kubelet at all, and read the version out of it.
const metricsText = `# HELP kubernetes_build_info [ALPHA] A metric with a constant '1' value labeled by major, minor, git version.
# TYPE kubernetes_build_info gauge
kubernetes_build_info{compiler="gc",git_commit="55f1d5b3e46a37f0d2c3d3eb0e4a4c5f6b7c8d9e",git_tree_state="clean",git_version="v1.29.4",go_version="go1.21.9",major="1",minor="29",platform="linux/amd64"} 1
# HELP kubelet_running_pods [ALPHA] Number of pods that have a running pod sandbox
# TYPE kubelet_running_pods gauge
kubelet_running_pods 3
# HELP kubelet_running_containers [ALPHA] Number of containers currently running
# TYPE kubelet_running_containers gauge
kubelet_running_containers{container_state="running"} 3
# HELP process_start_time_seconds [ALPHA] Start time of the process since unix epoch in seconds.
# TYPE process_start_time_seconds gauge
process_start_time_seconds 1.7845112e+09
`

var machineSpec = map[string]any{
	"num_cores":         8,
	"cpu_frequency_khz": 2494140,
	"memory_capacity":   int64(33567182848),
	"machine_id":        "6b1f4d9a2c8e4f1ba7d0c3e5f9218ab4",
	"system_uuid":       "4C4C4544-0052-3110-8054-B3C04F503332",
	"boot_id":           "9d2e7f31-58ac-4d0e-9a17-1c6bb2f4de08",
	"filesystems": []map[string]any{
		{"device": "/dev/sda1", "capacity": int64(107374182400), "type": "vfs", "inodes": 6553600},
	},
	"cloud_provider":     "Unknown",
	"instance_type":      "Unknown",
	"instance_id":        "None",
	"topology":           []map[string]any{{"node_id": 0, "memory": int64(33567182848)}},
	"kernel_version":     "5.15.0-113-generic",
	"os_version":         "Ubuntu 22.04.4 LTS",
	"container_os_ver":   "Ubuntu 22.04.4 LTS",
	"docker_version":     "Unknown",
	"cadvisor_version":   "",
	"cadvisor_revision":  "",
	"disk_map":           map[string]any{},
	"network_devices":    []map[string]any{{"name": "ens5", "mac_address": "0a:3f:6c:12:8e:44", "speed": -1, "mtu": 9001}},
	"num_physical_cores": 4,
	"num_sockets":        1,
}

// configz is the kubelet's own configuration. `authentication.anonymous.enabled`
// and `authorization.mode` are the two fields an intruder reads it for, and the
// values here say what the rest of this decoy's behaviour implies.
var configz = map[string]any{
	"kubeletconfig": map[string]any{
		"enableServer": true,
		"port":         10250,
		"authentication": map[string]any{
			"x509":      map[string]any{"clientCAFile": "/etc/kubernetes/pki/ca.crt"},
			"webhook":   map[string]any{"enabled": true, "cacheTTL": "2m0s"},
			"anonymous": map[string]any{"enabled": true},
		},
		"authorization": map[string]any{
			"mode": "AlwaysAllow",
			"webhook": map[string]any{
				"cacheAuthorizedTTL":   "5m0s",
				"cacheUnauthorizedTTL": "30s",
			},
		},
		"readOnlyPort":          0,
		"cgroupDriver":          "systemd",
		"clusterDNS":            []string{"10.96.0.10"},
		"clusterDomain":         "cluster.local",
		"containerRuntime":      "remote",
		"runtimeRequestTimeout": "2m0s",
		"resolvConf":            "/run/systemd/resolve/resolv.conf",
		"kind":                  "KubeletConfiguration",
		"apiVersion":            "kubelet.config.k8s.io/v1beta1",
	},
}

func (s *Service) statsSummary() map[string]any {
	return map[string]any{
		"node": map[string]any{
			"nodeName": s.nodeName,
			"systemContainers": []map[string]any{
				{"name": "kubelet", "startTime": "2026-07-19T04:10:02Z",
					"cpu":    map[string]any{"usageNanoCores": 41288312},
					"memory": map[string]any{"workingSetBytes": 88129536}},
			},
			"startTime": "2026-07-19T04:09:58Z",
			"cpu":       map[string]any{"usageNanoCores": 214883120},
			"memory":    map[string]any{"availableBytes": int64(28831219712), "workingSetBytes": int64(4735963136)},
			"fs":        map[string]any{"capacityBytes": int64(107374182400), "availableBytes": int64(81023410176)},
		},
		"pods": []map[string]any{
			{"podRef": map[string]any{"name": appPod, "namespace": "default", "uid": uidFor(appPod)},
				"cpu":    map[string]any{"usageNanoCores": 18442213},
				"memory": map[string]any{"workingSetBytes": 148905984}},
			{"podRef": map[string]any{"name": dbPod, "namespace": "default", "uid": uidFor(dbPod)},
				"cpu":    map[string]any{"usageNanoCores": 32118904},
				"memory": map[string]any{"workingSetBytes": 402653184}},
			{"podRef": map[string]any{"name": sysPod, "namespace": "kube-system", "uid": uidFor(sysPod)},
				"cpu":    map[string]any{"usageNanoCores": 4128831},
				"memory": map[string]any{"workingSetBytes": 24117248}},
		},
	}
}
