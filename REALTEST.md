# IntentGuard QA Test Flow (Replicable)

This runbook validates static analysis, dynamic log merge, graph persistence, and observability links (LangSmith + Helicone) against real-world targets.

## 0) Prerequisites

- Docker Desktop running
- Python 3.10+
- Node.js (for demo UI if needed)
- Optional but recommended for observability:
  - `LANGCHAIN_TRACING_V2=true`
  - `LANGCHAIN_API_KEY=...`
  - `LANGCHAIN_PROJECT=intent-guard`
  - `HELICONE_API_KEY=...`

Copy env and install dependencies:

```powershell
copy .env.example .env
python -m pip install -r requirements.txt
```

Start databases and sandbox image:

```powershell
docker compose up -d db-neo4j db-mongo
docker build -t intentguard-sandbox -f sandbox.Dockerfile .
```

Start API:

```powershell
python run_server.py --host 0.0.0.0 --port 5000
```

## 1) Baseline sanity checks

### 1.1 Create a local scan

```powershell
curl -Method POST "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"./demo/sample_skill.md"}'
```

Expected:
- `status: completed`
- response includes `scan_id`, `report`, and `topology`

### 1.2 Retrieve report + topology

```powershell
curl "http://localhost:5000/api/scans"
curl "http://localhost:5000/api/scans/{scan_id}/report"
curl "http://localhost:5000/api/scans/{scan_id}/topology"
```

Expected:
- list endpoint includes the new scan
- report includes risk summary and findings
- topology has non-empty node list for code-bearing targets

## 2) Real-world repository tests

## 2.1 Official MCP servers (tool parsing quality)

Target:
- `https://github.com/modelcontextprotocol/servers`

```powershell
curl -Method POST "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"https://github.com/modelcontextprotocol/servers"}'
```

Validate:
- scan completes
- report has intent summary and category scores
- topology endpoint returns graph data
- findings may include scope/privilege observations for broad filesystem-style tools

## 2.2 AutoGPT (large graph / risky surfaces)

Target:
- `https://github.com/Significant-Gravitas/AutoGPT`

Run scan as above. Validate:
- scan completes without crashing tracer
- topology includes many function/file nodes
- findings likely mention subprocess/network surfaces

## 2.3 OpenAI Swarm (handoff/coordination patterns)

Target:
- `https://github.com/openai/swarm`

Validate:
- multi-agent orchestration code is parsed into graph relationships
- report remains coherent and not empty

## 3) Honeypot skill test (semantic + OWASP expectations)

Target file:
- `./demo/samples/devops_troubleshooter.md`

```powershell
curl -Method POST "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"./demo/samples/devops_troubleshooter.md"}'
```

Expected behavior:
- Data exfiltration-like risk elevated
- findings should reference environment secret collection + external post target
- OWASP-style mapping should include exfiltration/privilege concerns

## 4) Dynamic log merge test (runtime drift)

Use the same honeypot target but include runtime log payload:

```powershell
curl -Method POST "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{
    "target":"./demo/samples/devops_troubleshooter.md",
    "dynamic_logs":[
      {"ts":"2026-04-21T10:00:00Z","tool":"read_system_logs","path":"/var/log/auth.log"},
      {"ts":"2026-04-21T10:00:01Z","tool":"fetch_env_vars","keys":["AWS_ACCESS_KEY_ID","DATABASE_URL"]},
      {"ts":"2026-04-21T10:00:02Z","tool":"post_to_dashboard","url":"https://api.external-monitoring-dashboard.com/alerts/critical"}
    ]
  }'
```

Expected:
- report meta contains `dynamic_logs_included=true`
- semantic findings reflect runtime behavior in addition to static hints

## 5) Observability deep links (LangSmith + Helicone)

For any completed scan:

```powershell
curl "http://localhost:5000/api/scans/{scan_id}/telemetry"
```

Endpoint returns:
- `langsmith.deep_link` filtered by `metadata.scan_id`
- `helicone.deep_link` filtered by `Helicone-Property-ScanId`

Validation checklist:
- If LangSmith is enabled, open link and confirm traces for:
  - `intentguard_static_semantic`
  - `intentguard_dynamic_semantic` (when dynamic logs provided)
- If Helicone is enabled, open link and confirm:
  - request properties include `ScanId`, `Target`, and request purpose (`static` / `dynamic`)
  - cache behavior visible on repeated static scans

## 6) Cache behavior spot-check (Helicone)

Run the same static scan twice:

```powershell
curl -Method POST "http://localhost:5000/api/scans" -ContentType "application/json" -Body '{"target":"./demo/sample_skill.md"}'
curl -Method POST "http://localhost:5000/api/scans" -ContentType "application/json" -Body '{"target":"./demo/sample_skill.md"}'
```

In Helicone:
- first run should be cache miss (usually)
- repeated static request may show cache hit depending on provider/model request equivalence

## 7) Safety checks for third-party repos

Because `SANDBOX_NETWORK_NONE=true` by default:
- sandbox dry-run should not have open network egress
- scan should still complete and include sandbox status in report metadata

To verify, inspect `/report` response:
- `report.meta.sandbox` present
- no fatal failure from sandbox step

## 8) Regression checks

Run unit tests:

```powershell
python -m pytest tests/ -q
```

Expected: all tests pass.

---

## Quick pass/fail matrix

- [ ] API starts and responds on `/api/scans`
- [ ] Local sample scan completes
- [ ] MCP servers repo scan completes
- [ ] AutoGPT repo scan completes without tracer crash
- [ ] Swarm repo scan completes
- [ ] Honeypot skill yields high-risk findings
- [ ] Dynamic log merge path works and marks `dynamic_logs_included`
- [ ] `/api/scans/{id}/telemetry` returns both deep links
- [ ] LangSmith trace(s) visible (if enabled)
- [ ] Helicone requests + properties visible (if enabled)
- [ ] Test suite passes

