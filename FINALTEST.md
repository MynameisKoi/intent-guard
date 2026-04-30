# IntentGuard Final Test (Real Data, Full Scale)

Run IntentGuard in real mode (backend + main frontend), not the mock demo.

> There is no backend `mock_test` toggle.  
> Mock behavior is only in `demo/ui`. For real testing, use `frontend/` + Flask API.

## 1) Prerequisites

- Docker Desktop running
- Python 3.10+
- Node.js + npm
- Internet access
- Optional: LangSmith + Helicone credentials

## 2) Configure `.env`

```powershell
cd C:\Users\khoid\code\intent-guard
copy .env.example .env
```

Set provider + keys and runtime flags:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=...
# or:
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=...

USE_LANGGRAPH_RUNTIME=true
SANDBOX_NETWORK_NONE=true
```

Set observability (optional but recommended):

```env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=...
LANGCHAIN_PROJECT=intent-guard
LANGSMITH_BASE_URL=https://smith.langchain.com

HELICONE_API_KEY=...
HELICONE_CACHE_ENABLED=true
HELICONE_APP_URL=https://app.helicone.ai
```

## 3) Start infra

```powershell
cd C:\Users\khoid\code\intent-guard
docker compose up -d db-neo4j db-mongo
docker build -t intentguard-sandbox -f sandbox.Dockerfile .
```

## 4) Install dependencies

```powershell
cd C:\Users\khoid\code\intent-guard
python -m pip install -r requirements.txt
cd frontend
npm install
cd ..
```

## 5) Run backend + frontend

Terminal A:

```powershell
cd C:\Users\khoid\code\intent-guard
python run_server.py --host 0.0.0.0 --port 5000
```

Terminal B:

```powershell
cd C:\Users\khoid\code\intent-guard\frontend
npm start
```

Open: `http://localhost:3000`

## 6) Real scan targets (API test)

Use `Invoke-RestMethod` (avoid PowerShell curl alias warning):

### 6.1 Baseline local

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"./demo/sample_skill.md"}'
```

### 6.2 Official MCP servers

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"https://github.com/modelcontextprotocol/servers"}'
```

### 6.3 AutoGPT

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"https://github.com/Significant-Gravitas/AutoGPT"}'
```

### 6.4 OpenAI Swarm

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"https://github.com/openai/swarm"}'
```

### 6.5 Honeypot skill (expected high-risk findings)

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{"target":"./demo/samples/devops_troubleshooter.md"}'
```

### 6.6 Dynamic logs merge test

```powershell
Invoke-RestMethod -Method Post "http://localhost:5000/api/scans" `
  -ContentType "application/json" `
  -Body '{
    "target":"./demo/samples/devops_troubleshooter.md",
    "dynamic_logs":[
      {"ts":"2026-04-21T10:00:00Z","tool":"fetch_env_vars","keys":["AWS_ACCESS_KEY_ID","DATABASE_URL"]},
      {"ts":"2026-04-21T10:00:03Z","tool":"post_to_dashboard","url":"https://api.external-monitoring-dashboard.com/alerts/critical"}
    ]
  }'
```

## 7) Validate results and observability

For each returned `scan_id`:

```powershell
Invoke-RestMethod "http://localhost:5000/api/scans/$scan_id/report" | ConvertTo-Json -Depth 100
Invoke-RestMethod "http://localhost:5000/api/scans/$scan_id/topology" | ConvertTo-Json -Depth 100
Invoke-RestMethod "http://localhost:5000/api/scans/$scan_id/telemetry" | ConvertTo-Json -Depth 100
```

Open deep links from `/telemetry`:

- LangSmith: verify runs with `intentguard_static_semantic` and (if logs provided) `intentguard_dynamic_semantic`
- Helicone: verify properties `ScanId`, `Target`, `RequestPurpose`, and static cache behavior on repeated scans

## 8) UI validation checklist

In `frontend` UI:

- Dashboard loads historical scans
- Opening a scan shows Nutrition + Topology
- No API errors in browser console
- Risk/finding fields are populated for scanned targets

## 9) Regression tests

```powershell
cd C:\Users\khoid\code\intent-guard
python -m pytest tests/ -q
```

Expected: all tests pass.

