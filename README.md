# IntentGuard

> Agentic AI reverse engineering and semantic intent security platform

IntentGuard is a multi-agent security framework designed to perform automated static inspection and reverse engineering on agentic AI skills, repositories, and Model Context Protocol (MCP) tool definitions. By orchestrating deterministic Abstract Syntax Tree (AST) tracing with LLM-driven semantic analysis, it bridges the gap between raw code and human understanding — exposing the true intent of AI agents for both technical and non-technical users.

---

## Table of contents

- [Architecture](#architecture)
- [Vulnerability coverage](#vulnerability-coverage)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running](#running)
- [Project structure](#project-structure)
- [API endpoints](#api-endpoints)
- [Environment variables](#environment-variables)
- [License](#license)

---

## Architecture

```text
                    ┌─────────────────────────────────────┐
                    │       IntentGuard Orchestrator      │
                    │   (Pipeline & Risk Scoring Core)    │
                    └────────────┬────────────────────────┘
                                 │
           ┌─────────────────────┴──────────────────────┐
           │  STATIC TRACK                              │  DYNAMIC TRACK
           ▼                                             ▼
AST & Dataflow Tracer                          Adversarial Simulator
· Parses .md/Python/JSON/manifests             · Replays 8 attack scenarios
· Builds deterministic syntax tree             · Mock tools, honeytoken environment
· Maps data origins to destinations            · Records attempted tool arguments
· Pushes topology to Neo4j graph               · Compares declared vs actual behaviour

Semantic Intent Analyzer
· LLM reads Neo4j graph data
· Deduces combined behavioral intent
  (e.g., benign read + external tool call)

OWASP Mapper
· Classifies semantic findings against
  OWASP Agentic Top 10 standard taxonomy
```

### Data flow

```text
Target Input (GitHub Repo URL / .md Skill File)
  → Ingestion Agent         →  Normalized workspace representation
  → AST & Dataflow Tracer   →  Graph nodes/edges injected into Neo4j
  → Semantic Analyzer       →  Intent descriptions and confidence scores
  → OWASP Mapper            →  Standardized vulnerability classifications
  → Adversarial Simulator   →  Observed tool calls, canary leaks, guardrail gaps
  → Risk Orchestrator       →  Aggregated Risk Score + JSON "Nutrition Label"
  → Flask API + React UI    →  Visual Graph Topology & Non-Tech Summary Views
```

### Semantic intent analysis — how it works

Because traditional antivirus relies on static signatures, it fails against dynamic, prompt-driven AI skills. IntentGuard uses **semantic reverse engineering** as its primary detection mechanism:

1. `trace_dataflow()` — The AST Tracer deterministically maps the flow of data. If an agent reads a local system file and later passes that variable to an LLM prompt which triggers an external `requests.post()`, this path is mapped in Neo4j.

2. `evaluate_intent()` — The LLM core is fed this specific path. It is asked to determine the combined goal of these operations. Instead of flagging syntax, it flags the *behavior* (e.g., "Unauthorized Data Exfiltration").

3. `map_to_taxonomy()` — The finding is tagged with an OWASP Agentic Top 10 label and routed to the UI. The frontend visualizes this exact path in the Graph Topology view, allowing developers to see the exact chain of events.

---

## Vulnerability coverage

| Type | Detection method |
| :--- | :--- |
| Prompt injection (direct) | Semantic Analyzer + injection detector |
| Prompt injection (indirect) | Adversarial Simulator — 3 scenarios |
| Unauthorized tool usage | AST Tracer + Simulator declared-vs-actual delta |
| Data exfiltration | Graph Topology Dataflow + LLM + honeytoken canaries |
| Excessive agency / destructive actions | Adversarial Simulator — 3 scenarios |
| Goal hijacking and jailbreaks | Adversarial Simulator — 2 multi-turn scenarios |
| Hardcoded credentials | Secret redaction pass |
| Insecure output handling | Semantic Analyzer |
| Supply chain / malicious `.md` | Ingestion Agent + AST Tracer |
| Over-privileged agent scope | Static Parsing + Semantic Analyzer |

---

## Prerequisites

- [Python 3.10+](https://www.python.org/)
- [Docker](https://www.docker.com/) — for Neo4j, MongoDB, and the execution sandbox
- [Node.js 18+](https://nodejs.org/) — for the React frontend
- An LLM API key from **one** provider: OpenAI (`OPENAI_API_KEY`) or Anthropic Claude (`ANTHROPIC_API_KEY`), selected with `LLM_PROVIDER` (see [Environment variables](#environment-variables))

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/your-org/intent-guard
cd intent-guard

# 2. Install backend dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env — set LLM_PROVIDER and the matching API key (OpenAI or Anthropic),
# plus database URIs (see Environment Variables below)

# 4. Start Neo4j and MongoDB
docker-compose up -d db-neo4j db-mongo

# 5. Build the Sandbox Docker image
docker build -t intentguard-sandbox -f sandbox.Dockerfile .
```

---

## Running

### Backend (Flask API)

```bash
python run_server.py --port 5000
```

The API binds `127.0.0.1` by default. It has no authentication and every scan spends
LLM credits and clones untrusted repositories, so only pass `--host 0.0.0.0` behind an
authenticating proxy, and set `API_CORS_ORIGINS` accordingly.

### Frontend (React / Tailwind)

```bash
cd frontend
npm install
npm start
# → http://localhost:3000
```

The frontend proxies `/api/*` to `http://localhost:5000`.

### Demo (mock dashboard)

The repository includes a **static preview** of the IntentGuard UI (no API keys or databases). The demo app starts with an **interactive mock pipeline** (ingestion → AST → Neo4j → LLM → MongoDB → UI) that emits a fake Scan ID and then loads the mock dashboard. See [`demo/README.md`](demo/README.md): `npm install && npm run dev` in `demo/ui`, and `npm test` for Vitest coverage of the mock pipeline.

### CLI (no frontend)

```bash
# Scan a public GitHub repository
python main.py scan https://github.com/user/agent-repo

# Scan a local skill file
python main.py scan ./skills/research_agent.md

# Quick smoke scan using bundled demo samples (see demo/README.md)
python main.py scan ./demo/sample_skill.md
```

---

## Project structure

```text
intent-guard/
├── .env.example               # Sample configuration (copy to .env; never commit secrets)
├── LICENSE
├── README.md
├── requirements.txt           # Python dependencies (Flask, drivers, OpenAI & Anthropic SDKs)
├── docker-compose.yml         # Neo4j, MongoDB, and optional local service wiring
├── sandbox.Dockerfile         # Image built as intentguard-sandbox for dynamic analysis
├── run_server.py              # Flask API entry point (`python run_server.py …`)
├── main.py                    # CLI entry point (`python main.py scan …`)
├── config.py                  # Settings, .env loader, LLM provider selection
│
├── api/                       # Flask application package
│   ├── __init__.py
│   ├── app.py                 # Application factory / extensions
│   └── routes.py              # REST endpoints (`/api/scans`, …)
│
├── engine/                    # Core analysis pipeline
│   ├── __init__.py
│   ├── orchestrator.py        # Pipeline coordinator and risk aggregation
│   ├── agents/
│   │   ├── ingestion.py       # Input normalization (repo URL, skill files, MCP JSON)
│   │   ├── ast_tracer.py      # Deterministic parsing and graph construction
│   │   ├── semantic.py        # LLM intent analysis (uses engine/llm clients)
│   │   ├── owasp.py           # OWASP Agentic Top 10 mapping
│   │   └── sandbox.py         # Dynamic dry-run execution in Docker
│   ├── database/
│   │   ├── neo4j_client.py    # Graph read/write for topology
│   │   └── mongo_client.py    # Persisted scan reports and metadata
│   ├── agent_runtime/         # LangGraph scan pipeline + LangSmith tracing hooks
│   │   ├── tracing.py         # LANGCHAIN_* / LangSmith env wiring
│   │   ├── langchain_llm.py   # ChatOpenAI / ChatAnthropic via Helicone when configured
│   │   └── scan_graph.py      # Static semantic node (cache-friendly) → optional dynamic log merge
│   └── llm/                   # Chat completions: OpenAI and Anthropic Claude
│       ├── __init__.py
│       ├── base.py            # Shared protocol / response normalization
│       ├── helicone.py        # Helicone-Auth / cache / property headers
│       ├── openai_client.py   # OpenAI-compatible chat API
│       └── anthropic_client.py # Messages API (Claude)
│
├── prompts/                   # Prompt templates for the Semantic Engine
│   └── intent_analysis.md
│
├── schemas/                   # Pydantic (or similar) models shared across API and engine
│   ├── graph_nodes.py
│   └── report_schema.py       # "Nutrition Label" JSON shape
│
├── tests/                     # pytest: unit and integration tests
│   ├── conftest.py
│   └── test_orchestrator.py
│
├── demo/                      # Bundled samples + interactive UI preview (no backend required)
│   ├── README.md              # How to run the mock dashboard and where mock data lives
│   ├── mock/scan-preview.json # Shared JSON model for the demo UI (risk, graph, OWASP, code)
│   ├── sample_skill.md        # Tiny agent skill file for future `main.py scan` smoke tests
│   ├── sample_mcp_tools.json  # Example MCP-style tool definitions for ingestion tests
│   ├── samples/               # Example `.py` / `.md` snippets aligned with the UI storyboard
│   └── ui/                    # Vite + React + Tailwind demo app (`npm install && npm run dev`)
│
└── frontend/                  # React + Tailwind dashboard
    ├── package.json
    ├── public/
    │   └── index.html
    ├── tailwind.config.js
    └── src/
        ├── App.jsx
        ├── index.js
        ├── setupProxy.js      # Dev-only: proxy /api → Flask (localhost:5000)
        ├── components/
        │   ├── NutritionLabel.jsx   # Non-technical summary view
        │   └── TopologyGraph.jsx    # Cytoscape / D3 graph view
        ├── pages/
        │   ├── Dashboard.jsx
        │   └── ScanDetails.jsx
        └── utils/
            └── api.js           # fetch helpers for `/api/*`
```

---

## API endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scans` | Submit a target. JSON `target` must be a public GitHub URL; use a multipart upload to scan local content. Body may include optional `dynamic_logs` (string or JSON) for LangGraph dynamic merge after static analysis |
| `GET` | `/api/scans` | List historical scan reports |
| `GET` | `/api/scans/{id}/report` | Retrieve the structured JSON "Nutrition Label" |
| `GET` | `/api/scans/{id}/topology` | Retrieve the Neo4j node/edge data for frontend visualization |
| `GET` | `/api/scans/{id}/telemetry` | Return ready-made LangSmith / Helicone deep-link URLs for this scan (based on scan metadata) |

---

## Environment variables

IntentGuard’s Semantic Intent Analyzer talks to **either** the OpenAI API **or** the [Anthropic Messages API](https://docs.anthropic.com/en/api/messages) (Claude). Set `LLM_PROVIDER` to choose which client `config.py` / `engine/llm` loads, and provide the matching secret.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `LLM_PROVIDER` | `openai` | `openai` or `anthropic` — which vendor backs semantic analysis |
| `OPENAI_API_KEY` | — | Required when `LLM_PROVIDER=openai` |
| `ANTHROPIC_API_KEY` | — | Required when `LLM_PROVIDER=anthropic` |
| `LLM_MODEL` | *(provider default)* | Chat model id for the active provider (e.g. OpenAI `gpt-4o`, Anthropic `claude-sonnet-4-20250514`) |
| `NEO4J_URI` | `bolt://localhost:7687` | Connection string for the graph database |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `password` | Neo4j password |
| `MONGO_URI` | `mongodb://localhost:27017` | Connection string for the document database |
| `SANDBOX_IMAGE` | `intentguard-sandbox` | Docker image name for dynamic analysis |
| `SANDBOX_TIMEOUT` | `45` | Execution timeout for the dry-run in seconds |
| `SANDBOX_NETWORK_NONE` | `true` | Adds `--network none` to sandbox dry-runs (recommended for untrusted third-party agent repos) |
| `DYNAMIC_ANALYSIS` | `true` | Run the adversarial simulation track |
| `DYNAMIC_DRIVER` | `scripted` | `scripted` reports capability and missing guardrails for free; `llm` runs the agent's own prompt against each attack and reports what it actually did (one call per scenario) |
| `DYNAMIC_MAX_TURNS` | `6` | Conversation turns per scenario for the `llm` driver |
| `SCAN_EXCLUDE_DIRS` | *(see `config.py`)* | Comma-separated directory names pruned before analysis (`.git`, `node_modules`, `__pycache__`, `dist`, …) |
| `SCAN_EXCLUDE_GLOBS` | *(see `config.py`)* | Comma-separated filename globs skipped (lockfiles, minified bundles, source maps) |
| `SCAN_FIXTURE_DIRS` | `demo,samples,examples,fixtures,mocks,…` | Directories treated as fixtures: analyzed and reported, excluded from the aggregate score |
| `SCAN_MAX_FILE_BYTES` | `512000` | Skip files larger than this (generated data inflates the bundle without adding intent) |
| `API_CORS_ORIGINS` | local `3000`/`5173` origins | Comma-separated origins allowed to call `/api/*` |
| `MAX_UPLOAD_BYTES` | `25000000` | Request body limit; larger uploads get a JSON `413` |
| `MAX_UPLOAD_FILES` | `500` | Maximum files accepted in one folder upload |
| `SCORE_FIXTURES_IN_AGGREGATE` | `false` | Set `true` to let fixture and documentation files raise the aggregate risk score |
| `HEURISTIC_MAX_SCORE` | `7.0` | Ceiling when no LLM verdict is available, so regex-only fallbacks never report Critical |
| `LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `MONGO_DB` | `intentguard` | MongoDB database name for scan documents |
| `LANGCHAIN_TRACING_V2` | `false` | Set `true` to send LangGraph / LangChain traces to [LangSmith](https://smith.langchain.com/) |
| `LANGCHAIN_API_KEY` | — | LangSmith API key (required when tracing is enabled) |
| `LANGCHAIN_PROJECT` | `intent-guard` | LangSmith project name |
| `LANGSMITH_BASE_URL` | `https://smith.langchain.com` | Base URL for LangSmith deep-link generation |
| `HELICONE_API_KEY` | — | Optional [Helicone](https://docs.helicone.ai/) key; when set, OpenAI/Anthropic SDKs and LangGraph LLM steps use the Helicone gateway |
| `HELICONE_CACHE_ENABLED` | `true` | When using Helicone, enable response caching (strongest on identical static prompts) |
| `HELICONE_APP_URL` | `https://us.helicone.ai` | Base URL for Helicone deep-link generation (use `https://eu.helicone.ai` on the EU region) |
| `USE_LANGGRAPH_RUNTIME` | `true` | Use LangGraph for semantic analysis (static pass + optional dynamic log node); set `false` to force the legacy single-call path |

---

## Real-world test targets

Suggested scan targets to stress the parser and semantic mapper:

- `https://github.com/modelcontextprotocol/servers`
- `https://github.com/Significant-Gravitas/AutoGPT`
- `https://github.com/openai/swarm`
- `./demo/samples/devops_troubleshooter.md` (intentional exfiltration-like honeypot)

If you want dynamic behavior checks, post a `dynamic_logs` payload with `POST /api/scans`:

```json
{
  "target": "./demo/samples/devops_troubleshooter.md",
  "dynamic_logs": [
    {"ts":"2026-04-21T10:00:00Z","tool":"fetch_env_vars","keys":["AWS_ACCESS_KEY_ID","DATABASE_URL"]},
    {"ts":"2026-04-21T10:00:03Z","tool":"post_to_dashboard","url":"https://api.external-monitoring-dashboard.com/alerts/critical"}
  ]
}
```

With `LANGCHAIN_TRACING_V2=true`, these semantic calls are traceable in LangSmith.
With `HELICONE_API_KEY` set, LLM traffic flows through the Helicone gateway with scan metadata (`Helicone-Property-ScanId`, `Helicone-Property-Target`) and static-cache properties.

---

## License

MIT
