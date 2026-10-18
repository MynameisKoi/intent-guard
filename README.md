# IntentGuard

> Agentic AI reverse engineering, model integrity, and semantic intent security platform

IntentGuard is a multi-agent security framework designed to perform automated static inspection, binary reverse engineering, and semantic intent analysis on agentic AI skills, repositories, Hugging Face model cards, model weights (GGUF, SafeTensors, PyTorch pickle), and Model Context Protocol (MCP) tool definitions. By orchestrating deterministic AST tracing, pure-Python binary & weight parsing, [REA (morluto/rea)](https://github.com/morluto/rea) reverse-engineering, and LLM-driven semantic analysis (via OpenRouter, OpenAI, or Anthropic), it exposes the true intent of AI agents and models for both technical and non-technical users.

---

## Table of contents

- [Architecture](#architecture)
- [Vulnerability coverage](#vulnerability-coverage)
- [Hugging Face & Model Weight Auditing](#hugging-face--model-weight-auditing)
- [REA Binary Reverse Engineering](#rea-binary-reverse-engineering)
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
           ┌─────────────────────┼──────────────────────┐
           │                     │                      │
           ▼                     ▼                      ▼
  STATIC & CODE TRACK    ARTIFACT & BINARY TRACK   DYNAMIC TRACK
AST & Dataflow Tracer   Binary & Weight Engines   Adversarial Simulator
· Parses .md/Python/    · GGUF & SafeTensors      · Replays 8 attack scenarios
  JSON/manifests          structural inspection   · Mock tools, honeytokens
· Builds deterministic  · Jinja SSTI detector     · Compares declared vs
  syntax tree           · Pickle opcode analysis    actual behaviour
· Maps data origins     · REA reverse engineering
  to destinations         for .exe/ELF/ASAR/WASM
· Pushes topology to    · HTTP Range streaming
  Neo4j graph             (no multi-GB downloads)
           │                     │                      │
           └─────────────────────┼──────────────────────┘
                                 ▼
                     Semantic Intent Analyzer
                     · OpenRouter (deepseek-v4.1-flash / Claude / GPT)
                     · Ingests AST graph + decompilation + weight evidence
                     · Deduces combined behavioral intent
                                 ▼
                           OWASP Mapper
                     · Standardizes findings to OWASP Agentic Top 10
                     · Aggregates risk score + Nutrition Label JSON
```

### Data flow

```text
Target Input (GitHub Repo / HF Model `hf:org/repo` / GGUF Weight / Binary .exe / .md Skill)
  → Ingestion Agent         →  Normalized workspace or HF metadata / streamed range headers
  → AST & Artifact Runner   →  Code dataflow + GGUF/weight integrity + REA decompilation
  → Semantic Analyzer       →  OpenRouter LLM synthesizes evidence & scores true intent
  → OWASP Mapper            →  Standardized vulnerability classifications
  → Adversarial Simulator   →  Observed tool calls, canary leaks, guardrail gaps
  → Risk Orchestrator       →  Aggregated Risk Score + JSON "Nutrition Label"
  → Flask API + React UI    →  Visual Graph Topology & Non-Tech Summary Views
```

### Semantic intent analysis — how it works

Because traditional antivirus relies on static signatures, it fails against dynamic, prompt-driven AI skills and anomalous model weights. IntentGuard uses **semantic reverse engineering** as its primary detection mechanism:

1. `trace_dataflow()` & `run_artifacts_for_workspace()` — The AST Tracer maps code dataflow in Neo4j, while the Artifact Runner validates model weight headers (GGUF, SafeTensors), disassembles PyTorch pickle opcodes without unpickling, inspects tokenizer Jinja templates, and uses REA to decompile binaries.
2. `evaluate_intent()` — The LLM core (e.g. `deepseek/deepseek-v4.1-flash` via OpenRouter) is fed the combined path, decompilation, and metadata. Instead of flagging syntax alone, it deduces the holistic intent (e.g., "Backdoored Chat Template with Data Exfiltration").
3. `map_to_taxonomy()` — Findings are mapped to the OWASP Agentic Top 10 and displayed in the Graph Topology and Nutrition Label views.

---

## Vulnerability coverage

| Type | Detection method |
| :--- | :--- |
| **GGUF weight tampering & anomalous scales** | Pure-Python GGUF parser — validates version, tensor boundaries, overlaps, misalignment, trailing unreferenced bytes, and fp16 quantization scale anomalies (NaN/Inf) |
| **Model card supply chain & typosquatting** | Hugging Face Hub inspector — compares repo against official namespaces (`openai`, `meta-llama`, `deepseek-ai`, etc.) and flags `trust_remote_code` hooks |
| **Chat template injection / Jinja SSTI** | AST Jinja tokenizer scanner — flags CVE-2024-34359 SSTI vectors and hidden system prompt overrides |
| **PyTorch arbitrary code execution** | Pickle opcode disassembler — scans `.bin`/`.pt`/`.pth` opcodes without executing unpickling payloads |
| **Binary executables & native malware** | REA ([morluto/rea](https://github.com/morluto/rea)) decompilation + static binary triage (entropy, packer detection, C2, injection APIs) |
| **Prompt injection (direct & indirect)** | Semantic Analyzer + Adversarial Simulator (3 scenarios) |
| **Unauthorized tool usage** | AST Tracer + Simulator declared-vs-actual delta |
| **Data exfiltration** | Graph Topology Dataflow + LLM + honeytoken canaries |
| **Excessive agency / destructive actions** | Adversarial Simulator — 3 scenarios |
| **Goal hijacking and jailbreaks** | Adversarial Simulator — 2 multi-turn scenarios |
| **Hardcoded credentials** | Secret redaction pass |
| **Supply chain / malicious `.md`** | Ingestion Agent + AST Tracer |

---

---

## Hugging Face & Model Weight Auditing

IntentGuard provides deep static inspection for Hugging Face model repositories and standalone model weights:

- **Target formats supported**:
  - `hf:org/repo` (or `https://huggingface.co/org/repo`)
  - Direct weight files: `.gguf`, `.safetensors`, `.bin`, `.pt`, `.pth`, `.onnx`
- **Zero-Download HTTP Range Streaming**:
  - Hugging Face models often reach 10GB–70GB+. IntentGuard queries the Hugging Face Hub API for repo metadata and uses HTTP Range requests (`engine/artifacts/byte_source.py`) to stream only the first few megabytes containing headers, metadata key-values, and tensor offsets. It never downloads the entire multi-gigabyte weight payload.
- **Pure-Python GGUF Parser (`engine/artifacts/gguf.py`)**:
  - Validates GGUF magic bytes (`GGUF`), versions (v1, v2, v3), metadata key count, and tensor count.
  - Checks for duplicate keys, out-of-bounds tensor offsets, overlapping tensor memory buffers, and alignment padding issues.
  - Identifies **unreferenced trailing overlays** (hidden backdoor shellcode or payloads appended past the declared tensor buffers).
  - Samples fp16/fp32 quantization scales and biases across tensor headers to flag corrupted or adversarial `NaN` / `+Inf` / `-Inf` scale factors that cause denial of service or deliberate degradation.
- **Chat Template Injection & Jinja SSTI (`engine/artifacts/chat_template.py`)**:
  - Inspects `tokenizer_config.json` and custom Jinja templates for Server-Side Template Injection (CVE-2024-34359).
  - Scans for dangerous Jinja expressions (`__class__`, `__mro__`, `__subclasses__`, `os.system`, `subprocess`) and hidden prompt injection/jailbreak instructions baked into model chat templates.
- **SafeTensors Validation (`engine/artifacts/safetensors.py`)**:
  - Validates 8-byte header size limits, JSON metadata schema, offset continuity, shape dimensions, and trailing junk data.
- **PyTorch Pickle Disassembly (`engine/artifacts/pickle_scan.py`)**:
  - Pure-Python opcode parser using Python's `pickletools.genops` without executing `pickle.load()`.
  - Flags dangerous opcodes (`GLOBAL`, `REDUCE`, `BUILD`, `INST`, `OBJ`) resolving to code execution symbols (`posix.system`, `subprocess.Popen`, `os.system`, `exec`, `eval`).
- **Typosquatting & Supply-Chain Checks (`engine/artifacts/huggingface.py`)**:
  - Flags model repos with names suspiciously close (Levenshtein distance <= 2) to official organizations (such as `openai`, `meta-llama`, `deepseek-ai`, `mistralai`, `google`, `anthropic`).
  - Flags `trust_remote_code=true` requirements and checks for custom executable modules (`modeling_*.py`, `configuration_*.py`) included in the repo.

---

## REA Binary Reverse Engineering

For native executables (`.exe`, ELF, Mach-O), Electron packages (`.asar`), WebAssembly (`.wasm`), and Go/Rust/Managed binaries, IntentGuard integrates [REA (morluto/rea)](https://github.com/morluto/rea):

- **Auto-Discovery**:
  - Looks for a local `rea` binary in `$PATH` or invokes `npx -y rea-agents@latest`.
  - Configurable via `REA_COMMAND=auto` (or `REA_COMMAND=off` to disable).
- **Subcommand Mapping**:
  - Go binaries → `rea inspect-go-binary`
  - Rust binaries → `rea inspect-rust-binary`
  - .NET / JVM / Managed → `rea inspect-managed-*`
  - Electron apps → `rea analyze-javascript-application`
  - Generic binaries / PE / ELF / Mach-O → `rea inspect-artifact`
- **Fallback Pure-Python Static Triage (`engine/artifacts/binary_triage.py`)**:
  - Computes Shannon entropy (flags packed/encrypted payloads with entropy > 7.2).
  - Detects known packers (UPX, PECompact, ASPack, Enigma).
  - Extracts embedded URLs, IPs, onion addresses, and suspicious API imports (Process Injection, Memory Manipulation, Token Impersonation, Credential Theft, Persistence, C2).
- **LLM Evidence Synthesis**:
  - Findings, decompiled symbols, and triage summaries are formatted into markdown evidence blocks and passed directly to the OpenRouter model for semantic intent analysis.

---

## Prerequisites

- [Python 3.10+](https://www.python.org/)
- [Docker](https://www.docker.com/) — for Neo4j, MongoDB, and the execution sandbox
- [Node.js 18+](https://nodejs.org/) — for the React frontend and `rea` CLI / `npx rea-agents`
- An LLM API key:
  - **OpenRouter** (recommended, configured with `deepseek/deepseek-v4.1-flash`, `anthropic/claude-sonnet-5.5`, or `openai/gpt-5.5`)
  - **OpenAI** (`OPENAI_API_KEY`)
  - **Anthropic Claude** (`ANTHROPIC_API_KEY`)
- *(Optional)* Hugging Face token (`HF_TOKEN`) for private or gated models (`meta-llama`, etc.)

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/your-org/intent-guard
cd intent-guard

# 2. Install backend dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env — set LLM_PROVIDER=openrouter, OPENROUTER_API_KEY=your_key,
# and LLM_MODEL=deepseek/deepseek-v4.1-flash

# 4. (Optional) Install REA reverse engineering tools globally
npm install -g rea-agents

# 5. Start Neo4j and MongoDB (if using graph / persistent storage)
docker-compose up -d db-neo4j db-mongo

# 6. Build the Sandbox Docker image
docker build -t intentguard-sandbox -f sandbox.Dockerfile .
```

---

## Running

### CLI Scans

```bash
# Scan a Hugging Face model repository (Zero-download HTTP Range header check)
python main.py scan hf:TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF

# Scan a local GGUF model weight or checkpoint
python main.py scan ./models/llama-3-8b-instruct.Q4_K_M.gguf

# Scan an executable or binary package with REA
python main.py scan ./dist/agent_runner.exe

# Scan a public GitHub agent repository
python main.py scan https://github.com/user/agent-repo

# Scan a local agentic markdown skill file
python main.py scan ./skills/research_agent.md

# Quick smoke scan with JSON nutrition label output
python main.py scan ./demo/sample_skill.md --json
```

### Backend (Flask API)

```bash
python run_server.py --port 5000
```

The API binds `127.0.0.1` by default.

### Frontend (React / Tailwind)

```bash
cd frontend
npm install
npm start
# → http://localhost:3000
```

---

## Project structure

```text
intent-guard/
├── .env.example               # Sample configuration (copy to .env; never commit secrets)
├── LICENSE
├── README.md
├── requirements.txt           # Python dependencies (Flask, Pydantic, OpenAI SDK, etc.)
├── docker-compose.yml         # Neo4j, MongoDB, and local service wiring
├── sandbox.Dockerfile         # Sandbox image for dynamic analysis
├── run_server.py              # Flask API entry point
├── main.py                    # CLI entry point (`python main.py scan …`)
├── config.py                  # Settings, .env loader, LLM provider selection
│
├── api/                       # Flask application package
│   ├── app.py                 # Application factory
│   └── routes.py              # REST endpoints (`/api/scans`, streaming, uploads)
│
├── engine/                    # Core analysis pipeline
│   ├── orchestrator.py        # Pipeline coordinator & risk aggregator
│   ├── dynamic/               # Adversarial attack replay simulator
│   ├── agents/
│   │   ├── ingestion.py       # Normalizes GitHub repos, HF models, GGUF/binaries, .md skills
│   │   ├── ast_tracer.py      # Deterministic code parsing & graph construction
│   │   ├── semantic.py        # LLM intent analysis (OpenRouter / OpenAI / Anthropic)
│   │   ├── owasp.py           # OWASP Agentic Top 10 taxonomy mapper
│   │   └── sandbox.py         # Dynamic dry-run execution in Docker
│   ├── artifacts/             # Model weight, model card & binary reverse engineering
│   │   ├── detect.py          # Magic byte sniffer (GGUF, Safetensors, Pickle, PE, ELF, etc.)
│   │   ├── byte_source.py     # Local file and HTTP Range remote streaming
│   │   ├── gguf.py            # GGUF parser: sanity, alignment, overlays, NaN/Inf scales
│   │   ├── safetensors.py     # SafeTensors header parser and validation
│   │   ├── pickle_scan.py     # Pure-Python PyTorch pickle opcode disassembler
│   │   ├── chat_template.py   # Jinja SSTI (CVE-2024-34359) & prompt injection scanner
│   │   ├── huggingface.py      # HF Hub API client, typosquatting & trust_remote_code checks
│   │   ├── binary_triage.py   # Static entropy, packer, URL, and capability detection
│   │   ├── rea_bridge.py      # Subprocess bridge to REA (morluto/rea) reverse-engineering
│   │   └── runner.py          # Orchestrates artifact scans & formats evidence for LLM
│   ├── llm/                   # Unified LLM provider layer
│   │   ├── openrouter_client.py # OpenRouter client with deepseek-v4.1-flash & headers
│   │   ├── openai_client.py   # OpenAI client
│   │   ├── anthropic_client.py # Anthropic Claude client
│   │   └── helicone.py        # Helicone gateway & caching headers
│   └── agent_runtime/         # LangGraph runtime with LangSmith tracing
│
├── schemas/                   # Pydantic schemas
│   ├── graph_nodes.py         # Neo4j topology & workflow nodes
│   └── report_schema.py       # NutritionLabel & Finding JSON schema
│
└── tests/                     # 98 pytest unit & integration tests
    ├── conftest.py
    ├── test_artifacts_and_rea.py # Tests for GGUF, SSTI, pickle, REA, OpenRouter
    └── test_orchestrator.py
```

---

## API endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scans` | Submit a target (GitHub URL, Hugging Face repo `hf:org/repo`, or file upload) |
| `POST` | `/api/scans/stream` | Server-Sent Events (SSE) stream returning real-time scan progress |
| `GET` | `/api/scans` | List historical scan reports |
| `GET` | `/api/scans/{id}/report` | Retrieve the structured JSON "Nutrition Label" |
| `GET` | `/api/scans/{id}/topology` | Retrieve the Neo4j node/edge data for frontend visualization |
| `GET` | `/api/scans/{id}/telemetry` | Return ready-made LangSmith / Helicone deep-link URLs |

---

## Environment variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `LLM_PROVIDER` | `openrouter` | `openrouter`, `openai`, or `anthropic` — which vendor backs semantic analysis |
| `OPENROUTER_API_KEY` | — | Required when `LLM_PROVIDER=openrouter` |
| `LLM_MODEL` | `deepseek/deepseek-v4.1-flash` | Model identifier (e.g. `deepseek/deepseek-v4.1-flash`, `anthropic/claude-sonnet-5.5`) |
| `OPENAI_API_KEY` | — | Required when `LLM_PROVIDER=openai` |
| `ANTHROPIC_API_KEY` | — | Required when `LLM_PROVIDER=anthropic` |
| `HF_TOKEN` | — | Optional Hugging Face token for private/gated model repos |
| `REA_COMMAND` | `auto` | Path to `rea` binary, `auto` (detects `rea` or `npx rea-agents`), or `off` |
| `REA_ANALYSIS_PROVIDER` | — | Optional REA disassembler backend (`ghidra`, `hopper`, `ida`) |
| `NEO4J_URI` | `bolt://localhost:7687` | Connection string for Neo4j |
| `MONGO_URI` | `mongodb://localhost:27017` | Connection string for MongoDB |
| `DYNAMIC_ANALYSIS` | `true` | Run the adversarial simulation track |
| `DYNAMIC_DRIVER` | `scripted` | `scripted` reports capabilities/gaps; `llm` tests real model compliance |
| `LANGCHAIN_TRACING_V2` | `false` | Enable LangSmith tracing |
| `HELICONE_API_KEY` | — | Optional Helicone observability and response cache key |
| `USE_LANGGRAPH_RUNTIME` | `true` | Use LangGraph for semantic analysis pipeline |

---

## License

MIT

