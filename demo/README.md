# IntentGuard demo

This folder is a **standalone preview** of the IntentGuard dashboard (v0.9.1-beta) using **static mock data**—no Flask API, Neo4j, or LLM keys required.

## Interactive UI (recommended)

The React app under `demo/ui` mirrors the product screenshots: scanned skills, sources, nutrition label, dataflow graph, OWASP Agentic Top 10 grid, annotated code, and aggregate risk / findings.

```bash
cd demo/ui
npm install
npm run dev
```

Open the URL Vite prints (typically `http://localhost:5173`).

### Mock pipeline (interactive workflow)

The app opens on **Mock pipeline**, which simulates the production flow from the root `README.md` without any network I/O:

1. **Ingestion** — POST to `/api/scans`, isolated sandbox path, `git clone` *or* uploaded `.md` metadata  
2. **Static parsing** — AST walk, imports, agentic surfaces  
3. **Graph construction** — Neo4j nodes/edges and “paths of interest”  
4. **Semantic analysis** — LLM path evaluation (`evaluate_intent` / OWASP mapping)  
5. **Aggregation & storage** — Nutrition Label JSON → MongoDB with a generated **Scan ID**  
6. **Display** — `GET /api/scans/{id}/report` + topology (mocked here as hydrating the dashboard)

Choose a public GitHub URL or a local `.md` file, then **Run mock pipeline**. When the run finishes, the static dashboard loads with **Sources** and the header **Scan ID** reflecting your input. Use **New mock scan** to run again or **Skip simulation · open static preview** to jump straight to the bundled report.

### Automated tests (pipeline logic)

```bash
cd demo/ui
npm test
```

Runs Vitest against `mockPipeline.ts` (stage ordering, GitHub URL parsing, abort handling).

### Static dashboard only

Use the left list to switch skills (e.g. `log_collector.py` for the full dataflow graph) and the tabs for each view.

```bash
npm run build   # production bundle → demo/ui/dist
npm run preview # serve the built bundle locally
```

Mock data lives in `demo/mock/scan-preview.json` (copied into `demo/ui/src/data/` for the bundler). Edit the JSON to tweak copy, graph nodes, or findings.

## Sample files for future CLI / API wiring

| Path | Purpose |
| :--- | :--- |
| `sample_skill.md` | Minimal skill front matter for smoke tests once `main.py scan` exists |
| `sample_mcp_tools.json` | Example MCP-style tool definitions for ingestion tests |
| `samples/*.py`, `samples/doc_reader.md` | Risky / benign snippets aligned with the UI storyboard |

When the backend is implemented, point scans at `./demo/samples` or `./demo/sample_skill.md` as described in the root `README.md`.
