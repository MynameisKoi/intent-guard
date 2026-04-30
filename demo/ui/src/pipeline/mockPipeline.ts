import type { PipelineEvent, PipelineInput, PipelineStageId } from "./pipelineTypes";

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const id = globalThis.setTimeout(resolve, ms);
    const onAbort = () => {
      globalThis.clearTimeout(id);
      reject(abortError());
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function abortError(): Error {
  const e = new Error("Aborted");
  e.name = "AbortError";
  return e;
}

function makeScanId(): string {
  const part =
    typeof crypto !== "undefined" && crypto.randomUUID
      ? crypto.randomUUID().replace(/-/g, "").slice(0, 12)
      : Math.random().toString(36).slice(2, 14);
  return `scan_${part}`;
}

/** Extract `owner/repo` from a GitHub HTTPS or SSH URL for display. */
export function parseGithubRepoLabel(url: string): string {
  const u = url.trim();
  const m = u.match(/github\.com[:/]([^/]+\/[^/?#]+)/i);
  if (m) return m[1].replace(/\.git$/i, "");
  return "unknown/repo";
}

function linesForStage(stage: PipelineStageId, input: PipelineInput, scanId: string): string[] {
  const sandboxPath = `/sandbox/ws_${scanId.slice(5, 13)}`;
  switch (stage) {
    case "ingestion":
      if (input.kind === "github") {
        const repo = parseGithubRepoLabel(input.url);
        return [
          `HTTP POST /api/scans — payload accepted (target: repository URL)`,
          `Allocating isolated workspace ${sandboxPath}`,
          `git clone → ${repo} (shallow, depth 1)`,
          `Normalizing workspace representation (skills, MCP manifests, .md files)`,
          `Handshake: Flask → ingestion agent → workspace ready`,
        ];
      }
      return [
        `HTTP POST /api/scans — multipart upload (skill file)`,
        `Allocating isolated workspace ${sandboxPath}`,
        `Stored: ${input.fileName} (${input.byteLength} bytes)`,
        `Normalizing workspace representation (single-skill scan)`,
        `Handshake: Flask → ingestion agent → workspace ready`,
      ];
    case "static_parse":
      return [
        `Python worker: AST walk (*.py, *.md, JSON tools)`,
        `Extracted: functions, globals, imports, string literals`,
        `Example: log_collector.py — AST depth 8, 8 top-level defs`,
        `Detected agentic surfaces: subprocess, requests.post, llm_construct_cmd, prompts`,
        `Deterministic trace ready for graph construction`,
      ];
    case "graph":
      return [
        `Neo4j Bolt session (NEO4J_URI)`,
        `MERGE (:Function)-[:CALLS]->(:Function); (:DataRead)-[:FLOWS_TO]->(:HttpRequest)`,
        `Materialized paths: read_filesystem → aggregate → upload_payload → EXT API`,
        `Tagged edges for “paths of interest” (file read → network)`,
        `Graph stats: 42 nodes, 58 relationships (demo numbers)`,
      ];
    case "semantic":
      return [
        `Cypher query: paths from local FileRead to HttpRequest`,
        `3 paths of interest packaged with code snippets`,
        `LLM_PROVIDER=openai — chat.completions (intent + risk score)`,
        `Parallel: evaluate_intent() semantics (no signature-only rules)`,
        `map_to_taxonomy() → OWASP Agentic Top 10 labels attached`,
      ];
    case "aggregate":
      return [
        `Risk orchestrator: merge static trace + semantic scores`,
        `Nutrition Label JSON validated against report schema`,
        `MongoDB: db.scans.insertOne({ scanId: "${scanId}", nutritionLabel: { ... } })`,
        `Persisted: nutrition summary, findings, skill list, metadata`,
      ];
    case "display":
      return [
        `GET /api/scans/${scanId}/report — 200 (MongoDB document)`,
        `GET /api/scans/${scanId}/topology — 200 (Neo4j projection)`,
        `Frontend: non-technical Nutrition label + technical graph view`,
        `Demo: hydrating dashboard from mock bundle`,
      ];
    default:
      return [];
  }
}

export interface RunMockPipelineOptions {
  /** Per log line delay (ms). Use 0 in tests. */
  logDelayMs?: number;
  /** Between stages (after logs). */
  stagePauseMs?: number;
  signal?: AbortSignal;
}

/**
 * Runs the six-stage workflow with simulated latency and structured log lines.
 * Emits events suitable for a terminal UI and for tests.
 */
export async function runMockPipeline(
  input: PipelineInput,
  onEvent: (e: PipelineEvent) => void,
  options: RunMockPipelineOptions = {},
): Promise<{ scanId: string; elapsedMs: number }> {
  const logDelay = options.logDelayMs ?? 220;
  const stagePause = options.stagePauseMs ?? 450;
  const signal = options.signal;
  if (signal?.aborted) {
    onEvent({ type: "aborted" });
    throw abortError();
  }
  const scanId = makeScanId();
  const tick = () => (typeof performance !== "undefined" ? performance.now() : Date.now());
  const t0 = tick();

  const stages: PipelineStageId[] = [
    "ingestion",
    "static_parse",
    "graph",
    "semantic",
    "aggregate",
    "display",
  ];

  try {
    for (const stage of stages) {
      if (signal?.aborted) throw abortError();
      onEvent({ type: "stage", stage, status: "start" });
      const lines = linesForStage(stage, input, scanId);
      for (const message of lines) {
        if (signal?.aborted) throw abortError();
        onEvent({ type: "log", message, stage });
        if (logDelay > 0) await sleep(logDelay, signal);
      }
      onEvent({ type: "stage", stage, status: "end" });
      if (stagePause > 0) await sleep(stagePause, signal);
    }
    const elapsedMs = Math.round(tick() - t0);
    onEvent({ type: "complete", scanId, elapsedMs });
    return { scanId, elapsedMs };
  } catch (e) {
    const err = e as Error;
    if (err?.name === "AbortError") {
      onEvent({ type: "aborted" });
    }
    throw e;
  }
}
