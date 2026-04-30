import { useCallback, useRef, useState } from "react";
import { PIPELINE_STAGE_IDS, type PipelineInput, type PipelineStageId } from "../pipeline/pipelineTypes";
import { runMockPipeline, type RunMockPipelineOptions } from "../pipeline/mockPipeline";

const STAGE_LABELS: Record<PipelineStageId, { title: string; subtitle: string }> = {
  ingestion: {
    title: "1 · Ingestion",
    subtitle: "Frontend → Flask · sandbox workspace",
  },
  static_parse: {
    title: "2 · Static parsing",
    subtitle: "AST / syntax layer · functions, imports, hooks",
  },
  graph: {
    title: "3 · Graph construction",
    subtitle: "Neo4j · dataflow & calls",
  },
  semantic: {
    title: "4 · Semantic analysis",
    subtitle: "Paths of interest → LLM intent & risk",
  },
  aggregate: {
    title: "5 · Aggregation & storage",
    subtitle: 'Nutrition Label JSON · MongoDB · Scan ID',
  },
  display: {
    title: "6 · Display",
    subtitle: "API → React · report + topology",
  },
};

const DEFAULT_URL = "https://github.com/example/my-agent-repo";

export interface PipelineRunnerProps {
  onComplete: (result: { scanId: string; input: PipelineInput }) => void;
  /** Use shorter delays (e.g. in Storybook or fast machines). */
  fastMode?: boolean;
}

export function PipelineRunner({ onComplete, fastMode }: PipelineRunnerProps) {
  const [mode, setMode] = useState<"github" | "skill">("github");
  const [url, setUrl] = useState(DEFAULT_URL);
  const [fileName, setFileName] = useState("research_agent.md");
  const [fileSize, setFileSize] = useState(2048);

  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [activeStage, setActiveStage] = useState<PipelineStageId | null>(null);
  const [doneStages, setDoneStages] = useState<PipelineStageId[]>([]);
  const [logs, setLogs] = useState<{ stage: PipelineStageId; message: string }[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const logBoxRef = useRef<HTMLDivElement | null>(null);

  const appendLog = useCallback((stage: PipelineStageId, message: string) => {
    setLogs((prev) => [...prev, { stage, message }]);
    requestAnimationFrame(() => {
      logBoxRef.current?.scrollTo({ top: logBoxRef.current.scrollHeight, behavior: "smooth" });
    });
  }, []);

  const run = async () => {
    const input: PipelineInput =
      mode === "github"
        ? { kind: "github", url: url.trim() || DEFAULT_URL }
        : { kind: "skill", fileName: fileName.trim() || "skill.md", byteLength: fileSize };

    const opts: RunMockPipelineOptions = {
      logDelayMs: fastMode ? 35 : 180,
      stagePauseMs: fastMode ? 120 : 380,
      signal: undefined,
    };

    const ac = new AbortController();
    abortRef.current = ac;
    opts.signal = ac.signal;

    setRunning(true);
    setLogs([]);
    setDoneStages([]);
    setActiveStage(null);
    setProgress(0);
    setStatus("Running mock pipeline…");

    try {
      const result = await runMockPipeline(
        input,
        (e) => {
          if (e.type === "log") {
            appendLog(e.stage, e.message);
            const idx = PIPELINE_STAGE_IDS.indexOf(e.stage);
            const pct = Math.min(99, Math.round(((idx + 0.6) / PIPELINE_STAGE_IDS.length) * 100));
            setProgress(pct);
          }
          if (e.type === "stage" && e.status === "start") {
            setActiveStage(e.stage);
            const idx = PIPELINE_STAGE_IDS.indexOf(e.stage);
            setProgress(Math.min(95, Math.round((idx / PIPELINE_STAGE_IDS.length) * 100)));
          }
          if (e.type === "stage" && e.status === "end") {
            setDoneStages((d) => (d.includes(e.stage) ? d : [...d, e.stage]));
          }
          if (e.type === "complete") {
            setProgress(100);
            setStatus(`Complete in ${e.elapsedMs} ms — ${e.scanId}`);
            setActiveStage(null);
          }
          if (e.type === "aborted") {
            setStatus("Aborted");
          }
        },
        opts,
      );

      onComplete({ scanId: result.scanId, input });
    } catch (err) {
      const e = err as Error;
      if (e.name === "AbortError") {
        setStatus("Cancelled");
        setProgress(0);
      } else {
        setStatus(e.message || "Error");
      }
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  };

  const cancel = () => {
    abortRef.current?.abort();
  };

  const onFileChange = (files: FileList | null) => {
    const f = files?.[0];
    if (!f) return;
    setFileName(f.name);
    setFileSize(f.size);
  };

  return (
    <div className="mx-auto flex min-h-full max-w-3xl flex-col px-4 py-10">
      <div className="mb-2 text-center">
        <h1 className="text-2xl font-bold text-white">Mock pipeline</h1>
        <p className="mt-2 text-sm text-ig-muted">
          Simulates the end-to-end workflow from the README: ingestion → AST → Neo4j → LLM semantics → MongoDB → UI.
          No real network or databases.
        </p>
      </div>

      <div className="mt-8 rounded-xl border border-ig-border bg-ig-panel p-5">
        <div className="flex gap-2 border-b border-ig-border pb-4">
          <button
            type="button"
            disabled={running}
            onClick={() => setMode("github")}
            className={`rounded-lg px-4 py-2 text-sm font-medium ${
              mode === "github" ? "bg-ig-accent text-slate-900" : "bg-ig-bg text-slate-300 hover:bg-slate-800"
            }`}
          >
            Public GitHub URL
          </button>
          <button
            type="button"
            disabled={running}
            onClick={() => setMode("skill")}
            className={`rounded-lg px-4 py-2 text-sm font-medium ${
              mode === "skill" ? "bg-ig-accent text-slate-900" : "bg-ig-bg text-slate-300 hover:bg-slate-800"
            }`}
          >
            Upload .md skill
          </button>
        </div>

        <div className="mt-5 space-y-4">
          {mode === "github" ? (
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Repository URL</span>
              <input
                className="mt-1 w-full rounded-lg border border-ig-border bg-ig-bg px-3 py-2 font-mono text-sm text-slate-200 outline-none focus:border-ig-accent"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={running}
                placeholder="https://github.com/org/repo"
              />
            </label>
          ) : (
            <div>
              <span className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Skill file</span>
              <div className="mt-1 flex flex-wrap items-center gap-3">
                <input
                  type="file"
                  accept=".md,.markdown,text/markdown"
                  disabled={running}
                  onChange={(e) => onFileChange(e.target.files)}
                  className="text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-1.5 file:text-sm file:text-white"
                />
                <span className="text-xs text-ig-muted">
                  {fileName} · {fileSize} bytes (simulated ingestion uses file name + size)
                </span>
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <button
              type="button"
              disabled={running}
              onClick={() => void run()}
              className="rounded-lg bg-ig-accent px-5 py-2.5 text-sm font-semibold text-slate-900 hover:brightness-110 disabled:opacity-50"
            >
              Run mock pipeline
            </button>
            {running && (
              <button
                type="button"
                onClick={cancel}
                className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-2.5 text-sm font-medium text-red-200"
              >
                Cancel
              </button>
            )}
            {status && <span className="text-xs text-ig-muted">{status}</span>}
          </div>
        </div>
      </div>

      <div className="mt-6 rounded-xl border border-ig-border bg-ig-panel p-4">
        <div className="mb-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
          <div
            className="h-full rounded-full bg-ig-accent transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
        <ol className="grid gap-2 sm:grid-cols-2">
          {PIPELINE_STAGE_IDS.map((id) => {
            const done = doneStages.includes(id);
            const active = activeStage === id;
            return (
              <li
                key={id}
                className={`rounded-lg border px-3 py-2 text-left text-xs ${
                  active
                    ? "border-ig-accent bg-emerald-950/30 text-emerald-100"
                    : done
                      ? "border-slate-600 bg-slate-900/60 text-slate-300"
                      : "border-ig-border bg-ig-bg text-ig-muted"
                }`}
              >
                <div className="font-semibold text-slate-200">{STAGE_LABELS[id].title}</div>
                <div className="text-[11px] text-ig-muted">{STAGE_LABELS[id].subtitle}</div>
              </li>
            );
          })}
        </ol>
      </div>

      <div
        ref={logBoxRef}
        className="mt-4 max-h-[320px] min-h-[160px] overflow-y-auto rounded-xl border border-ig-border bg-[#05070a] p-3 font-mono text-[11px] leading-relaxed text-emerald-200/90"
      >
        {logs.length === 0 && <span className="text-slate-600">// Pipeline log output appears here…</span>}
        {logs.map((l, i) => (
          <div key={i} className="whitespace-pre-wrap border-l-2 border-slate-700 pl-2">
            <span className="text-slate-500">[{l.stage}]</span> {l.message}
          </div>
        ))}
      </div>
    </div>
  );
}
