import { useMemo, useState } from "react";
import type { ScanPreview, SkillPreview, SourceRef } from "../types";
import type { PipelineInput } from "../pipeline/pipelineTypes";
import { parseGithubRepoLabel } from "../pipeline/mockPipeline";
import { AnnotatedCode } from "./AnnotatedCode";
import { GraphPane } from "./GraphPane";
import { NutritionPane } from "./NutritionPane";
import { OwaspPane } from "./OwaspPane";

export type TabId = "nutrition" | "graph" | "owasp" | "code";
type AudienceMode = "executive" | "engineer";

const TABS: { id: TabId; label: string }[] = [
  { id: "nutrition", label: "Nutrition label" },
  { id: "graph", label: "Dataflow graph" },
  { id: "owasp", label: "OWASP mapping" },
  { id: "code", label: "Annotated code" },
];

function riskBadgeClass(r: string): string {
  switch (r) {
    case "HIGH":
      return "bg-red-950/80 text-red-200 border border-red-800/80";
    case "MED":
      return "bg-amber-950/70 text-amber-100 border border-amber-800/50";
    case "LOW":
      return "bg-emerald-950/60 text-emerald-100 border border-emerald-800/30";
    default:
      return "bg-slate-800 text-slate-200";
  }
}

function categoryBarWidth(level: string): string {
  if (level === "high") return "w-[92%]";
  if (level === "medium") return "w-[55%]";
  return "w-[28%]";
}

function categoryBarColor(level: string): string {
  if (level === "high") return "bg-red-500/90";
  if (level === "medium") return "bg-ig-warn/90";
  return "bg-emerald-500/70";
}

function sourceKindLabel(kind: SourceRef["kind"]): string {
  if (kind === "github") return "GH";
  if (kind === "mcp") return "MCP";
  return "FILE";
}

export function deriveSourcesFromInput(input: PipelineInput | null, fallback: SourceRef[]): SourceRef[] {
  if (!input) return fallback;
  if (input.kind === "github") {
    const label = parseGithubRepoLabel(input.url);
    return [
      { id: "src-gh", label, kind: "github" },
      { id: "src-mcp", label: "mcp-tools.json", kind: "mcp" },
    ];
  }
  return [{ id: "src-upload", label: input.fileName, kind: "upload" }];
}

export interface DashboardViewProps {
  data: ScanPreview;
  /** When set, header shows live scan metadata (mock pipeline output). */
  scanContext?: { scanId: string; input: PipelineInput } | null;
  /** Override meta for header progress text (e.g. after pipeline completes). */
  headerMeta?: Partial<Pick<ScanPreview["meta"], "analysisProgress" | "semanticStatus">>;
  initialTab?: TabId;
  onNewMockScan?: () => void;
}

function levelColor(level: string): string {
  if (level === "high") return "text-red-300";
  if (level === "medium") return "text-amber-300";
  return "text-emerald-300";
}

export function DashboardView({
  data,
  scanContext,
  headerMeta,
  initialTab = "graph",
  onNewMockScan,
}: DashboardViewProps) {
  const [skillId, setSkillId] = useState<string>("log_collector");
  const [tab, setTab] = useState<TabId>(initialTab);
  const [audience, setAudience] = useState<AudienceMode>("executive");

  const skill = useMemo(
    () => data.skills.find((s) => s.id === skillId) ?? data.skills[0],
    [skillId, data.skills],
  ) as SkillPreview;

  const sources = useMemo(
    () => deriveSourcesFromInput(scanContext?.input ?? null, data.sources),
    [scanContext, data.sources],
  );

  const meta = data.meta;
  const progress = headerMeta?.analysisProgress ?? meta.analysisProgress;
  const statusLine = headerMeta?.semanticStatus ?? meta.semanticStatus;

  return (
    <div className="flex min-h-full flex-col bg-ig-bg text-slate-100">
      <header className="sticky top-0 z-10 flex flex-wrap items-center gap-4 border-b border-ig-border bg-ig-panel/95 px-6 py-3 backdrop-blur">
        <div className="flex items-baseline gap-2">
          <span className="text-lg font-bold text-ig-accent">IntentGuard</span>
          <span className="text-xs text-ig-muted">v{meta.version}</span>
        </div>
        {scanContext && (
          <div className="hidden text-[11px] text-ig-muted md:block" title="Mock scan identifier">
            Scan <span className="font-mono text-slate-300">{scanContext.scanId}</span>
          </div>
        )}
        <div className="flex min-w-[200px] flex-1 flex-col gap-1">
          <div className="flex justify-between text-[11px] text-ig-muted">
            <span>{statusLine}</span>
            <span>{progress}%</span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full bg-ig-accent transition-all"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
        <div className="rounded-full border border-red-800/60 bg-red-950/50 px-3 py-1 text-xs font-semibold text-red-200">
          {meta.highRiskCount} HIGH risks
        </div>
        <div className="ml-auto inline-flex rounded-lg border border-ig-border bg-ig-bg p-1 text-xs">
          <button
            type="button"
            onClick={() => setAudience("executive")}
            className={`rounded px-3 py-1 font-medium ${
              audience === "executive" ? "bg-ig-accent text-slate-900" : "text-slate-300 hover:text-white"
            }`}
          >
            Executive view
          </button>
          <button
            type="button"
            onClick={() => setAudience("engineer")}
            className={`rounded px-3 py-1 font-medium ${
              audience === "engineer" ? "bg-ig-accent text-slate-900" : "text-slate-300 hover:text-white"
            }`}
          >
            Engineer view
          </button>
        </div>
        {onNewMockScan && (
          <button
            type="button"
            onClick={onNewMockScan}
            className="rounded-md border border-ig-border bg-ig-bg px-3 py-1 text-xs font-medium text-slate-200 hover:bg-slate-800"
          >
            New mock scan
          </button>
        )}
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="hidden w-[250px] shrink-0 flex-col border-r border-ig-border bg-ig-panel xl:flex">
          <nav className="border-b border-ig-border px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Scanned skills</h2>
            <ul className="mt-2 space-y-1">
              {data.skills.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    onClick={() => setSkillId(s.id)}
                    className={`flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-sm transition ${
                      s.id === skillId ? "bg-slate-800/80 text-white" : "text-slate-300 hover:bg-slate-800/40"
                    }`}
                  >
                    <span className="truncate">{s.name}</span>
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${riskBadgeClass(s.risk)}`}>
                      {s.risk}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
          <section className="border-b border-ig-border px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Sources</h2>
            <ul className="mt-2 space-y-2 text-sm">
              {sources.map((src) => (
                <li key={src.id} className="flex items-center gap-2 text-slate-300">
                  <span className="text-ig-muted">{sourceKindLabel(src.kind)}</span>
                  <span className="truncate">{src.label}</span>
                </li>
              ))}
            </ul>
          </section>
          <section className="px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Views</h2>
            <ul className="mt-2 space-y-1">
              {TABS.map((t) => (
                <li key={t.id}>
                  <button
                    type="button"
                    onClick={() => {
                      setAudience("engineer");
                      setTab(t.id);
                    }}
                    className={`w-full rounded-md px-2 py-1.5 text-left text-sm ${
                      tab === t.id ? "text-ig-accent" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {t.label}
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </aside>

        <main className="flex min-w-0 flex-1 flex-col">
          <div className="flex flex-wrap items-start justify-between gap-3 border-b border-ig-border bg-ig-bg/80 px-6 py-4">
            <div>
              <h1 className="text-xl font-semibold text-white">{skill.name}</h1>
              <p className="mt-1 text-xs text-ig-muted">
                {skill.language} · {skill.lines} lines · Scanned {skill.scannedAgo} · AST depth {skill.astDepth}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                className="rounded-md border border-ig-border bg-ig-panel px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
              >
                Export report
              </button>
              <button
                type="button"
                className="rounded-md border border-ig-border bg-ig-panel px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
              >
                Pre-commit hook
              </button>
              <button
                type="button"
                className="rounded-md bg-ig-accent px-4 py-1.5 text-xs font-semibold text-slate-900 hover:brightness-110"
              >
                Re-scan
              </button>
            </div>
          </div>

          {audience === "engineer" && (
            <div className="border-b border-ig-border px-6">
              <div className="flex flex-wrap gap-1">
                {TABS.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setTab(t.id)}
                    className={`border-b-2 px-3 py-2 text-sm font-medium transition ${
                      tab === t.id
                        ? "border-ig-accent text-ig-accent"
                        : "border-transparent text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div className="flex-1 overflow-y-auto px-6 py-6">
            {audience === "executive" && (
              <div className="space-y-6">
                <section className="grid gap-3 md:grid-cols-3">
                  <article className="rounded-lg border border-ig-border bg-ig-panel p-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Overall risk</div>
                    <div className="mt-2 text-3xl font-bold text-red-200">{data.aggregate.score}</div>
                    <div className="text-sm text-red-300">{data.aggregate.label}</div>
                  </article>
                  <article className="rounded-lg border border-ig-border bg-ig-panel p-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Top issue count</div>
                    <div className="mt-2 text-3xl font-bold text-white">{data.findings.length}</div>
                    <div className="text-sm text-slate-400">Cross-skill findings identified</div>
                  </article>
                  <article className="rounded-lg border border-ig-border bg-ig-panel p-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Scanned assets</div>
                    <div className="mt-2 text-3xl font-bold text-white">{data.skills.length}</div>
                    <div className="text-sm text-slate-400">Skills and modules reviewed</div>
                  </article>
                </section>

                <section className="rounded-lg border border-ig-border bg-ig-panel p-5">
                  <h3 className="text-sm font-semibold text-white">Plain-language intent summary</h3>
                  <p className="mt-2 text-sm leading-relaxed text-slate-200">{skill.nutrition.intentSummary}</p>
                </section>

                <section className="rounded-lg border border-ig-border bg-ig-panel p-5">
                  <h3 className="text-sm font-semibold text-white">Risk profile by category</h3>
                  <ul className="mt-3 grid gap-3 sm:grid-cols-2">
                    {data.aggregate.categories.map((c) => (
                      <li key={c.id} className="rounded border border-ig-border bg-ig-bg/40 px-3 py-2 text-sm">
                        <span className="text-slate-300">{c.label}</span>
                        <span className={`ml-2 font-semibold capitalize ${levelColor(c.level)}`}>{c.level}</span>
                      </li>
                    ))}
                  </ul>
                </section>

                <section className="rounded-lg border border-ig-border bg-ig-panel p-5">
                  <h3 className="text-sm font-semibold text-white">Priority findings for stakeholders</h3>
                  <ul className="mt-3 space-y-3">
                    {data.findings.slice(0, 4).map((f) => (
                      <li key={f.id} className="rounded border border-ig-border bg-ig-bg/40 p-3">
                        <div className="font-medium text-slate-100">{f.title}</div>
                        <p className="mt-1 text-sm text-slate-300">{f.body}</p>
                      </li>
                    ))}
                  </ul>
                </section>

                <section className="rounded-lg border border-ig-border bg-ig-panel p-5">
                  <h3 className="text-sm font-semibold text-white">Technical appendix</h3>
                  <p className="mt-2 text-sm text-slate-300">
                    Switch to <span className="text-ig-accent">Engineer view</span> for dataflow graph, OWASP mapping,
                    and annotated source details.
                  </p>
                </section>
              </div>
            )}

            {audience === "engineer" && (
              <>
                {tab === "nutrition" && <NutritionPane skill={skill} />}
                {tab === "graph" && <GraphPane skill={skill} />}
                {tab === "owasp" && <OwaspPane skill={skill} />}
                {tab === "code" && <AnnotatedCode skill={skill} />}
              </>
            )}
          </div>
        </main>

        <aside className="hidden w-[300px] shrink-0 flex-col border-l border-ig-border bg-ig-panel px-4 py-5 lg:flex">
          <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Risk score</h2>
          <div className="mt-2 text-3xl font-bold text-red-200">
            {data.aggregate.score}
            <span className="text-lg font-normal text-ig-muted"> / 10</span>
          </div>
          <p className="text-sm font-semibold text-red-300/90">{data.aggregate.label}</p>

          <h3 className="mt-6 text-[10px] font-bold uppercase tracking-wider text-ig-muted">Risk categories</h3>
          <ul className="mt-3 space-y-3">
            {data.aggregate.categories.map((c) => (
              <li key={c.id}>
                <div className="mb-1 flex justify-between text-[11px] text-slate-400">
                  <span>{c.label}</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                  <div
                    className={`h-full max-w-full rounded-full ${categoryBarWidth(c.level)} ${categoryBarColor(c.level)}`}
                  />
                </div>
              </li>
            ))}
          </ul>

          <h3 className="mt-6 text-[10px] font-bold uppercase tracking-wider text-ig-muted">
            Findings ({data.findings.length})
          </h3>
          <ul className="mt-2 max-h-[420px] space-y-3 overflow-y-auto pr-1 text-xs">
            {data.findings.map((f) => (
              <li key={f.id} className="rounded-md border border-ig-border bg-ig-bg/50 p-3">
                <div className="font-semibold text-slate-200">{f.title}</div>
                <p className="mt-1 text-[11px] leading-relaxed text-slate-400">{f.body}</p>
                <div className="mt-2 text-[10px] font-mono text-ig-accent">OWASP {f.owasp}</div>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </div>
  );
}
