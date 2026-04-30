import type { SkillPreview } from "../types";

export function OwaspPane({ skill }: { skill: SkillPreview }) {
  const ow = skill.owasp;
  if (!ow) {
    return (
      <div className="rounded-lg border border-dashed border-ig-border bg-ig-bg/60 px-4 py-12 text-center text-sm text-ig-muted">
        No OWASP mapping in the mock for this skill. Try{" "}
        <code className="text-ig-accent">log_collector.py</code> or <code className="text-ig-accent">data_aggregator.py</code>.
      </div>
    );
  }
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {ow.cards.map((c) => (
          <div
            key={c.id}
            className={`rounded-lg border px-3 py-2 text-center text-xs font-semibold ${
              c.flagged
                ? "border-ig-danger bg-red-950/40 text-red-200"
                : "border-ig-border bg-ig-panel text-slate-400"
            }`}
          >
            <div className="text-[10px] font-bold uppercase tracking-wide">{c.id}</div>
            <div className="mt-1 leading-tight">{c.title}</div>
          </div>
        ))}
      </div>
      <div className="rounded-lg border border-ig-border bg-ig-bg/50 p-5">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <h3 className="text-lg font-semibold text-red-200">{ow.focusDetail.title}</h3>
          <span className="rounded bg-red-950 px-2 py-0.5 text-xs font-semibold text-red-200">
            {ow.focusDetail.risk} Risk
          </span>
        </div>
        <p className="text-sm leading-relaxed text-slate-300">{ow.focusDetail.description}</p>
        <div className="mt-4 rounded border border-ig-border bg-ig-panel px-3 py-2 font-mono text-xs text-ig-accent">
          Affected path: {ow.focusDetail.path}
        </div>
      </div>
    </div>
  );
}
