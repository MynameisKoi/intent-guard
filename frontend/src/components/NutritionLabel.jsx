/**
 * Non-technical summary from the Nutrition Label JSON (`GET /api/scans/:id/report`).
 */
const OWASP_LLM_TITLES = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

function renderOwaspLlmLabel(owaspId) {
  if (!owaspId) return null;
  const key = String(owaspId).toUpperCase();
  const title = OWASP_LLM_TITLES[key];
  return title ? `${key} - ${title}` : key;
}

function categoryLevelClass(level) {
  const l = String(level || "").toLowerCase();
  if (l === "high") return "text-red-300";
  if (l === "medium") return "text-amber-300";
  return "text-emerald-300";
}

export default function NutritionLabel({ report, sources }) {
  if (!report) {
    return <p className="text-ig-muted">No report payload.</p>;
  }

  const risk = report.risk_score ?? "—";
  const label = report.risk_label ?? "";

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-ig-border bg-ig-panel p-4">
        <div className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Risk</div>
        <div className="mt-1 text-3xl font-bold text-red-200">
          {risk}
          <span className="text-lg font-normal text-ig-muted"> / 10</span>
        </div>
        <div className="text-sm text-red-300/90">{label}</div>
      </div>

      {sources?.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Sources</h3>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {sources.map((s, i) => (
              <li key={i}>
                <span className="text-ig-muted">{s.kind}</span> · {s.label}
              </li>
            ))}
          </ul>
        </div>
      )}

      <section>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Intent summary</h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-200">{report.intent_summary}</p>
      </section>

      {(report.permissions_inferred?.length > 0 || report.network_targets?.length > 0) && (
        <div className="grid gap-4 sm:grid-cols-2">
          {report.permissions_inferred?.length > 0 && (
            <div className="rounded-lg border border-ig-border bg-ig-panel/80 p-3">
              <h4 className="text-xs font-semibold text-ig-muted">Permissions inferred</h4>
              <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">
                {report.permissions_inferred.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            </div>
          )}
          {report.network_targets?.length > 0 && (
            <div className="rounded-lg border border-ig-border bg-ig-panel/80 p-3">
              <h4 className="text-xs font-semibold text-ig-muted">Network</h4>
              <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">
                {report.network_targets.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {report.shell_execution && (
        <div className="rounded border border-ig-warn/50 bg-amber-950/30 px-3 py-2 text-sm text-amber-100">
          Shell / subprocess execution flagged in analysis.
        </div>
      )}

      {report.findings?.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Findings</h3>
          <ul className="mt-3 space-y-3">
            {report.findings.map((f) => (
              <li key={f.id} className="rounded-lg border border-ig-border bg-ig-panel/60 p-3">
                <div className="font-semibold text-slate-100">{f.title}</div>
                <p className="mt-1 text-xs text-slate-400">{f.description}</p>
                {f.owasp_id && (
                  <div className="mt-2 font-mono text-xs text-ig-accent">{renderOwaspLlmLabel(f.owasp_id)}</div>
                )}
                {f.affected_path && <div className="mt-1 font-mono text-xs text-emerald-300">Affected path: {f.affected_path}</div>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {report.category_scores?.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Category scores</h3>
          <ul className="mt-2 flex flex-wrap gap-2 text-xs">
            {report.category_scores.map((c, i) => (
              <li key={i} className="rounded border border-ig-border px-2 py-1 text-slate-300">
                {c.category}: <span className={categoryLevelClass(c.level)}>{c.level}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
