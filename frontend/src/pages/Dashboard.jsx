import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import NutritionLabel from "../components/NutritionLabel";
import TopologyGraph from "../components/TopologyGraph";
import { useTheme } from "../ThemeContext";
import {
  createScanStream,
  createScanStreamFromFolder,
  getReport,
  getTopology,
  listScans,
} from "../utils/api";

const TABS = [
  { id: "nutrition", label: "Nutrition label" },
  { id: "graph", label: "Dataflow graph" },
  { id: "owasp", label: "OWASP mapping" },
  { id: "annotated", label: "Annotated code" },
];

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
  if (!owaspId) return "";
  const key = String(owaspId).toUpperCase();
  const title = OWASP_LLM_TITLES[key];
  return title ? `${key} - ${title}` : key;
}

const OWASP_LLM_ORDER = Object.keys(OWASP_LLM_TITLES);

function formatSseEvent(ev) {
  if (!ev || typeof ev !== "object") return String(ev);
  if (ev.type === "heartbeat") return "… waiting";
  if (ev.type === "scan_started") return `Scan started (${ev.scan_id?.slice(0, 8)}…)`;
  if (ev.type === "phase") return `Phase ${ev.phase}: ${ev.status}`;
  if (ev.type === "semantic_started") return "Semantic analysis — LLM traffic visible in LangSmith / Helicone";
  if (ev.type === "llm_step") {
    const bits = [ev.step, ev.phase, ev.note].filter(Boolean);
    return `LLM: ${bits.join(" · ")}`;
  }
  if (ev.type === "scan_complete") return `Complete (${ev.record?.status || "done"})`;
  if (ev.type === "scan_failed") return `Failed: ${ev.error || "error"}`;
  if (ev.type === "trace_warning") return ev.message || "Trace warning";
  return ev.type || JSON.stringify(ev);
}

const STAKEHOLDER_IMPACT_MAP = {
  LLM01: {
    economic: "Fraudulent or unauthorized actions can trigger incident response costs, legal review, and downtime.",
    reputational: "Publicized model abuse can reduce customer trust in AI-enabled workflows.",
  },
  LLM02: {
    economic: "Sensitive data leakage can lead to regulatory penalties, breach remediation spend, and contract risk.",
    reputational: "Loss of confidence from clients and partners after exposure of confidential information.",
  },
  LLM03: {
    economic: "Compromised dependencies can create broad operational disruption and expensive emergency patch cycles.",
    reputational: "Perception of weak vendor governance may impact enterprise deal velocity.",
  },
  LLM04: {
    economic: "Poisoned data can degrade decisions, increasing error rates and avoidable business losses.",
    reputational: "Stakeholders may question output reliability and oversight quality.",
  },
  LLM05: {
    economic: "Unsafe downstream actions can create financial exposure through workflow corruption and remediation.",
    reputational: "Visible failures in customer-facing outputs can damage brand credibility.",
  },
  LLM06: {
    economic: "Over-privileged agent actions can cause direct loss through unauthorized transactions or changes.",
    reputational: "Perceived lack of control over automation can undermine executive and board confidence.",
  },
  LLM07: {
    economic: "Prompt leakage can reveal internal controls and increase attack success rates, raising security costs.",
    reputational: "Disclosure of internal AI logic may signal weak security architecture.",
  },
  LLM08: {
    economic: "RAG/vector weaknesses can produce costly misrouting, bad recommendations, and operational rework.",
    reputational: "Persistent retrieval errors can erode confidence in product quality.",
  },
  LLM09: {
    economic: "Misinformation can drive poor business decisions, complaints, and avoidable support costs.",
    reputational: "Incorrect outputs in market-facing channels can weaken brand authority.",
  },
  LLM10: {
    economic: "Unbounded usage can inflate model spend and infrastructure bills unexpectedly.",
    reputational: "Uncontrolled cost spikes can raise concerns about governance maturity.",
  },
};

function stakeholderSummary(finding) {
  const key = String(finding?.owasp_id || "").toUpperCase();
  const impacts = STAKEHOLDER_IMPACT_MAP[key] || {
    economic: "Potential for unplanned security and operational costs.",
    reputational: "Potential erosion of customer and partner trust.",
  };
  const confidence = Number(finding?.confidence || 0);
  const severity = confidence >= 0.8 ? "High" : confidence >= 0.55 ? "Medium" : "Low";
  return {
    key,
    title: OWASP_LLM_TITLES[key] || finding?.title || "Business risk",
    severity,
    economic: impacts.economic,
    reputational: impacts.reputational,
  };
}

function riskLevelColor(level) {
  if (level === "high") return "bg-red-500/90";
  if (level === "medium") return "bg-ig-warn/90";
  return "bg-emerald-500/70";
}

function barWidth(level) {
  if (level === "high") return "w-[92%]";
  if (level === "medium") return "w-[55%]";
  return "w-[30%]";
}

const RECENT_SCAN_LIMIT = 5;
const LIVE_PHASE_ORDER = [
  "ingestion",
  "static_analysis",
  "graph_storage",
  "semantic_analysis",
  "taxonomy",
  "sandbox",
  "persist",
];

function isGithubRepoTarget(value) {
  const raw = String(value || "").trim();
  return /^(https?:\/\/)?(www\.)?github\.com\/[^/\s]+\/[^/\s]+\/?$/i.test(raw);
}

function computeLiveProgress(liveEvents) {
  const completed = new Set();
  let started = false;
  let finished = false;
  let failed = false;
  for (const row of liveEvents) {
    const ev = row.ev || {};
    if (ev.type === "scan_started") started = true;
    if (ev.type === "phase" && (ev.status === "complete" || ev.status === "skipped")) completed.add(ev.phase);
    if (ev.type === "scan_complete") finished = true;
    if (ev.type === "scan_failed" || (ev.type === "phase" && ev.status === "failed")) failed = true;
  }
  if (finished && !failed) return 100;
  const base = started ? 8 : 0;
  const perPhase = Math.round((90 - base) / LIVE_PHASE_ORDER.length);
  const doneCount = LIVE_PHASE_ORDER.filter((p) => completed.has(p)).length;
  const pct = Math.min(98, base + doneCount * perPhase + (failed ? 0 : 2));
  return Math.max(0, pct);
}

export default function Dashboard() {
  const { theme, setTheme } = useTheme();
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [reportPayload, setReportPayload] = useState(null);
  const [topology, setTopology] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailsLoading, setDetailsLoading] = useState(false);
  const [err, setErr] = useState("");
  const [target, setTarget] = useState("./demo/sample_skill.md");
  const [inputMode, setInputMode] = useState("github");
  const [isScanning, setIsScanning] = useState(false);
  const [forceRescan, setForceRescan] = useState(false);
  const scanAbortRef = useRef(null);
  const scanInFlightRef = useRef(false);
  const [tab, setTab] = useState("nutrition");
  const [selectedOwaspId, setSelectedOwaspId] = useState("LLM01");
  const [audience, setAudience] = useState("technical");
  const [exportType, setExportType] = useState("html");
  const [liveEvents, setLiveEvents] = useState([]);
  const [streamTelemetry, setStreamTelemetry] = useState(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [showLiveStatus, setShowLiveStatus] = useState(true);
  const [graphFilters, setGraphFilters] = useState({
    showTests: false,
    highRiskOnly: false,
    collapseModules: true,
    astDebugMode: false,
    depth: 4,
    limit: 500,
  });

  const loadScans = async (preferScanId = null) => {
    setErr("");
    setLoading(true);
    try {
      const data = await listScans();
      const rows = data.scans || [];
      setScans(rows);
      const urlScan = searchParams.get("scan");
      const nextId =
        (preferScanId && rows.some((r) => r.scan_id === preferScanId) && preferScanId) ||
        (urlScan && rows.some((r) => r.scan_id === urlScan) && urlScan) ||
        rows[0]?.scan_id ||
        "";
      setSelectedScanId(nextId);
      if (preferScanId && rows.some((r) => r.scan_id === preferScanId)) {
        setSearchParams({ scan: preferScanId }, { replace: true });
      }
    } catch (e) {
      setErr(e.message || String(e));
      setScans([]);
      setSelectedScanId("");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadScans();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- initial load only; URL handled in loadScans
  }, []);

  useEffect(() => {
    const id = searchParams.get("scan");
    if (!id || !scans.length) return;
    if (!scans.some((s) => s.scan_id === id)) return;
    if (id !== selectedScanId) setSelectedScanId(id);
  }, [searchParams, scans, selectedScanId]);

  useEffect(() => {
    if (!selectedScanId) {
      setReportPayload(null);
      setTopology(null);
      return;
    }
    let cancelled = false;
    setDetailsLoading(true);
    (async () => {
      try {
        const [rep, topo] = await Promise.all([
          getReport(selectedScanId),
          getTopology(selectedScanId, {
            includeTests: graphFilters.showTests,
            onlyPaths: graphFilters.highRiskOnly,
            depth: graphFilters.depth,
            limit: graphFilters.astDebugMode ? 300 : graphFilters.limit,
            debug: graphFilters.astDebugMode,
          }),
        ]);
        if (cancelled) return;
        setReportPayload(rep);
        setTopology(topo);
      } catch (e) {
        if (!cancelled) {
          setErr(e.message || String(e));
          setReportPayload(null);
          setTopology(null);
        }
      } finally {
        if (!cancelled) setDetailsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selectedScanId, graphFilters]);

  useEffect(() => {
    return () => {
      scanAbortRef.current?.abort();
    };
  }, []);

  const onSubmit = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (scanInFlightRef.current) return;
    if (inputMode === "github" && !isGithubRepoTarget(target)) {
      setErr("Please paste a valid GitHub repository URL (e.g. https://github.com/org/repo).");
      return;
    }
    scanInFlightRef.current = true;
    scanAbortRef.current?.abort();
    const ac = new AbortController();
    scanAbortRef.current = ac;
    setIsScanning(true);
    setIsStreaming(true);
    setLiveEvents([]);
    setStreamTelemetry(null);
    setErr("");
    const pushEvent = (ev) => {
      setLiveEvents((prev) => [...prev.slice(-150), { t: Date.now(), ev }]);
      if (ev.telemetry) setStreamTelemetry(ev.telemetry);
      if (ev.type === "scan_complete" && ev.record?.scan_id) {
        void loadScans(ev.record.scan_id);
      }
      if (ev.type === "scan_failed") {
        setErr(ev.error || "Scan failed");
      }
      if (ev.type === "scan_complete" && ev.record?.status === "failed") {
        setErr(ev.record.error || "Scan completed with errors");
      }
    };
    try {
      if (inputMode === "folder") {
        const folderInput = document.getElementById("folder-input");
        const mdFileInput = document.getElementById("md-file-input");
        const folderFiles = folderInput?.files;
        const mdFiles = mdFileInput?.files;
        const files = folderFiles?.length ? folderFiles : mdFiles;
        if (!files || files.length === 0) {
          throw new Error("Please upload a repository folder or a single .md file.");
        }
        await createScanStreamFromFolder({ files, onEvent: pushEvent, signal: ac.signal, forceRescan });
      } else {
        await createScanStream({ target: target.trim(), onEvent: pushEvent, signal: ac.signal, forceRescan });
      }
    } catch (e2) {
      if (e2?.name !== "AbortError") {
        setErr(e2.message || String(e2));
      }
    } finally {
      if (scanAbortRef.current === ac) scanAbortRef.current = null;
      scanInFlightRef.current = false;
      setIsScanning(false);
      setIsStreaming(false);
    }
  };

  const report = reportPayload?.report;
  const sources = reportPayload?.sources || [];
  const findings = report?.findings || [];
  const categories = report?.category_scores || [];
  const riskScore = report?.risk_score ?? "—";
  const riskLabel = report?.risk_label ?? "Unknown";
  const annotations = report?.meta?.annotated_code || [];

  const activeScan = useMemo(() => scans.find((s) => s.scan_id === selectedScanId), [scans, selectedScanId]);
  const recentScans = useMemo(() => scans.slice(0, RECENT_SCAN_LIMIT), [scans]);
  const hasMoreScans = scans.length > RECENT_SCAN_LIMIT;
  const stakeholderFindings = useMemo(
    () =>
      [...findings]
        .sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0))
        .slice(0, 5)
        .map(stakeholderSummary),
    [findings],
  );
  const liveProgress = useMemo(() => computeLiveProgress(liveEvents), [liveEvents]);
  const findingsByOwasp = useMemo(() => {
    const bucket = {};
    for (const fid of OWASP_LLM_ORDER) bucket[fid] = [];
    for (const f of findings) {
      const id = String(f.owasp_id || "").toUpperCase();
      if (bucket[id]) bucket[id].push(f);
    }
    return bucket;
  }, [findings]);
  const activeOwaspFindings = findingsByOwasp[selectedOwaspId] || [];
  const violatedOwasp = useMemo(
    () =>
      OWASP_LLM_ORDER.filter((id) => (findingsByOwasp[id] || []).length > 0).map((id) => ({
        id,
        label: renderOwaspLlmLabel(id),
        count: findingsByOwasp[id].length,
      })),
    [findingsByOwasp],
  );

  useEffect(() => {
    if (findingsByOwasp[selectedOwaspId]?.length) return;
    const firstWithFinding = OWASP_LLM_ORDER.find((id) => (findingsByOwasp[id] || []).length > 0) || "LLM01";
    if (firstWithFinding !== selectedOwaspId) setSelectedOwaspId(firstWithFinding);
  }, [findingsByOwasp, selectedOwaspId]);

  const onExport = () => {
    if (!report) return;
    const payload = {
      scan_id: selectedScanId,
      target: activeScan?.target,
      report,
      topology,
      exported_at: new Date().toISOString(),
    };
    const pretty = JSON.stringify(payload, null, 2);
    const executiveItems = stakeholderFindings
      .map(
        (f) =>
          `<li><strong>${f.key ? `${f.key}: ${f.title}` : f.title}</strong> (${f.severity} exposure)<br>` +
          `<strong>Economic effect:</strong> ${f.economic}<br>` +
          `<strong>Reputational effect:</strong> ${f.reputational}</li>`,
      )
      .join("");
    const executiveSection = `
      <h2>Executive Risk Packet</h2>
      <p><strong>Overall risk:</strong> ${riskScore} / 10 (${riskLabel})</p>
      <p><strong>Scan target:</strong> ${(activeScan?.target || "N/A").replace(/[<>&]/g, (m) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[m]))}</p>
      <h3>Top Business Risks</h3>
      ${
        executiveItems
          ? `<ol>${executiveItems}</ol>`
          : "<p>No findings were flagged for business-impact reporting in this scan.</p>"
      }
    `;
    if (exportType === "html") {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>IntentGuard Report</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:24px;line-height:1.5;max-width:1000px}h1,h2,h3{margin:0 0 10px}ol{padding-left:22px}li{margin-bottom:10px}pre{background:#f3f4f6;padding:16px;border-radius:8px;white-space:pre-wrap;border:1px solid #e5e7eb}</style></head><body><h1>IntentGuard Scan Report</h1>${executiveSection}<h2>Technical Appendix (JSON)</h2><pre>${pretty.replace(/[<>&]/g, (m) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[m]))}</pre></body></html>`;
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `intentguard-${selectedScanId}.html`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }
    const win = window.open("", "_blank");
    if (!win) return;
    win.document.write(
      `<html><head><title>IntentGuard PDF Export</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:20px;line-height:1.45}h1,h2,h3{margin:0 0 10px}ol{padding-left:20px}li{margin-bottom:10px}pre{white-space:pre-wrap;background:#f4f4f4;padding:12px;border-radius:6px;border:1px solid #e5e7eb}</style></head><body><h1>IntentGuard Scan ${selectedScanId}</h1>${executiveSection}<h2>Technical Appendix (JSON)</h2><pre>${pretty.replace(/[<>&]/g, (m) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[m]))}</pre><script>window.print();</script></body></html>`,
    );
    win.document.close();
  };

  return (
    <div className="flex min-h-[calc(100vh-56px)]">
      <aside className="hidden h-full min-h-0 w-[260px] shrink-0 flex-col border-r border-ig-border bg-ig-panel xl:flex">
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          <nav className="border-b border-ig-border px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Scanned runs</h2>
            <p className="mt-1 text-[10px] text-ig-muted">Showing {recentScans.length} latest</p>
            <ul className="mt-2 space-y-1">
              {recentScans.map((s) => (
                <li key={s.scan_id}>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedScanId(s.scan_id);
                      setSearchParams({ scan: s.scan_id });
                    }}
                    className={`w-full rounded-md px-2 py-1.5 text-left text-sm ${
                      selectedScanId === s.scan_id ? "bg-slate-800/80 text-white" : "text-slate-300 hover:bg-slate-800/40"
                    }`}
                  >
                    <div className="truncate font-mono text-xs">{s.scan_id.slice(0, 12)}...</div>
                    <div className="truncate text-[11px] text-ig-muted">{s.target}</div>
                  </button>
                </li>
              ))}
            </ul>
            <Link
              to="/history"
              className="mt-2 flex w-full items-center justify-center rounded-md border border-ig-border bg-ig-bg/80 px-2 py-2 text-center text-xs font-semibold text-ig-accent hover:bg-slate-800/50"
            >
              {hasMoreScans
                ? `Scan history · ${scans.length - RECENT_SCAN_LIMIT} older run${scans.length - RECENT_SCAN_LIMIT === 1 ? "" : "s"}`
                : "Scan history · all runs"}
            </Link>
            {!recentScans.length && !loading && (
              <p className="mt-2 text-xs text-ig-muted">No runs yet. Start a scan from the main panel.</p>
            )}
          </nav>
          <section className="border-b border-ig-border px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Sources</h2>
            <ul className="mt-2 space-y-2 text-sm">
              {sources.map((src, i) => (
                <li key={`${src.kind}-${i}`} className="flex items-center gap-2 text-slate-300">
                  <span className="text-ig-muted">{String(src.kind || "src").toUpperCase()}</span>
                  <span className="truncate">{src.label}</span>
                </li>
              ))}
              {!sources.length && <li className="text-xs text-ig-muted">Select a scan to view sources.</li>}
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
                      setAudience("technical");
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
        </div>
        <div className="shrink-0 border-t border-ig-border bg-ig-panel px-3 py-3">
          <button
            type="button"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            className="w-full rounded-lg border border-ig-border bg-ig-bg px-3 py-2 text-xs font-semibold text-slate-200 shadow-sm hover:bg-slate-800/80"
          >
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </button>
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col">
        <div className="border-b border-ig-border bg-ig-panel px-6 py-4">
          <form onSubmit={onSubmit} className="grid gap-3 lg:grid-cols-[1fr_auto_auto]">
            <div>
              <div className="inline-flex rounded-lg border border-ig-border bg-ig-bg p-1 text-xs">
                <button
                  type="button"
                  onClick={() => setInputMode("github")}
                  className={`rounded px-3 py-1 font-medium ${
                    inputMode === "github" ? "bg-ig-accent text-slate-900" : "text-slate-300"
                  }`}
                >
                  GitHub link
                </button>
                <button
                  type="button"
                  onClick={() => setInputMode("folder")}
                  className={`rounded px-3 py-1 font-medium ${
                    inputMode === "folder" ? "bg-ig-accent text-slate-900" : "text-slate-300"
                  }`}
                >
                  Upload repo folder / .md
                </button>
              </div>
              {inputMode === "github" ? (
                <label className="mt-2 block">
                  <span className="text-xs text-ig-muted">Scan target (GitHub repo URL only)</span>
                  <input
                    className="mt-1 w-full rounded-lg border border-ig-border bg-ig-bg px-3 py-2 font-mono text-sm text-slate-100 outline-none focus:border-ig-accent"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="https://github.com/org/repo"
                  />
                </label>
              ) : (
                <div className="mt-2 grid gap-2">
                  <label className="block">
                    <span className="text-xs text-ig-muted">Upload repository folder</span>
                    <input
                      id="folder-input"
                      name="files"
                      type="file"
                      multiple
                      webkitdirectory="true"
                      directory=""
                      className="mt-1 block w-full text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-1.5 file:text-white"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs text-ig-muted">Or upload a single Markdown file (.md)</span>
                    <input
                      id="md-file-input"
                      name="files"
                      type="file"
                      accept=".md,.markdown,text/markdown"
                      className="mt-1 block w-full text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-700 file:px-3 file:py-1.5 file:text-white"
                    />
                  </label>
                </div>
              )}
            </div>
            <label className="self-end inline-flex items-center gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                checked={forceRescan}
                onChange={(e) => setForceRescan(e.target.checked)}
                disabled={isScanning}
              />
              Force Rescan (Bypass Cache)
            </label>
            <button
              type="submit"
              disabled={isScanning}
              className="self-end rounded-lg bg-ig-accent px-5 py-2 text-sm font-semibold text-slate-900 hover:brightness-110 disabled:opacity-50"
            >
              {isScanning ? "Scanning…" : "Run scan"}
            </button>
            <div className="self-end inline-flex items-center gap-2">
              <select
                value={exportType}
                onChange={(e) => setExportType(e.target.value)}
                className="rounded border border-ig-border bg-ig-bg px-2 py-2 text-xs text-slate-200"
              >
                <option value="html">HTML</option>
                <option value="pdf">PDF</option>
              </select>
              <button
                type="button"
                onClick={onExport}
                disabled={!report}
                className="rounded border border-ig-border bg-ig-bg px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:opacity-40"
              >
                Export report
              </button>
            </div>
          </form>
          <div className="mt-3 inline-flex rounded-lg border border-ig-border bg-ig-bg p-1 text-xs">
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
              onClick={() => setAudience("technical")}
              className={`rounded px-3 py-1 font-medium ${
                audience === "technical" ? "bg-ig-accent text-slate-900" : "text-slate-300 hover:text-white"
              }`}
            >
              Technical view
            </button>
          </div>
          {err && <p className="mt-2 text-sm text-ig-danger">{err}</p>}
          {(isStreaming || liveEvents.length > 0) && (
            <div className="mt-4 rounded-lg border border-ig-border bg-ig-bg/60 px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <div className="text-xs font-semibold uppercase tracking-wide text-ig-muted">Live scan status</div>
                <button
                  type="button"
                  onClick={() => setShowLiveStatus((v) => !v)}
                  className="rounded border border-ig-border bg-ig-panel px-2 py-1 text-[11px] font-semibold text-slate-200 hover:bg-slate-800"
                >
                  {showLiveStatus ? "Hide" : "Show"}
                </button>
              </div>
              <div className="mt-2">
                <div className="flex items-center justify-between text-[11px] text-slate-300">
                  <span>{isStreaming ? "Scan in progress…" : "Latest stream snapshot"}</span>
                  <span className="font-mono">{liveProgress}%</span>
                </div>
                <div className="mt-1 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full bg-ig-accent transition-all duration-300" style={{ width: `${liveProgress}%` }} />
                </div>
              </div>
              {showLiveStatus && (
                <>
                  <p className="mt-2 text-[11px] text-slate-400">
                    Phases and LLM steps stream while the scan runs. Open observability in another tab to watch traces
                    appear in real time.
                  </p>
                  {streamTelemetry && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {streamTelemetry.langsmith?.enabled && streamTelemetry.langsmith?.deep_link && (
                        <a
                          href={streamTelemetry.langsmith.deep_link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="rounded border border-ig-border bg-ig-panel px-2 py-1 text-[11px] font-semibold text-ig-accent hover:underline"
                        >
                          LangSmith (live)
                        </a>
                      )}
                      {streamTelemetry.helicone?.enabled && streamTelemetry.helicone?.deep_link && (
                        <a
                          href={streamTelemetry.helicone.deep_link}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="rounded border border-ig-border bg-ig-panel px-2 py-1 text-[11px] font-semibold text-ig-accent hover:underline"
                        >
                          Helicone (live)
                        </a>
                      )}
                    </div>
                  )}
                  <ul className="mt-2 max-h-40 overflow-y-auto text-[11px] leading-snug text-slate-300">
                    {liveEvents.map((row, i) => (
                      <li key={`${row.t}-${i}`} className="border-b border-ig-border/40 py-1 font-mono">
                        <span className="text-ig-muted">{new Date(row.t).toLocaleTimeString()}</span>{" "}
                        {formatSseEvent(row.ev)}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}
        </div>

        {audience === "technical" && (
          <div className="border-b border-ig-border px-6">
            <div className="flex flex-wrap gap-1">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTab(t.id)}
                  className={`border-b-2 px-3 py-2 text-sm font-medium ${
                    tab === t.id ? "border-ig-accent text-ig-accent" : "border-transparent text-slate-400"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="px-6 py-6">
          {loading && <p className="text-sm text-ig-muted">Loading scans…</p>}
          {!loading && !scans.length && <p className="text-sm text-ig-muted">No scans yet. Run one above.</p>}
          {!loading && selectedScanId && (
            <div className="space-y-4">
              <div>
                <h1 className="text-xl font-semibold text-white">{activeScan?.target || "Selected scan"}</h1>
                <p className="mt-1 text-xs text-ig-muted font-mono">{selectedScanId}</p>
              </div>
              {detailsLoading ? (
                <p className="text-sm text-ig-muted">Loading scan details…</p>
              ) : (
                <>
                  {audience === "executive" && (
                    <div className="space-y-4">
                      <section className="rounded-lg border border-ig-border bg-ig-panel p-4">
                        <h3 className="text-sm font-semibold text-white">Plain-language summary</h3>
                        <p className="mt-2 text-sm text-slate-300">
                          {report?.intent_summary || "No summary available for this scan."}
                        </p>
                      </section>
                      <section className="rounded-lg border border-ig-border bg-ig-panel p-4">
                        <h3 className="text-sm font-semibold text-white">Top business risks for stakeholders</h3>
                        {!stakeholderFindings.length ? (
                          <p className="mt-2 text-sm text-ig-muted">No findings available.</p>
                        ) : (
                          <ul className="mt-3 space-y-3">
                            {stakeholderFindings.map((f, idx) => (
                              <li key={`${f.key}-${idx}`} className="rounded border border-ig-border bg-ig-bg/60 p-3">
                                <div className="flex items-center justify-between gap-3">
                                  <div className="font-semibold text-slate-200">
                                    {f.key ? `${f.key}: ${f.title}` : f.title}
                                  </div>
                                  <span
                                    className={`rounded px-2 py-0.5 text-[11px] font-semibold ${
                                      f.severity === "High"
                                        ? "bg-red-900/40 text-red-200"
                                        : f.severity === "Medium"
                                          ? "bg-amber-900/40 text-amber-200"
                                          : "bg-emerald-900/40 text-emerald-200"
                                    }`}
                                  >
                                    {f.severity} exposure
                                  </span>
                                </div>
                                <p className="mt-2 text-sm text-slate-300">
                                  <span className="font-semibold text-slate-200">Economic effect:</span> {f.economic}
                                </p>
                                <p className="mt-1 text-sm text-slate-300">
                                  <span className="font-semibold text-slate-200">Reputational effect:</span>{" "}
                                  {f.reputational}
                                </p>
                              </li>
                            ))}
                          </ul>
                        )}
                      </section>
                    </div>
                  )}
                  {audience === "technical" && tab === "nutrition" && <NutritionLabel report={report} sources={sources} />}
                  {audience === "technical" && tab === "graph" && (
                    <TopologyGraph topology={topology} graphFilters={graphFilters} onChangeGraphFilters={setGraphFilters} />
                  )}
                  {audience === "technical" && tab === "owasp" && (
                    <div className="space-y-4">
                      <div className="rounded-lg border border-ig-border bg-ig-panel p-4">
                        <h3 className="text-sm font-semibold text-white">OWASP mapping</h3>
                        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
                          {OWASP_LLM_ORDER.map((id) => {
                            const count = findingsByOwasp[id]?.length || 0;
                            const active = selectedOwaspId === id;
                            const risky = count > 0;
                            return (
                              <button
                                key={id}
                                type="button"
                                onClick={() => setSelectedOwaspId(id)}
                                className={`rounded-xl border px-3 py-3 text-left transition ${
                                  active
                                    ? "border-ig-accent bg-emerald-900/20"
                                    : risky
                                      ? "border-red-500/70 bg-red-950/35"
                                      : "border-ig-border bg-ig-bg/40 hover:bg-slate-800/40"
                                }`}
                              >
                                <div className="font-mono text-xs font-semibold text-slate-200">{id}</div>
                                <div className="mt-1 text-xs text-slate-300">{OWASP_LLM_TITLES[id]}</div>
                                <div className={`mt-2 text-[11px] ${risky ? "text-red-300" : "text-ig-muted"}`}>
                                  {count ? `${count} finding${count === 1 ? "" : "s"}` : "No findings"}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      <div className="rounded-lg border border-ig-border bg-ig-panel p-4">
                        <h3 className="text-sm font-semibold text-white">
                          {selectedOwaspId}: {OWASP_LLM_TITLES[selectedOwaspId]}
                        </h3>
                        {!activeOwaspFindings.length ? (
                          <p className="mt-3 text-sm text-ig-muted">No findings mapped to this OWASP category in this scan.</p>
                        ) : (
                          <ul className="mt-3 space-y-3">
                            {activeOwaspFindings.map((f) => {
                              const level = f.confidence >= 0.8 ? "High Risk" : f.confidence >= 0.55 ? "Medium Risk" : "Low Risk";
                              const badgeCls =
                                level === "High Risk"
                                  ? "border-red-500/70 bg-red-950/50 text-red-200"
                                  : level === "Medium Risk"
                                    ? "border-amber-500/60 bg-amber-950/40 text-amber-200"
                                    : "border-emerald-500/60 bg-emerald-950/40 text-emerald-200";
                              return (
                                <li key={f.id} className="rounded-lg border border-ig-border bg-ig-bg/50 p-4">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <h4 className="text-base font-semibold text-slate-100">{f.title}</h4>
                                    <span className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${badgeCls}`}>
                                      {level}
                                    </span>
                                  </div>
                                  <p className="mt-2 text-sm text-slate-300">{f.description}</p>
                                  {f.affected_path && (
                                    <div className="mt-3 rounded-md border border-ig-border bg-[#0b111b] px-3 py-2 text-sm font-mono text-emerald-300">
                                      Affected path: {f.affected_path}
                                    </div>
                                  )}
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </div>
                    </div>
                  )}
                  {audience === "technical" && tab === "annotated" && (
                    <div className="rounded-lg border border-ig-border bg-ig-panel p-4">
                      <h3 className="text-sm font-semibold text-white">Annotated code</h3>
                      {!annotations.length ? (
                        <p className="mt-2 text-sm text-ig-muted">No semantic annotations available for this scan.</p>
                      ) : (
                        <div className="overflow-hidden rounded-lg border border-ig-border bg-[#05070a] font-mono text-[13px]">
                          <div className="grid grid-cols-[220px_1fr_220px_90px] border-b border-ig-border bg-ig-panel px-3 py-2 text-[11px] text-ig-muted">
                            <span>File</span>
                            <span>Evidence</span>
                            <span>Annotation</span>
                            <span>Severity</span>
                          </div>
                          <div className="max-h-[420px] overflow-y-auto">
                            {annotations.map((a, i) => (
                              <div
                                key={`${a.file || "unknown"}-${a.annotation}-${i}`}
                                className="grid grid-cols-[220px_1fr_220px_90px] border-b border-ig-border/40 px-3 py-2 text-xs text-slate-200"
                              >
                                <span className="truncate text-slate-400">{a.file || "unknown"}</span>
                                <code className="pr-3 text-slate-100">{a.code}</code>
                                <span className="pr-3 text-slate-300">{a.annotation}</span>
                                <span
                                  className={`font-semibold uppercase ${
                                    a.severity === "high"
                                      ? "text-red-300"
                                      : a.severity === "medium"
                                        ? "text-amber-300"
                                        : "text-emerald-300"
                                  }`}
                                >
                                  {a.severity}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </main>

      <aside className="hidden w-[300px] shrink-0 flex-col border-l border-ig-border bg-ig-panel px-4 py-5 lg:flex">
        <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">Risk score</h2>
        <div className="mt-2 text-3xl font-bold text-red-200">
          {riskScore}
          <span className="text-lg font-normal text-ig-muted"> / 10</span>
        </div>
        <p className="text-sm font-semibold text-red-300/90">{riskLabel}</p>

        <h3 className="mt-6 text-[10px] font-bold uppercase tracking-wider text-ig-muted">Risk categories</h3>
        <ul className="mt-3 space-y-3">
          {categories.map((c, i) => (
            <li key={`${c.category}-${i}`}>
              <div className="mb-1 text-[11px] text-slate-400">{c.category}</div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div className={`h-full ${barWidth(c.level)} ${riskLevelColor(c.level)}`} />
              </div>
            </li>
          ))}
          {!categories.length && <li className="text-xs text-ig-muted">No category scores in this report.</li>}
        </ul>

        <h3 className="mt-6 text-[10px] font-bold uppercase tracking-wider text-ig-muted">
          OWASP violations ({violatedOwasp.length})
        </h3>
        <div className="mt-2 flex flex-wrap gap-2 pr-1 text-xs">
          {violatedOwasp.map((v) => (
            <button
              key={v.id}
              type="button"
              onClick={() => {
                setAudience("technical");
                setTab("owasp");
                setSelectedOwaspId(v.id);
              }}
              className="rounded-md border border-ig-border bg-ig-bg/50 px-2 py-1.5 font-mono text-[10px] text-ig-accent hover:bg-slate-800/60"
              title={`Open ${v.label} mapping (${v.count} findings)`}
            >
              {v.label}
            </button>
          ))}
          {!violatedOwasp.length && <div className="text-ig-muted">No OWASP violations.</div>}
        </div>
      </aside>
    </div>
  );
}
