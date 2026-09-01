import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import NutritionLabel from "../components/NutritionLabel";
import TopologyGraph from "../components/TopologyGraph";
import WorkflowGraph from "../components/WorkflowGraph";
import { getReport, getTopology } from "../utils/api";

export default function ScanDetails() {
  const { scanId } = useParams();
  const [reportPayload, setReportPayload] = useState(null);
  const [topology, setTopology] = useState(null);
  const [err, setErr] = useState("");
  const [graphView, setGraphView] = useState("workflow");
  const [graphFilters, setGraphFilters] = useState({
    showTests: false,
    highRiskOnly: false,
    collapseModules: true,
    astDebugMode: false,
  });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setErr("");
      try {
        const rep = await getReport(scanId);
        if (cancelled) return;
        setReportPayload(rep);
      } catch (e) {
        if (!cancelled) setErr(e.message || String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const topo = await getTopology(scanId, {
          includeTests: graphFilters.showTests,
          onlyPaths: graphFilters.highRiskOnly,
          limit: graphFilters.astDebugMode ? 300 : 500,
          debug: graphFilters.astDebugMode,
        });
        if (cancelled) return;
        setTopology(topo);
      } catch (e) {
        if (!cancelled) setErr(e.message || String(e));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId, graphFilters]);

  if (err) {
    return (
      <div>
        <Link to="/" className="text-sm text-ig-accent">
          ← Back
        </Link>
        <p className="mt-4 text-ig-danger">{err}</p>
      </div>
    );
  }

  const report = reportPayload?.report;
  const sources = reportPayload?.sources;

  return (
    <div className="space-y-6">
      <Link to="/" className="text-sm text-ig-accent hover:underline">
        ← All scans
      </Link>
      <h1 className="text-xl font-semibold text-white">Scan {scanId}</h1>

      <div className="grid gap-8 lg:grid-cols-2">
        <div>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-ig-muted">Nutrition label</h2>
          <NutritionLabel report={report} sources={sources} />
        </div>
        <div>
          <div className="mb-3 flex items-center gap-1 rounded-lg border border-ig-border bg-ig-panel p-1 text-xs">
            {[
              ["workflow", "What it does"],
              ["topology", "Code topology"],
            ].map(([key, caption]) => (
              <button
                key={key}
                type="button"
                onClick={() => setGraphView(key)}
                className={`rounded-md px-3 py-1.5 font-semibold transition ${
                  graphView === key ? "bg-ig-accent/20 text-ig-accent" : "text-ig-muted hover:text-slate-200"
                }`}
              >
                {caption}
              </button>
            ))}
          </div>
          {graphView === "workflow" ? (
            <WorkflowGraph workflow={report?.workflow} />
          ) : (
            <TopologyGraph topology={topology} graphFilters={graphFilters} onChangeGraphFilters={setGraphFilters} />
          )}
        </div>
      </div>
    </div>
  );
}
