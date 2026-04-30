import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTheme } from "../ThemeContext";
import { listScans } from "../utils/api";

export default function History() {
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setErr("");
      setLoading(true);
      try {
        const data = await listScans();
        if (!cancelled) setScans(data.scans || []);
      } catch (e) {
        if (!cancelled) setErr(e.message || String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const openScan = (scanId) => {
    navigate(`/?scan=${encodeURIComponent(scanId)}`);
  };

  return (
    <div className="flex h-full min-h-0 overflow-hidden">
      <aside className="hidden h-full min-h-0 w-[260px] shrink-0 flex-col border-r border-ig-border bg-ig-panel xl:flex">
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          <div className="border-b border-ig-border px-4 py-3">
            <Link to="/" className="text-xs font-semibold text-ig-accent hover:underline">
              ← Dashboard
            </Link>
            <h1 className="mt-3 text-sm font-bold text-white">Scan history</h1>
            <p className="mt-1 text-[11px] leading-snug text-ig-muted">Open any past run in the main dashboard.</p>
          </div>
          <nav className="px-4 py-3">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-ig-muted">All scanned runs</h2>
            {loading && <p className="mt-2 text-xs text-ig-muted">Loading…</p>}
            {err && <p className="mt-2 text-xs text-ig-danger">{err}</p>}
            {!loading && !err && !scans.length && <p className="mt-2 text-xs text-ig-muted">No scans yet.</p>}
            <ul className="mt-2 space-y-1">
              {scans.map((s) => (
                <li key={s.scan_id}>
                  <button
                    type="button"
                    onClick={() => openScan(s.scan_id)}
                    className="w-full rounded-md px-2 py-1.5 text-left text-sm text-slate-300 hover:bg-slate-800/40"
                  >
                    <div className="truncate font-mono text-xs">{s.scan_id.slice(0, 14)}…</div>
                    <div className="truncate text-[11px] text-ig-muted">{s.target}</div>
                    {s.created_at && (
                      <div className="mt-0.5 text-[10px] text-slate-500">{new Date(s.created_at).toLocaleString()}</div>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          </nav>
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

      <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <div className="border-b border-ig-border bg-ig-panel px-6 py-4 xl:hidden">
          <Link to="/" className="text-xs font-semibold text-ig-accent hover:underline">
            ← Dashboard
          </Link>
          <h1 className="mt-2 text-lg font-bold text-white">Scan history</h1>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {loading && <p className="text-sm text-ig-muted">Loading scans…</p>}
          {err && <p className="text-sm text-ig-danger">{err}</p>}
          {!loading && !err && (
            <div className="rounded-lg border border-ig-border bg-ig-panel">
              <div className="hidden border-b border-ig-border px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-ig-muted xl:grid xl:grid-cols-[minmax(0,1.2fr)_minmax(0,2fr)_140px_100px] xl:gap-2">
                <span>Scan ID</span>
                <span>Target</span>
                <span>Created</span>
                <span className="text-right">Open</span>
              </div>
              <ul className="divide-y divide-ig-border">
                {scans.map((s) => (
                  <li
                    key={s.scan_id}
                    className="flex flex-col gap-2 px-4 py-3 text-sm xl:grid xl:grid-cols-[minmax(0,1.2fr)_minmax(0,2fr)_140px_100px] xl:items-center xl:gap-2"
                  >
                    <span className="font-mono text-xs text-slate-200">{s.scan_id}</span>
                    <span className="truncate text-slate-300">{s.target}</span>
                    <span className="text-xs text-ig-muted">
                      {s.created_at ? new Date(s.created_at).toLocaleString() : "—"}
                    </span>
                    <div className="xl:text-right">
                      <button
                        type="button"
                        onClick={() => openScan(s.scan_id)}
                        className="rounded-md border border-ig-border bg-ig-bg px-3 py-1.5 text-xs font-semibold text-ig-accent hover:bg-slate-800/60"
                      >
                        Open in dashboard
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
              {!scans.length && <p className="px-4 py-8 text-center text-sm text-ig-muted">No scans recorded yet.</p>}
            </div>
          )}
        </div>
        <div className="border-t border-ig-border bg-ig-panel px-4 py-3 xl:hidden">
          <button
            type="button"
            onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
            className="w-full rounded-lg border border-ig-border bg-ig-bg px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800/80"
          >
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </button>
        </div>
      </main>
    </div>
  );
}
