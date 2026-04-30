import { useEffect, useState } from "react";
import raw from "./data/scan-preview.json";
import { DashboardView } from "./components/DashboardView";
import { PipelineRunner } from "./components/PipelineRunner";
import type { PipelineInput } from "./pipeline/pipelineTypes";
import type { ScanPreview } from "./types";

const data = raw as ScanPreview;

export default function App() {
  const [view, setView] = useState<"runner" | "dashboard">("runner");
  const [scanContext, setScanContext] = useState<{ scanId: string; input: PipelineInput } | null>(null);
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    const stored = localStorage.getItem("intentguard-theme");
    return stored === "light" ? "light" : "dark";
  });

  useEffect(() => {
    document.documentElement.classList.toggle("theme-light", theme === "light");
    localStorage.setItem("intentguard-theme", theme);
  }, [theme]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

  if (view === "runner") {
    return (
      <div className="relative flex min-h-full flex-col bg-ig-bg">
        <button
          type="button"
          onClick={toggleTheme}
          className="fixed bottom-4 left-4 z-30 rounded-lg border border-ig-border bg-ig-panel px-3 py-1.5 text-xs font-semibold text-slate-200 shadow-lg hover:bg-slate-800"
        >
          {theme === "dark" ? "Light theme" : "Dark theme"}
        </button>
        <PipelineRunner
          fastMode={Boolean(import.meta.env.DEV)}
          onComplete={(r) => {
            setScanContext(r);
            setView("dashboard");
          }}
        />
        <footer className="border-t border-ig-border py-6 text-center">
          <button
            type="button"
            className="text-sm text-ig-accent hover:underline"
            onClick={() => {
              setScanContext(null);
              setView("dashboard");
            }}
          >
            Skip simulation · open static preview
          </button>
        </footer>
      </div>
    );
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={toggleTheme}
        className="fixed bottom-4 left-4 z-30 rounded-lg border border-ig-border bg-ig-panel px-3 py-1.5 text-xs font-semibold text-slate-200 shadow-lg hover:bg-slate-800"
      >
        {theme === "dark" ? "Light theme" : "Dark theme"}
      </button>
      <DashboardView
        data={data}
        scanContext={scanContext}
        headerMeta={
          scanContext
            ? {
                analysisProgress: 100,
                semanticStatus: "Pipeline complete — MongoDB report + Neo4j topology (mock data)",
              }
            : undefined
        }
        onNewMockScan={() => {
          setView("runner");
        }}
      />
    </div>
  );
}
