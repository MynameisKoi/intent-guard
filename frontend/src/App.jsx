import { Link, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import ScanDetails from "./pages/ScanDetails";
import { ThemeProvider } from "./ThemeContext";

export default function App() {
  return (
    <ThemeProvider>
      <div className="min-h-screen overflow-x-hidden overflow-y-auto bg-ig-bg">
        <header className="border-b border-ig-border bg-ig-panel px-6 py-3">
          <div className="flex items-center justify-between">
            <Link to="/" className="text-lg font-bold text-ig-accent">
              IntentGuard
            </Link>
            <span className="text-xs text-ig-muted">Dashboard · Flask API</span>
          </div>
        </header>
        <main className="min-h-[calc(100vh-49px)] px-0 py-0">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/history" element={<History />} />
            <Route path="/scan/:scanId" element={<ScanDetails />} />
          </Routes>
        </main>
      </div>
    </ThemeProvider>
  );
}
