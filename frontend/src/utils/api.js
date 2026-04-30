const API = "/api";
const inflightGet = new Map();

function normalizeTarget(target) {
  const raw = String(target || "").trim();
  if (/^github\.com\/[^/]+\/[^/]+\/?$/i.test(raw)) {
    return `https://${raw}`;
  }
  return raw;
}

async function handle(res) {
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(text || res.statusText);
  }
  if (!res.ok) throw new Error(data.error || data.message || res.statusText);
  return data;
}

async function dedupedGetJson(url) {
  if (inflightGet.has(url)) return inflightGet.get(url);
  const p = (async () => {
    const res = await fetch(url);
    return handle(res);
  })();
  inflightGet.set(url, p);
  try {
    return await p;
  } finally {
    if (inflightGet.get(url) === p) inflightGet.delete(url);
  }
}

export async function listScans() {
  return dedupedGetJson(`${API}/scans`);
}

export async function createScan(target, dynamicLogs = null, forceRescan = false) {
  const normalizedTarget = normalizeTarget(target);
  const body = dynamicLogs ? { target: normalizedTarget, dynamic_logs: dynamicLogs } : { target: normalizedTarget };
  if (forceRescan) body.force_rescan = true;
  const res = await fetch(`${API}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handle(res);
}

function isTerminalScanEvent(data) {
  return data?.type === "scan_complete" || data?.type === "scan_failed";
}

/** Parse SSE frames from a fetch Response body (POST /api/scans/stream). */
export async function consumeScanSse(response, onEvent, opts = {}) {
  const { signal } = opts;
  const reader = response.body?.getReader();
  if (!reader) return;

  const decoder = new TextDecoder();
  let buffer = "";
  const releaseReader = () => reader.cancel().catch(() => {});

  const onAbort = () => {
    releaseReader();
  };
  if (signal) {
    if (signal.aborted) return;
    signal.addEventListener("abort", onAbort);
  }

  try {
    while (true) {
      let chunk;
      try {
        chunk = await reader.read();
      } catch (err) {
        if (signal?.aborted || err?.name === "AbortError") break;
        throw err;
      }
      const { done, value } = chunk;
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let sep;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const block = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        for (const line of block.split("\n")) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              onEvent(data);
              if (isTerminalScanEvent(data)) {
                await releaseReader();
                return;
              }
            } catch {
              /* ignore malformed chunk */
            }
          }
        }
      }
    }
  } finally {
    if (signal) signal.removeEventListener("abort", onAbort);
    await releaseReader();
  }
}

/**
 * Live scan via Server-Sent Events over HTTP (POST + text/event-stream).
 * Fires `onEvent` for phases, LLM steps, telemetry, heartbeats, then completes.
 */
export async function createScanStream({ target, dynamicLogs = null, onEvent, signal, forceRescan = false }) {
  const normalizedTarget = normalizeTarget(target);
  const body = dynamicLogs ? { target: normalizedTarget, dynamic_logs: dynamicLogs } : { target: normalizedTarget };
  if (forceRescan) body.force_rescan = true;
  const res = await fetch(`${API}/scans/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try {
      const j = JSON.parse(text);
      msg = j.error || j.message || text;
    } catch {
      /* use raw */
    }
    throw new Error(msg || res.statusText);
  }
  await consumeScanSse(res, onEvent, { signal });
}

export async function createScanStreamFromFolder({ files, onEvent, signal, forceRescan = false }) {
  const list = Array.from(files || []);
  if (!list.length) throw new Error("No files selected.");
  const form = new FormData();
  list.forEach((file) => {
    const path =
      (file.webkitRelativePath && String(file.webkitRelativePath).replace(/\\/g, "/")) || file.name;
    form.append("files", file, path);
  });
  if (forceRescan) form.append("force_rescan", "true");
  const res = await fetch(`${API}/scans/stream`, {
    method: "POST",
    headers: { Accept: "text/event-stream" },
    body: form,
    signal,
  });
  if (!res.ok) {
    const text = await res.text();
    let msg = text;
    try {
      const j = JSON.parse(text);
      msg = j.error || j.message || text;
    } catch {
      /* use raw */
    }
    throw new Error(msg || res.statusText);
  }
  await consumeScanSse(res, onEvent, { signal });
}

export async function createScanFromFolder(files) {
  const list = Array.from(files || []);
  if (!list.length) {
    throw new Error("No files selected.");
  }
  const form = new FormData();
  list.forEach((file) => {
    const path =
      (file.webkitRelativePath && String(file.webkitRelativePath).replace(/\\/g, "/")) || file.name;
    form.append("files", file, path);
  });
  const res = await fetch(`${API}/scans`, { method: "POST", body: form });
  return handle(res);
}

export async function getReport(scanId) {
  return dedupedGetJson(`${API}/scans/${encodeURIComponent(scanId)}/report`);
}

export async function getTopology(scanId, options = {}) {
  const params = new URLSearchParams();
  if (options.includeTests !== undefined) params.set("include_tests", String(Boolean(options.includeTests)));
  if (options.onlyPaths !== undefined) params.set("only_paths", String(Boolean(options.onlyPaths)));
  if (options.depth !== undefined) params.set("depth", String(options.depth));
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.debug) params.set("debug", "true");
  const suffix = params.toString() ? `?${params.toString()}` : "";
  return dedupedGetJson(`${API}/scans/${encodeURIComponent(scanId)}/topology${suffix}`);
}

export async function getTelemetry(scanId) {
  return dedupedGetJson(`${API}/scans/${encodeURIComponent(scanId)}/telemetry`);
}
