import { useEffect, useMemo } from "react";
import dagre from "dagre";
import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  useEdgesState,
  useNodesState,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

function kindClass(kind, isSource) {
  if (kind === "source") {
    return "border-emerald-400/95 bg-emerald-950/85 text-emerald-50 ring-2 ring-emerald-500/40";
  }
  if (kind === "agent") {
    return "border-cyan-400/90 bg-cyan-950/80 text-cyan-50 ring-1 ring-cyan-500/35";
  }
  if (kind === "tool") {
    return "border-rose-400/85 bg-rose-950/75 text-rose-50";
  }
  if (kind === "prompt") {
    return "border-fuchsia-400/85 bg-fuchsia-950/75 text-fuchsia-50";
  }
  if (kind === "permission") {
    return "border-lime-400/85 bg-lime-950/70 text-lime-50";
  }
  if (kind === "task") {
    return "border-indigo-400/85 bg-indigo-950/75 text-indigo-50";
  }
  if (kind === "function" && isSource) {
    return "border-emerald-400/80 bg-emerald-950/50 text-emerald-100 ring-1 ring-emerald-500/30";
  }
  switch (kind) {
    case "file":
      return "border-sky-400/80 bg-sky-950/80 text-sky-100";
    case "function":
      return "border-violet-400/80 bg-violet-950/80 text-violet-100";
    case "external":
      return "border-ig-warn bg-amber-950/70 text-amber-100";
    case "data":
      return "border-sky-500/60 bg-slate-900 text-slate-100";
    default:
      return "border-ig-border bg-ig-panel text-slate-200";
  }
}

function FlowNode({ data }) {
  const isSource = Boolean(data.isSource ?? data.is_source);
  return (
    <div
      className={`min-w-[120px] max-w-[200px] rounded-lg border-2 px-2 py-1.5 text-xs font-semibold shadow ${kindClass(
        data.kind,
        isSource,
      )}`}
    >
      <Handle type="target" position={Position.Top} className="!h-2 !w-2 !bg-slate-500" />
      <div className="truncate">{data.label}</div>
      {data.kind === "source" ? (
        <div className="truncate text-[10px] font-medium uppercase tracking-wide text-emerald-200/90">Source</div>
      ) : null}
      {data.path && <div className="truncate font-mono text-[10px] opacity-80">{data.path}</div>}
      <Handle type="source" position={Position.Bottom} className="!h-2 !w-2 !bg-slate-500" />
    </div>
  );
}

function AgentGroupNode({ data }) {
  return (
    <div className="h-full w-full rounded-xl border-2 border-cyan-400/50 bg-cyan-950/20 p-2 text-xs text-cyan-100">
      <div className="truncate font-semibold">{data.label}</div>
      {data.path ? <div className="truncate font-mono text-[10px] opacity-80">{data.path}</div> : null}
    </div>
  );
}

const nodeTypes = { ig: FlowNode, agentGroup: AgentGroupNode };

function isTestPath(path = "") {
  const p = String(path).toLowerCase();
  return (
    p.includes("/tests/") ||
    p.includes("\\tests\\") ||
    p.includes("/test_") ||
    p.includes("\\test_") ||
    p.endsWith("/conftest.py") ||
    p.endsWith("\\conftest.py") ||
    p.includes("/mock_") ||
    p.includes("\\mock_")
  );
}

function isHighRiskNode(node, topology) {
  if (!node) return false;
  if (
    node.kind === "external" ||
    node.kind === "source" ||
    node.kind === "agent" ||
    node.kind === "tool" ||
    node.kind === "prompt" ||
    node.kind === "permission" ||
    node.kind === "task" ||
    node.is_source
  )
    return true;
  const edges = topology?.edges || [];
  return edges.some((e) => {
    if (e.source !== node.id && e.target !== node.id) return false;
    const other = topology.nodes.find((n) => n.id === (e.source === node.id ? e.target : e.source));
    return other?.kind === "external";
  });
}

function moduleKey(path) {
  const p = String(path || "").replace(/\\/g, "/");
  if (!p) return "(root)";
  const parts = p.split("/").filter(Boolean);
  return parts.length <= 1 ? "(root)" : parts[0];
}

function layoutTopLevelWithDagre(nodes, edges) {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", ranksep: 120, nodesep: 80, marginx: 20, marginy: 20 });

  const topLevel = nodes.filter((n) => !n.parentNode);
  topLevel.forEach((n) => {
    const w = n.width || n.style?.width || 200;
    const h = n.height || n.style?.height || 100;
    g.setNode(n.id, { width: Number(w), height: Number(h) });
  });

  const topIds = new Set(topLevel.map((n) => n.id));
  edges.forEach((e) => {
    if (topIds.has(e.source) && topIds.has(e.target)) g.setEdge(e.source, e.target);
  });

  dagre.layout(g);
  return nodes.map((n) => {
    if (n.parentNode) return n;
    const p = g.node(n.id);
    if (!p) return n;
    const w = Number(n.width || n.style?.width || 200);
    const h = Number(n.height || n.style?.height || 100);
    return { ...n, position: { x: p.x - w / 2, y: p.y - h / 2 } };
  });
}

function toElements(topology, options = {}) {
  if (!topology?.nodes?.length) {
    return { nodes: [], edges: [] };
  }
  const { showTests = false, highRiskOnly = false, collapseModules = true } = options;
  let filteredNodes = topology.nodes.filter((n) => (showTests ? true : !isTestPath(n.path)));
  if (highRiskOnly) {
    const keepIds = new Set(
      filteredNodes.filter((n) => isHighRiskNode(n, { nodes: filteredNodes, edges: topology.edges || [] })).map((n) => n.id),
    );
    filteredNodes = filteredNodes.filter((n) => keepIds.has(n.id));
  }
  const allowedIds = new Set(filteredNodes.map((n) => n.id));
  let filteredEdges = (topology.edges || []).filter((e) => allowedIds.has(e.source) && allowedIds.has(e.target));

  if (collapseModules) {
    const moduleNodesMap = new Map();
    const mapNodeToModule = new Map();
    for (const n of filteredNodes) {
      const key = moduleKey(n.path);
      mapNodeToModule.set(n.id, key);
      if (!moduleNodesMap.has(key)) {
        moduleNodesMap.set(key, {
          id: `module:${key}`,
          type: "ig",
          position: { x: 0, y: 0 },
          data: { label: key, kind: "file", path: `${key}/`, isSource: false, is_source: false },
        });
      }
    }
    const mergedEdges = new Map();
    for (const e of filteredEdges) {
      const s = `module:${mapNodeToModule.get(e.source)}`;
      const t = `module:${mapNodeToModule.get(e.target)}`;
      if (!s || !t || s === t) continue;
      const id = `${s}->${t}`;
      const vn = e.variable_name != null && String(e.variable_name).length ? String(e.variable_name) : "";
      if (!mergedEdges.has(id)) {
        mergedEdges.set(id, {
          id,
          source: s,
          target: t,
          label: vn || "module",
          labelStyle: { fill: "#94a3b8", fontSize: 10 },
          labelBgStyle: { fill: "#0f172a", fillOpacity: 0.88 },
          labelBgPadding: [3, 2],
          labelBgBorderRadius: 3,
          style: { stroke: "#64748b", strokeWidth: 1.6 },
        });
      } else if (vn) {
        const cur = mergedEdges.get(id);
        const prev = cur.label && cur.label !== "module" ? cur.label : "";
        cur.label = [prev, vn].filter(Boolean).join(", ");
      }
    }
    const modules = Array.from(moduleNodesMap.values());
    const moduleColumns = 4;
    modules.forEach((n, i) => {
      n.position = { x: 40 + (i % moduleColumns) * 260, y: 40 + Math.floor(i / moduleColumns) * 170 };
    });
    return { nodes: modules, edges: Array.from(mergedEdges.values()) };
  }

  const byId = new Map(filteredNodes.map((n) => [n.id, n]));
  const capabilityKinds = new Set(["tool", "prompt", "permission", "task"]);
  const childrenByAgent = new Map();
  filteredEdges.forEach((e) => {
    const src = byId.get(e.source);
    const tgt = byId.get(e.target);
    if (!src || !tgt) return;
    if (src.kind === "agent" && capabilityKinds.has(tgt.kind)) {
      if (!childrenByAgent.has(src.id)) childrenByAgent.set(src.id, []);
      childrenByAgent.get(src.id).push(tgt.id);
    }
  });

  const childSet = new Set(Array.from(childrenByAgent.values()).flat());
  const nodes = [];
  for (const n of filteredNodes) {
    if (n.kind === "agent") {
      const kids = childrenByAgent.get(n.id) || [];
      const cols = Math.min(3, Math.max(1, kids.length));
      const rows = Math.max(1, Math.ceil(kids.length / cols));
      const width = Math.max(320, cols * 190 + 40);
      const height = Math.max(170, rows * 90 + 70);
      nodes.push({
        id: n.id,
        type: "agentGroup",
        position: { x: 0, y: 0 },
        style: { width, height },
        data: { label: n.label, path: n.path, kind: n.kind },
      });
      kids.forEach((cid, idx) => {
        const child = byId.get(cid);
        if (!child) return;
        nodes.push({
          id: child.id,
          type: "ig",
          parentId: n.id,
          extent: "parent",
          position: { x: 20 + (idx % cols) * 180, y: 48 + Math.floor(idx / cols) * 84 },
          draggable: false,
          data: {
            label: child.label,
            kind: child.kind || "other",
            path: child.path,
            isSource: Boolean(child.is_source),
            is_source: Boolean(child.is_source),
          },
        });
      });
    } else if (!childSet.has(n.id)) {
      nodes.push({
        id: n.id,
        type: "ig",
        position: { x: 0, y: 0 },
        data: {
          label: n.label,
          kind: n.kind || "other",
          path: n.path,
          isSource: Boolean(n.is_source),
          is_source: Boolean(n.is_source),
        },
      });
    }
  }

  const laidOutNodes = layoutTopLevelWithDagre(nodes, filteredEdges);
  const edges = filteredEdges.map((e) => {
    const vn = e.variable_name != null && String(e.variable_name).length ? String(e.variable_name) : "";
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: "bezier",
      label: vn || e.kind || "flow",
      labelStyle: { fill: "#94a3b8", fontSize: 11, fontWeight: 500 },
      labelBgStyle: { fill: "#0f172a", fillOpacity: 0.9 },
      labelBgPadding: [4, 2],
      labelBgBorderRadius: 4,
      markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
      style: { stroke: "#64748b", strokeWidth: 1.5 },
    };
  });
  return { nodes: laidOutNodes, edges };
}

/**
 * Technical graph from `GET /api/scans/:id/topology` (Neo4j or Mongo fallback).
 */
export default function TopologyGraph({ topology, graphFilters, onChangeGraphFilters }) {
  const filters = graphFilters || {
    showTests: false,
    highRiskOnly: false,
    collapseModules: true,
    astDebugMode: false,
  };
  const baseElements = useMemo(() => toElements(topology, filters), [topology, filters]);
  const [nodes, setNodes, onNodesChange] = useNodesState(baseElements.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(baseElements.edges);

  useEffect(() => {
    setNodes(baseElements.nodes);
    setEdges(baseElements.edges);
  }, [baseElements, setNodes, setEdges]);

  if (!topology?.nodes?.length) {
    return (
      <div className="rounded-lg border border-dashed border-ig-border bg-ig-panel/40 p-8 text-center text-sm text-ig-muted">
        No graph nodes for this scan (empty topology or Neo4j not populated).
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-ig-border bg-ig-panel px-3 py-2 text-xs">
        <label className="inline-flex items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={Boolean(filters.showTests)}
            onChange={(e) => onChangeGraphFilters?.((prev) => ({ ...prev, showTests: e.target.checked }))}
          />
          Show test files
        </label>
        <label className="inline-flex items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={Boolean(filters.highRiskOnly)}
            onChange={(e) => onChangeGraphFilters?.((prev) => ({ ...prev, highRiskOnly: e.target.checked }))}
          />
          Show only high-risk paths
        </label>
        <label className="inline-flex items-center gap-2 text-slate-300">
          <input
            type="checkbox"
            checked={Boolean(filters.collapseModules)}
            onChange={(e) => onChangeGraphFilters?.((prev) => ({ ...prev, collapseModules: e.target.checked }))}
          />
          Collapse modules
        </label>
        <label className="inline-flex cursor-pointer items-center gap-2 text-amber-200/90">
          <input
            type="checkbox"
            role="switch"
            aria-checked={Boolean(filters.astDebugMode)}
            checked={Boolean(filters.astDebugMode)}
            onChange={(e) => onChangeGraphFilters?.((prev) => ({ ...prev, astDebugMode: e.target.checked }))}
          />
          Show Unfiltered AST (Debug Mode)
        </label>
      </div>
      <div className="h-[420px] rounded-lg border border-ig-border bg-[#0a0d12]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        defaultEdgeOptions={{ type: "bezier" }}
        fitView
        minZoom={0.4}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={20} />
        <Controls className="!bg-ig-panel !border-ig-border" />
      </ReactFlow>
      </div>
    </div>
  );
}
