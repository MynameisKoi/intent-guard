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

const ROLE_STYLE = {
  input: { ring: "border-emerald-400/90 bg-emerald-950/80 text-emerald-50", caption: "Input" },
  process: { ring: "border-sky-400/85 bg-sky-950/80 text-sky-50", caption: "Processing" },
  decision: { ring: "border-indigo-400/85 bg-indigo-950/80 text-indigo-50", caption: "Decision" },
  external: { ring: "border-amber-400/90 bg-amber-950/80 text-amber-50", caption: "External action" },
  output: { ring: "border-rose-400/85 bg-rose-950/80 text-rose-50", caption: "Output" },
  storage: { ring: "border-violet-400/85 bg-violet-950/80 text-violet-50", caption: "Storage" },
};

function StepNode({ data }) {
  const style = ROLE_STYLE[data.role] || ROLE_STYLE.process;
  return (
    <div
      className={`w-[230px] rounded-xl border-2 px-3 py-2 shadow-lg ${style.ring} ${
        data.sensitive ? "ring-2 ring-rose-500/50" : ""
      }`}
      title={data.detail || undefined}
    >
      <Handle type="target" position={Position.Top} className="!h-2 !w-2 !bg-slate-500" />
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide opacity-80">{style.caption}</span>
        {data.sensitive ? (
          <span className="rounded bg-rose-500/25 px-1.5 py-0.5 text-[9px] font-bold uppercase text-rose-100">
            sensitive
          </span>
        ) : null}
      </div>
      <div className="mt-1 text-[13px] font-semibold leading-snug">{data.label}</div>
      {data.detail ? (
        <div className="mt-1 line-clamp-2 text-[10px] leading-snug opacity-75">{data.detail}</div>
      ) : null}
      <Handle type="source" position={Position.Bottom} className="!h-2 !w-2 !bg-slate-500" />
    </div>
  );
}

const nodeTypes = { step: StepNode };

const NODE_WIDTH = 230;
const NODE_HEIGHT = 96;

function toElements(workflow) {
  const steps = workflow?.steps || [];
  if (!steps.length) return { nodes: [], edges: [] };

  const transitions = (workflow.transitions || []).filter((t) =>
    steps.some((s) => s.id === t.source) && steps.some((s) => s.id === t.target),
  );

  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: "TB", ranksep: 70, nodesep: 45, marginx: 20, marginy: 20 });
  steps.forEach((s) => g.setNode(s.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  transitions.forEach((t) => g.setEdge(t.source, t.target));
  dagre.layout(g);

  const nodes = steps.map((s) => {
    const pos = g.node(s.id) || { x: 0, y: 0 };
    return {
      id: s.id,
      type: "step",
      position: { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 },
      data: { label: s.label, role: s.role, detail: s.detail, sensitive: Boolean(s.sensitive) },
    };
  });

  const edges = transitions.map((t, i) => ({
    id: `wf-${t.source}-${t.target}-${i}`,
    source: t.source,
    target: t.target,
    type: "smoothstep",
    label: t.label || "",
    labelStyle: { fill: "#cbd5e1", fontSize: 10, fontWeight: 500 },
    labelBgStyle: { fill: "#0f172a", fillOpacity: 0.9 },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 4,
    markerEnd: { type: MarkerType.ArrowClosed, color: "#64748b" },
    style: { stroke: "#64748b", strokeWidth: 1.6 },
  }));

  return { nodes, edges };
}

/**
 * Plain-language view of what the scanned repository does, as opposed to the
 * symbol-level topology graph.
 */
export default function WorkflowGraph({ workflow }) {
  const elements = useMemo(() => toElements(workflow), [workflow]);
  const [nodes, setNodes, onNodesChange] = useNodesState(elements.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(elements.edges);

  useEffect(() => {
    setNodes(elements.nodes);
    setEdges(elements.edges);
  }, [elements, setNodes, setEdges]);

  if (!workflow?.steps?.length) {
    return (
      <div className="rounded-lg border border-dashed border-ig-border bg-ig-panel/40 p-8 text-center text-sm text-ig-muted">
        No workflow reconstructed for this scan.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {workflow.summary ? (
        <p className="rounded-lg border border-ig-border bg-ig-panel px-3 py-2 text-xs leading-relaxed text-slate-300">
          {workflow.summary}
        </p>
      ) : null}
      <div className="h-[420px] rounded-lg border border-ig-border bg-[#0a0d12]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.3}
          maxZoom={1.5}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1e293b" gap={20} />
          <Controls className="!bg-ig-panel !border-ig-border" />
        </ReactFlow>
      </div>
      <p className="text-[11px] text-ig-muted">
        {workflow.source === "llm"
          ? "Reconstructed by semantic analysis of the whole repository."
          : "Derived from traced entry points, capabilities, and external calls."}
      </p>
    </div>
  );
}
