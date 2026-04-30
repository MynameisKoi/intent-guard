import { useEffect, useMemo, type CSSProperties } from "react";
import {
  Background,
  Controls,
  ReactFlow,
  useEdgesState,
  useNodesState,
  Handle,
  Position,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphEdge, GraphNode, SkillPreview } from "../types";

function kindClasses(kind: GraphNode["kind"]): string {
  switch (kind) {
    case "function":
      return "border-violet-400/80 bg-violet-950/80 text-violet-100";
    case "datastore":
      return "border-sky-400/80 bg-sky-950/80 text-sky-100";
    case "flagged":
      return "border-ig-danger bg-red-950/70 text-red-100";
    case "external":
      return "border-ig-warn bg-amber-950/70 text-amber-100";
    default:
      return "border-ig-border bg-ig-panel text-slate-100";
  }
}

function DataflowNode({ data }: NodeProps<{ label: string; kind: GraphNode["kind"] }>) {
  return (
    <div
      className={`min-w-[140px] max-w-[200px] rounded-lg border-2 px-3 py-2 text-xs font-semibold shadow-lg ${kindClasses(
        data.kind,
      )}`}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-500 !h-2 !w-2" />
      {data.label}
      <Handle type="source" position={Position.Bottom} className="!bg-slate-500 !h-2 !w-2" />
    </div>
  );
}

const nodeTypes = { dataflow: DataflowNode };

function toFlowElements(graph: NonNullable<SkillPreview["graph"]>) {
  const nodes = graph.nodes.map((n) => ({
    id: n.id,
    type: "dataflow" as const,
    position: { x: n.x, y: n.y },
    data: { label: n.label, kind: n.kind },
  }));
  const edges: {
    id: string;
    source: string;
    target: string;
    label?: string;
    animated?: boolean;
    style?: CSSProperties;
    labelStyle?: CSSProperties;
    labelBgStyle?: CSSProperties;
  }[] = graph.edges.map((e: GraphEdge) => {
    const isExfil = e.variant === "exfil";
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: isExfil,
      style: isExfil
        ? { stroke: "#f87171", strokeWidth: 2, strokeDasharray: "6 4" }
        : { stroke: "#64748b", strokeWidth: 1.5 },
      labelStyle: isExfil ? { fill: "#f87171", fontWeight: 600, fontSize: 11 } : { fill: "#94a3b8", fontSize: 11 },
      labelBgStyle: { fill: "rgba(15, 23, 42, 0.85)" },
    };
  });
  return { nodes, edges };
}

export function GraphPane({ skill }: { skill: SkillPreview }) {
  const graph = skill.graph;
  const initial = useMemo(() => (graph ? toFlowElements(graph) : { nodes: [], edges: [] }), [graph]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);

  useEffect(() => {
    if (!graph) return;
    const next = toFlowElements(graph);
    setNodes(next.nodes);
    setEdges(next.edges);
  }, [graph, setNodes, setEdges]);

  if (!graph) {
    return (
      <div className="flex h-[520px] items-center justify-center rounded-lg border border-dashed border-ig-border bg-ig-bg/60 text-sm text-ig-muted">
        No dataflow graph for this skill in the mock dataset. Select <code className="text-ig-accent">log_collector.py</code>.
      </div>
    );
  }

  return (
    <div className="h-[520px] overflow-hidden rounded-lg border border-ig-border bg-[#0a0d12]">
      <div className="flex flex-wrap gap-3 border-b border-ig-border px-4 py-2 text-[11px] text-ig-muted">
        {graph.legend.map((L) => (
          <span key={L.kind} className="inline-flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${legendDot(L.kind)}`} />
            {L.label}
          </span>
        ))}
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.5}
        maxZoom={1.5}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnDrag
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={20} />
        <Controls className="!bg-ig-panel !border-ig-border !shadow-xl" />
      </ReactFlow>
    </div>
  );
}

function legendDot(kind: GraphNode["kind"]): string {
  switch (kind) {
    case "function":
      return "bg-violet-400";
    case "datastore":
      return "bg-sky-400";
    case "flagged":
      return "bg-red-400";
    case "external":
      return "bg-amber-400";
    default:
      return "bg-slate-500";
  }
}
