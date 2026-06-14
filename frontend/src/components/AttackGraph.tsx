"use client";

import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MarkerType,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { AttackGraph, NodeStatus } from "@/lib/types";

const NODE_STYLES: Record<NodeStatus, { bg: string; border: string; text: string }> = {
  safe: { bg: "#064e3b", border: "#34d399", text: "#6ee7b7" },
  suspicious: { bg: "#78350f", border: "#fbbf24", text: "#fcd34d" },
  malicious: { bg: "#7f1d1d", border: "#f87171", text: "#fca5a5" },
};

function layoutNodes(graph: AttackGraph): Node[] {
  const positions: Record<string, { x: number; y: number }> = {};
  const ids = graph.nodes.map((n) => n.id);

  ids.forEach((id, i) => {
    positions[id] = { x: 220, y: i * 120 + 40 };
  });

  return graph.nodes.map((n) => {
    const style = NODE_STYLES[n.status];
    return {
      id: n.id,
      position: positions[n.id] ?? { x: 0, y: 0 },
      data: { label: n.label },
      style: {
        background: style.bg,
        border: `2px solid ${style.border}`,
        color: style.text,
        borderRadius: 10,
        padding: "12px 20px",
        fontSize: 13,
        fontWeight: 600,
        minWidth: 140,
        textAlign: "center" as const,
        boxShadow: `0 0 20px ${style.border}33`,
      },
    };
  });
}

function buildEdges(graph: AttackGraph): Edge[] {
  return graph.edges.map((e) => {
    const targetNode = graph.nodes.find((n) => n.id === e.target);
    const color =
      targetNode?.status === "malicious"
        ? "#f87171"
        : targetNode?.status === "suspicious"
          ? "#fbbf24"
          : "#34d399";

    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label ?? undefined,
      animated: targetNode?.status !== "safe",
      style: { stroke: color, strokeWidth: 2 },
      labelStyle: { fill: "#94a3b8", fontSize: 11 },
      markerEnd: { type: MarkerType.ArrowClosed, color },
    };
  });
}

export function AttackGraphView({ graph }: { graph: AttackGraph }) {
  const nodes = useMemo(() => layoutNodes(graph), [graph]);
  const edges = useMemo(() => buildEdges(graph), [graph]);

  return (
    <div className="glass h-[520px] overflow-hidden rounded-xl">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnDrag
        zoomOnScroll
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={20} />
        <Controls showInteractive={false} className="!bg-slate-900 !border-slate-700 !shadow-lg" />
      </ReactFlow>
    </div>
  );
}
