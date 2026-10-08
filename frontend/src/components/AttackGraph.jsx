import { useCallback, useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

const initialNodes = [
  {
    id: "internet",
    position: { x: 20, y: 170 },
    data: { label: "🌐 Internet" },
    style: {
      background: "#172033",
      color: "#fff",
      border: "1px solid #64748b",
      borderRadius: 12,
      padding: 14,
      width: 150,
      textAlign: "center",
      fontWeight: 600,
    },
  },
  {
    id: "api",
    position: { x: 190, y: 170 },
    data: { label: "Public API" },
    style: {
      background: "#172033",
      color: "#fff",
      border: "1px solid #3b82f6",
      borderRadius: 12,
      padding: 14,
      width: 150,
      textAlign: "center",
    },
  },
  {
    id: "server",
    position: { x: 360, y: 170 },
    data: { label: "Web Server" },
    style: {
      background: "#172033",
      color: "#fff",
      border: "1px solid #3b82f6",
      borderRadius: 12,
      padding: 14,
      width: 150,
      textAlign: "center",
    },
  },
  {
    id: "iam",
    position: { x: 530, y: 170 },
    data: { label: "⚠ Excessive IAM" },
    style: {
      background: "#3a2416",
      color: "#fbbf24",
      border: "1px solid #f59e0b",
      borderRadius: 12,
      padding: 14,
      width: 170,
      textAlign: "center",
      fontWeight: 600,
    },
  },
  {
    id: "database",
    position: { x: 700, y: 170 },
    data: { label: "🔴 Customer Database" },
    style: {
      background: "#3b1515",
      color: "#f87171",
      border: "1px solid #ef4444",
      borderRadius: 12,
      padding: 14,
      width: 180,
      textAlign: "center",
      fontWeight: 700,
    },
  },
];

const initialEdges = [
  {
    id: "e1",
    source: "internet",
    target: "api",
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed },
  },
  {
    id: "e2",
    source: "api",
    target: "server",
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed },
  },
  {
    id: "e3",
    source: "server",
    target: "iam",
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed },
  },
  {
    id: "e4",
    source: "iam",
    target: "database",
    animated: true,
    style: { stroke: "#ef4444", strokeWidth: 3 },
    markerEnd: { type: MarkerType.ArrowClosed },
  },
];

export default function AttackGraph({ fixed }) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    if (fixed) {
      setEdges((current) =>
        current.filter((edge) => edge.id !== "e4")
      );
    } else {
      setEdges(initialEdges);
    }
  }, [fixed, setEdges]);

  const onInit = useCallback(() => {}, []);

  return (
    <div className="graph-container">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onInit={onInit}
        fitView
        attributionPosition="bottom-left"
      >
        <Background gap={20} size={1} />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  );
}
