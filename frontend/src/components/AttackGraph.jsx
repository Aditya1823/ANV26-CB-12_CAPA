import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  MarkerType,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

function getResourceInfo(resource) {
  const info = {
    api: {
      label: "Internet API",
      type: "API",
      icon: "🌐",
    },

    server: {
      label: "Web Server",
      type: "SERVER",
      icon: "🖥️",
    },

    iam: {
      label: "IAM Role",
      type: "IAM",
      icon: "🔑",
    },

    iam_a: {
      label: "IAM Role A",
      type: "EXCESSIVE",
      icon: "🔑",
    },

    iam_b: {
      label: "IAM Role B",
      type: "ADMIN",
      icon: "🔐",
    },

    database: {
      label: "Critical Database",
      type: "DATABASE",
      icon: "🗄️",
    },
  };

  return (
    info[resource] || {
      label: resource,
      type: "RESOURCE",
      icon: "◆",
    }
  );
}

function getNodePosition(
  resourceId,
  index,
  resources
) {
  const knownPositions = {
    api: {
      x: 30,
      y: 210,
    },

    server: {
      x: 300,
      y: 210,
    },

    iam: {
      x: 570,
      y: 210,
    },

    iam_a: {
      x: 570,
      y: 80,
    },

    iam_b: {
      x: 570,
      y: 340,
    },

    database: {
      x: 890,
      y: 210,
    },
  };

  if (knownPositions[resourceId]) {
    return knownPositions[resourceId];
  }

  const column =
    index % 4;

  const row =
    Math.floor(index / 4);

  return {
    x: 40 + column * 270,
    y: 100 + row * 170,
  };
}

function getNodeVisualState(resource) {
  if (resource.critical) {
    return {
      border: "1px solid #ef4444",
      background:
        "linear-gradient(145deg, rgba(239,68,68,0.18), rgba(127,29,29,0.12))",
      accent: "#f87171",
    };
  }

  if (resource.admin_permission) {
    return {
      border: "1px solid #ef4444",
      background:
        "linear-gradient(145deg, rgba(239,68,68,0.13), rgba(127,29,29,0.08))",
      accent: "#fb7185",
    };
  }

  if (resource.excessive_permission) {
    return {
      border: "1px solid #f59e0b",
      background:
        "linear-gradient(145deg, rgba(245,158,11,0.15), rgba(120,53,15,0.08))",
      accent: "#fbbf24",
    };
  }

  if (resource.internet_exposed) {
    return {
      border: "1px solid #f97316",
      background:
        "linear-gradient(145deg, rgba(249,115,22,0.14), rgba(124,45,18,0.08))",
      accent: "#fb923c",
    };
  }

  return {
    border:
      "1px solid rgba(148,163,184,0.24)",
    background:
      "linear-gradient(145deg, #111827, #0f172a)",
    accent: "#94a3b8",
  };
}

function createNodes(configuration) {
  const resources =
    configuration?.resources || [];

  return resources.map(
    (resource, index) => {
      const info =
        getResourceInfo(
          resource.id
        );

      const position =
        getNodePosition(
          resource.id,
          index,
          resources
        );

      const visual =
        getNodeVisualState(
          resource
        );

      return {
        id: resource.id,

        position,

        data: {
          label: (
            <div
              style={{
                width: "178px",
                textAlign: "left",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                }}
              >
                <div
                  style={{
                    width: "38px",
                    height: "38px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent:
                      "center",
                    flexShrink: 0,
                    borderRadius:
                      "10px",
                    background:
                      "rgba(15,23,42,0.9)",
                    fontSize: "19px",
                  }}
                >
                  {info.icon}
                </div>

                <div
                  style={{
                    minWidth: 0,
                  }}
                >
                  <div
                    style={{
                      color: "#f8fafc",
                      fontSize: "13px",
                      fontWeight: 750,
                      lineHeight: 1.2,
                    }}
                  >
                    {info.label}
                  </div>

                  <div
                    style={{
                      marginTop: "4px",
                      color:
                        visual.accent,
                      fontSize: "8px",
                      fontWeight: 800,
                      letterSpacing:
                        "0.09em",
                    }}
                  >
                    {info.type}
                  </div>
                </div>
              </div>

              {(resource.internet_exposed ||
                resource.excessive_permission ||
                resource.admin_permission ||
                resource.critical) && (
                <div
                  style={{
                    marginTop: "10px",
                    paddingTop: "8px",
                    borderTop:
                      "1px solid rgba(148,163,184,0.12)",
                    color:
                      visual.accent,
                    fontSize: "8px",
                    fontWeight: 800,
                    letterSpacing:
                      "0.04em",
                  }}
                >
                  {resource.internet_exposed &&
                    "● INTERNET EXPOSED"}

                  {resource.excessive_permission &&
                    "● EXCESSIVE PERMISSION"}

                  {resource.admin_permission &&
                    "● ADMIN PRIVILEGE"}

                  {resource.critical &&
                    "● CRITICAL ASSET"}
                </div>
              )}
            </div>
          ),
        },

        style: {
          width: "205px",
          minHeight: "92px",
          padding: "13px",

          border:
            visual.border,

          borderRadius: "14px",

          background:
            visual.background,

          color: "#f8fafc",

          boxShadow:
            "0 8px 25px rgba(0,0,0,0.22)",

          transition:
            "all 0.2s ease",
        },
      };
    }
  );
}

function getPathEdges(paths) {
  const edges = new Set();

  for (const path of paths || []) {
    for (
      let index = 0;
      index < path.length - 1;
      index++
    ) {
      edges.add(
        `${path[index]}->${path[index + 1]}`
      );
    }
  }

  return edges;
}

function createEdges(
  configuration,
  originalPaths,
  remainingPaths,
  simulationActive
) {
  const connections =
    configuration?.connections || [];

  const originalEdges =
    getPathEdges(
      originalPaths
    );

  const remainingEdges =
    getPathEdges(
      remainingPaths
    );

  return connections
    .filter((connection) =>
      originalEdges.has(
        `${connection.from}->${connection.to}`
      )
    )
    .map(
      (connection, index) => {
        const edgeKey =
          `${connection.from}->${connection.to}`;

        const stillActive =
          remainingEdges.has(
            edgeKey
          );

        const wasRemoved =
          simulationActive &&
          !stillActive;

        let stroke =
          stillActive
            ? "#60a5fa"
            : "#64748b";

        let strokeWidth =
          stillActive ? 3 : 2;

        if (
          connection.type ===
          "permission"
        ) {
          stroke =
            stillActive
              ? "#ef4444"
              : "#64748b";

          strokeWidth =
            stillActive ? 3 : 2;
        }

        if (wasRemoved) {
          stroke = "#64748b";
          strokeWidth = 2;
        }

        const edgeLabel =
          wasRemoved
            ? "BROKEN"
            : connection.permission ||
              connection.type ||
              "";

        return {
          id:
            `attack-edge-${index}`,

          source:
            connection.from,

          target:
            connection.to,

          animated:
            stillActive,

          label:
            edgeLabel,

          labelStyle: {
            fontSize: 9,
            fontWeight: 800,
            fill:
              wasRemoved
                ? "#94a3b8"
                : "#e2e8f0",
          },

          labelBgStyle: {
            fill:
              wasRemoved
                ? "#1e293b"
                : "#0f172a",

            stroke:
              wasRemoved
                ? "#475569"
                : "#263244",
          },

          labelBgPadding: [
            7,
            4,
          ],

          labelBgBorderRadius: 5,

          markerEnd: {
            type:
              MarkerType.ArrowClosed,

            color:
              stroke,
          },

          style: {
            stroke,
            strokeWidth,

            strokeDasharray:
              wasRemoved
                ? "8 7"
                : undefined,

            opacity:
              wasRemoved
                ? 0.5
                : 1,
          },
        };
      }
    );
}

function getViewportConfig(
  configuration
) {
  const resourceCount =
    configuration?.resources
      ?.length || 0;

  if (resourceCount <= 4) {
    return {
      padding: 0.32,
      minZoom: 0.55,
      maxZoom: 1.35,
    };
  }

  return {
    padding: 0.25,
    minZoom: 0.45,
    maxZoom: 1.25,
  };
}

export default function AttackGraph({
  fixed,
  attackPaths = [],
  configuration,
  originalAttackPaths = null,
  remainingAttackPaths = null,
}) {
  const originalPaths =
    originalAttackPaths ||
    attackPaths;

  const remainingPaths =
    remainingAttackPaths ??
    attackPaths;

  const simulationActive =
    remainingAttackPaths !== null;

  const nodes =
    createNodes(
      configuration
    );

  const edges =
    createEdges(
      configuration,
      originalPaths,
      remainingPaths,
      simulationActive
    );

  const viewport =
    getViewportConfig(
      configuration
    );

  return (
    <div
      className="cloudshield-attack-graph"
      style={{
        width: "100%",
        height: "520px",
        minHeight: "520px",
        borderRadius: "14px",
        overflow: "hidden",
        border:
          "1px solid #263244",
        background:
          "#080d17",
        position: "relative",
      }}
    >
      <div
        style={{
          position: "absolute",
          top: "14px",
          left: "16px",
          zIndex: 5,
          pointerEvents:
            "none",
        }}
      >
        <div
          style={{
            color: "#64748b",
            fontSize: "8px",
            fontWeight: 800,
            letterSpacing:
              "0.1em",
          }}
        >
          SECURITY GRAPH
        </div>

        <div
          style={{
            marginTop: "3px",
            color: "#94a3b8",
            fontSize: "10px",
          }}
        >
          Entry point → privilege path → critical asset
        </div>
      </div>

      {simulationActive && (
        <div
          style={{
            position: "absolute",
            top: "14px",
            right: "16px",
            zIndex: 5,
            padding:
              "6px 9px",
            border:
              "1px solid #475569",
            borderRadius: "6px",
            background:
              "rgba(15,23,42,0.92)",
            color:
              fixed
                ? "#4ade80"
                : "#fbbf24",
            fontSize: "8px",
            fontWeight: 800,
            letterSpacing:
              "0.06em",
          }}
        >
          {fixed
            ? "REMEDIATION VERIFIED"
            : "WHAT-IF SIMULATION"}
        </div>
      )}

      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        fitViewOptions={{
          padding:
            viewport.padding,

          includeHiddenNodes:
            true,
        }}
        minZoom={
          viewport.minZoom
        }
        maxZoom={
          viewport.maxZoom
        }
        proOptions={{
          hideAttribution:
            true,
        }}
      >
        <Background
          gap={28}
          size={1}
          color="#1e293b"
        />

        <Controls
          showInteractive={false}
        />

        <MiniMap
          nodeStrokeWidth={3}
          pannable
          zoomable
        />
      </ReactFlow>
    </div>
  );
}