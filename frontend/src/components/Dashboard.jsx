import { useEffect, useMemo, useState } from "react";

import AttackGraph from "./AttackGraph";
import RiskPanel from "./RiskPanel";
import RemediationPanel from "./RemediationPanel";
import PersonaPanel from "./PersonaPanel";

const API_BASE = "http://127.0.0.1:8000";

const scenarios = {
  singlePath: {
    name: "Single Attack Path",

    description:
      "Internet → API → Server → Excessive IAM → Critical Database",

    configuration: {
      resources: [
        {
          id: "api",
          type: "API",
          internet_exposed: true,
        },
        {
          id: "server",
          type: "SERVER",
        },
        {
          id: "iam",
          type: "IAM_ROLE",
          excessive_permission: true,
        },
        {
          id: "database",
          type: "DATABASE",
          critical: true,
        },
      ],

      connections: [
        {
          from: "api",
          to: "server",
          type: "network",
        },
        {
          from: "server",
          to: "iam",
          type: "trust",
        },
        {
          from: "iam",
          to: "database",
          type: "permission",
          permission: "READ_WRITE",
        },
      ],
    },

    preferredRemediation: {
      action: "REDUCE_EXCESSIVE_PERMISSION",
      resource: "iam",
    },
  },

  multiPath: {
    name: "Multiple Attack Paths",

    description:
      "Two independent routes reach the same critical database",

    configuration: {
      resources: [
        {
          id: "api",
          type: "API",
          internet_exposed: true,
        },
        {
          id: "iam_a",
          type: "IAM_ROLE",
          excessive_permission: true,
        },
        {
          id: "iam_b",
          type: "IAM_ROLE",
          admin_permission: true,
        },
        {
          id: "database",
          type: "DATABASE",
          critical: true,
        },
      ],

      connections: [
        {
          from: "api",
          to: "iam_a",
          type: "trust",
        },
        {
          from: "iam_a",
          to: "database",
          type: "permission",
          permission: "READ_WRITE",
        },
        {
          from: "api",
          to: "iam_b",
          type: "trust",
        },
        {
          from: "iam_b",
          to: "database",
          type: "permission",
          permission: "ADMIN",
        },
      ],
    },

    preferredRemediation: {
      action: "REDUCE_EXCESSIVE_PERMISSION",
      resource: "iam_a",
    },
  },
};

export default function Dashboard() {
  const [selectedScenario, setSelectedScenario] =
    useState("singlePath");

  const [analysis, setAnalysis] =
    useState(null);

  const [simulation, setSimulation] =
    useState(null);

  const [selectedRemediation, setSelectedRemediation] =
    useState(null);

  const [loading, setLoading] =
    useState(false);

  const [simulating, setSimulating] =
    useState(false);

  const [error, setError] =
    useState("");

  const scenario =
    scenarios[selectedScenario];

  const analyzeConfiguration = async () => {
    try {
      setLoading(true);
      setError("");
      setSimulation(null);

      setSelectedRemediation(
        scenario.preferredRemediation
      );

      const response = await fetch(
        `${API_BASE}/analyze`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            configuration:
              scenario.configuration,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          "Backend analysis failed"
        );
      }

      const data =
        await response.json();

      setAnalysis(data);
    } catch (err) {
      console.error(err);

      setError(
        "Unable to connect to CloudShield backend. Make sure FastAPI is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const simulateFix = async (
    remediationOverride = null
  ) => {
    try {
      setSimulating(true);
      setError("");

      const remediation =
        remediationOverride ||
        selectedRemediation ||
        scenario.preferredRemediation;

      const response = await fetch(
        `${API_BASE}/simulate`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            configuration:
              scenario.configuration,

            remediation,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          "Simulation failed"
        );
      }

      const data =
        await response.json();

      setSimulation({
        before: data.before,

        after: data.after,

        risk_reduction:
          data.risk_reduction,

        path_broken:
          data.path_broken,

        remaining_paths:
          data.remaining_paths,

        remediation:
          data.remediation,

        multi_fix: false,
      });
    } catch (err) {
      console.error(err);

      setError(
        "Unable to run remediation simulation."
      );
    } finally {
      setSimulating(false);
    }
  };

  const simulateRemediationSet = async (
    remediationSet
  ) => {
    try {
      setSimulating(true);
      setError("");

      if (
        !remediationSet ||
        remediationSet.length === 0
      ) {
        throw new Error(
          "No remediation actions supplied"
        );
      }

      const response = await fetch(
        `${API_BASE}/simulate-set`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            configuration:
              scenario.configuration,

            remediations:
              remediationSet,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          "Multi-remediation simulation failed"
        );
      }

      const data =
        await response.json();

      setSimulation({
        before: data.before,

        after: data.after,

        risk_reduction:
          data.risk_reduction,

        path_broken:
          data.path_broken,

        remaining_paths:
          data.remaining_paths,

        remediations:
          data.remediations,

        broken_attack_paths:
          data.broken_attack_paths,

        security_percentage:
          data.security_percentage,

        multi_fix: true,
      });
    } catch (err) {
      console.error(err);

      setError(
        "Unable to run multi-remediation simulation."
      );
    } finally {
      setSimulating(false);
    }
  };

  useEffect(() => {
    analyzeConfiguration();
  }, [selectedScenario]);

  const attackPaths =
    analysis?.attack_paths || [];

  const primaryAttackPath =
    attackPaths[0];

  const currentAttackPaths =
    simulation
      ? simulation.after.attack_paths
      : attackPaths.length;

  const currentRiskScore =
    simulation
      ? simulation.after.risk_score
      : analysis?.summary?.highest_risk || 0;

  const isFixed =
    simulation?.path_broken === true;

  const currentSeverity =
    isFixed
      ? "SECURE"
      : primaryAttackPath?.severity ||
        "UNKNOWN";

  const entryPoint =
    primaryAttackPath?.entry_point ||
    "Unknown";

  const criticalAsset =
    primaryAttackPath?.target ||
    "Unknown";

  const blastRadius =
    primaryAttackPath?.blast_radius
      ?.affected_resource_count || 0;

  const weakness = useMemo(() => {
    if (
      !primaryAttackPath?.risk_reasons
    ) {
      return "Security weakness detected";
    }

    const reason =
      primaryAttackPath.risk_reasons.find(
        (item) =>
          item.includes(
            "excessive permissions"
          ) ||
          item.includes(
            "admin-level permissions"
          ) ||
          item.includes(
            "public access"
          ) ||
          item.includes(
            "internet exposed"
          )
      );

    return (
      reason ||
      "Security weakness detected"
    );
  }, [primaryAttackPath]);

  const summary =
    analysis?.summary || {
      total_resources: 0,
      critical_assets: 0,
      dangerous_paths: 0,
      highest_risk: 0,
    };

  const optimizedRemediations =
    analysis?.optimized_remediations ||
    [];

  const personaRankings =
    analysis?.persona_rankings || {};

  return (
    <div className="dashboard">

      <div className="dashboard-header">

        <div>

          <span className="eyebrow">
            CLOUD SECURITY ANALYSIS
          </span>

          <h1>
            CloudShield
          </h1>

          <p>
            Cloud Attack Path Analyzer &
            Remediation Optimizer
          </p>

        </div>

        <div className="scenario-selector">

          <label htmlFor="scenario">
            ANALYSIS SCENARIO
          </label>

          <select
            id="scenario"
            value={selectedScenario}
            onChange={(event) =>
              setSelectedScenario(
                event.target.value
              )
            }
          >
            {Object.entries(
              scenarios
            ).map(
              ([key, value]) => (
                <option
                  key={key}
                  value={key}
                >
                  {value.name}
                </option>
              )
            )}
          </select>

          <span className="scenario-description">
            {scenario.description}
          </span>

        </div>

      </div>

      {error && (
        <div className="error-banner">
          {error}
        </div>
      )}

      <div className="summary-grid">

        <div className="summary-card">

          <span>
            Resources
          </span>

          <strong>
            {summary.total_resources}
          </strong>

        </div>

        <div className="summary-card">

          <span>
            Attack Paths
          </span>

          <strong>
            {currentAttackPaths}
          </strong>

        </div>

        <div className="summary-card">

          <span>
            Critical Assets
          </span>

          <strong>
            {summary.critical_assets}
          </strong>

        </div>

        <div className="summary-card">

          <span>
            Risk Score
          </span>

          <strong>
            {currentRiskScore}
          </strong>

        </div>

      </div>

      <div className="dashboard-grid">

        <div className="panel graph-panel">

          <div className="panel-header">

            <div>

              <span className="eyebrow">
                ATTACK PATH VISUALIZATION
              </span>

              <h2>
                Security Graph
              </h2>

            </div>

            <span
              className={
                currentAttackPaths === 0
                  ? "status-badge safe"
                  : "status-badge critical"
              }
            >
              {currentAttackPaths === 0
                ? "PROTECTED"
                : `${currentAttackPaths} PATH${
                    currentAttackPaths > 1
                      ? "S"
                      : ""
                  } DETECTED`}
            </span>

          </div>

          {loading ? (

            <div className="loading-state">
              Analyzing cloud security graph...
            </div>

          ) : (

            <AttackGraph
              fixed={isFixed}

              attackPaths={
                simulation?.remaining_paths?.map(
                  (item) => item.path
                ) ||
                attackPaths.map(
                  (item) => item.path
                )
              }

              originalAttackPaths={
                attackPaths.map(
                  (item) => item.path
                )
              }

              remainingAttackPaths={
                simulation
                  ? simulation.remaining_paths.map(
                      (item) => item.path
                    )
                  : null
              }

              configuration={
                scenario.configuration
              }
            />

          )}

        </div>

        <RiskPanel
          fixed={isFixed}

          riskScore={
            currentRiskScore
          }

          severity={
            currentSeverity
          }

          entryPoint={
            entryPoint
          }

          weakness={
            weakness
          }

          criticalAsset={
            criticalAsset
          }

          blastRadius={
            blastRadius
          }

          attackPaths={
            attackPaths
          }
        />

        <RemediationPanel
          fixed={isFixed}

          simulation={
            simulation
          }

          simulating={
            simulating
          }

          onFix={
            simulateFix
          }

          onFixSet={
            simulateRemediationSet
          }

          optimizedRemediations={
            optimizedRemediations
          }

          selectedRemediation={
            selectedRemediation
          }

          onSelectRemediation={
            setSelectedRemediation
          }
        />

      </div>

      <div
        style={{
          marginTop: "24px",
        }}
      >

        <PersonaPanel
          personaRankings={
            personaRankings
          }
        />

      </div>

    </div>
  );
}