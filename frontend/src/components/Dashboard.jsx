import { useEffect, useMemo, useRef, useState } from "react";

import AttackGraph from "./AttackGraph";
import RiskPanel from "./RiskPanel";
import RemediationPanel from "./RemediationPanel";
import PersonaPanel from "./PersonaPanel";
import FindingsPanel from "./FindingsPanel";

const API_BASE = "http://127.0.0.1:8001";

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

  const [uploadedConfiguration, setUploadedConfiguration] =
    useState(null);

  const [uploadedFileName, setUploadedFileName] =
    useState("");

  const fileInputRef = useRef(null);

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

  const activeConfiguration =
    uploadedConfiguration ||
    scenario.configuration;

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
              activeConfiguration,
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

  const handleFileUpload = async (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    // Reset the native file input so another file can be selected
    // immediately, including the same file again.
    if (event.target) {
      event.target.value = "";
    }

    try {
      setLoading(true);
      setError("");
      setSimulation(null);
      setSelectedRemediation(null);

      const response = await fetch(
        `${API_BASE}/security/analyze-file`,
        {
          method: "POST",
          body: (() => {
            const formData = new FormData();
            formData.append("file", file);
            return formData;
          })(),
        }
      );

      if (!response.ok) {
        let detail = "";
        try {
          const errorData = await response.json();
          detail = errorData.detail || JSON.stringify(errorData);
        } catch {
          detail = await response.text();
        }
        throw new Error(
          `File analysis failed (${response.status}): ${detail}`
        );
      }

      const data = await response.json();

      if (!data.configuration) {
        throw new Error(
          "Uploaded file is not a valid CloudShield configuration"
        );
      }

      setUploadedConfiguration(data.configuration);
      setUploadedFileName(file.name);

      const analyzeResponse = await fetch(
        `${API_BASE}/analyze`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            configuration: data.configuration,
          }),
        }
      );

      if (!analyzeResponse.ok) {
        throw new Error("CloudShield analysis failed");
      }

      const analysisData =
        await analyzeResponse.json();

      setAnalysis({
        ...analysisData,
        findings:
          data.findings ||
          analysisData.findings ||
          [],
        findings_summary:
          data.findings_summary ||
          analysisData.findings_summary ||
          data.summary ||
          {},
      });
    } catch (err) {
      console.error(err);
      setError(
        err.message ||
        "Unable to analyze uploaded configuration."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearUploadedConfiguration = () => {
    setUploadedConfiguration(null);
    setUploadedFileName("");
    setAnalysis(null);
    setSimulation(null);
    setSelectedRemediation(null);
    setError("");

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
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
              activeConfiguration,

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
              activeConfiguration,

            remediations: remediationSet,
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
    if (!uploadedConfiguration) {
      analyzeConfiguration();
    }
  }, [selectedScenario, uploadedConfiguration]);

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

  const baseSummary =
    analysis?.summary || {
      total_resources: 0,
      critical_assets: 0,
      dangerous_paths: 0,
      highest_risk: 0,
    };

  const summary = simulation
    ? {
        ...baseSummary,
        dangerous_paths: simulation.remaining_paths?.length || 0,
        highest_risk:
          simulation.after?.risk_score ?? baseSummary.highest_risk,
      }
    : baseSummary;

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
            
            onChange={(event) => {
              setSelectedScenario(event.target.value);
              setUploadedConfiguration(null);
              setUploadedFileName("");
              setAnalysis(null);
              setSimulation(null);
              setSelectedRemediation(null);
            }}
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

      <div
        className="panel"
        style={{
          marginTop: "24px",
          marginBottom: "24px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            gap: "20px",
            flexWrap: "wrap",
          }}
        >
          <div>
            <span className="eyebrow">
              REAL CONFIGURATION ANALYSIS
            </span>

            <h2>
              Upload Cloud Configuration
            </h2>

            <p
              style={{
                marginTop: "6px",
                opacity: 0.7,
              }}
            >
              Upload a JSON or YAML configuration for full CloudShield analysis.
            </p>

            {uploadedFileName && (
              <p
                style={{
                  marginTop: "8px",
                  opacity: 0.85,
                }}
              >
                Loaded: <strong>{uploadedFileName}</strong>
              </p>
            )}
          </div>

          <div
            style={{
              display: "flex",
              gap: "10px",
              alignItems: "center",
            }}
          >
            <label
              className="secondary-action"
              style={{
                cursor: "pointer",
                display: "inline-flex",
                alignItems: "center",
              }}
            >
              Choose Config File
              <input
                type="file"
                accept=".json,.yaml,.yml,.env,.ini,.cfg,.conf,.properties,.toml,.txt"
                onChange={handleFileUpload}
                style={{ display: "none" }}
              />
            </label>

            {uploadedConfiguration && (
              <button
                className="secondary-action"
                onClick={clearUploadedConfiguration}
              >
                Clear Upload
              </button>
            )}
          </div>
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
                activeConfiguration
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

          simulation={simulation}
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