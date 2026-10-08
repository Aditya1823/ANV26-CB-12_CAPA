export default function RiskPanel({
  fixed = false,
  riskScore = 0,
  severity = "UNKNOWN",
  entryPoint = "Unknown",
  weakness = "Security weakness detected",
  criticalAsset = "Unknown",
  blastRadius = 0,
  attackPaths = [],
  simulation = null,
}) {
  const primaryAttackPath = attackPaths[0] || null;
  const normalizedSeverity =
    severity?.toUpperCase() || "UNKNOWN";

  const isSecure =
    fixed ||
    normalizedSeverity === "SECURE";

  const severityClass = isSecure
    ? "secure"
    : normalizedSeverity.toLowerCase();

  const primaryPath =
    attackPaths?.[0]?.path || [];

  return (
    <div className="panel risk-panel">

      <div className="panel-header">

        <div>
          <span className="eyebrow">
            SECURITY ASSESSMENT
          </span>

          <h2>
            Risk Analysis
          </h2>
        </div>

        <span
          className={`status-badge ${
            isSecure
              ? "safe"
              : "critical"
          }`}
        >
          {isSecure
            ? "PROTECTED"
            : normalizedSeverity}
        </span>

      </div>

      <div
        className={`risk-overview ${severityClass}`}
      >

        <div className="risk-score-box">

          <span className="risk-score-label">
            RISK SCORE
          </span>

          <strong>
            {riskScore}
          </strong>

          <span className="risk-score-max">
            / 100
          </span>

        </div>

        <div className="risk-state">

          <span className="risk-state-label">
            SECURITY STATE
          </span>

          <strong>
            {isSecure
              ? "SECURE"
              : normalizedSeverity}
          </strong>

          <p>
            {isSecure
              ? "The dangerous path is no longer reachable."
              : "A critical asset is reachable from an exposed entry point."}
          </p>

        </div>

      </div>

      {primaryPath.length > 0 && (
        <div className="risk-section">

          <span className="section-label">
            ATTACK PATH
          </span>

          <div className="attack-path-display">

            {primaryPath.map(
              (node, index) => (
                <span
                  className="attack-path-node"
                  key={`${node}-${index}`}
                >

                  {node}

                  {index <
                    primaryPath.length - 1 && (
                    <span className="attack-path-arrow">
                      →
                    </span>
                  )}

                </span>
              )
            )}

          </div>

        </div>
      )}

      <div className="risk-section">

        <span className="section-label">
          WHY IS THIS DANGEROUS?
        </span>

        <div className="danger-chain">

          <div className="danger-item">

            <div className="danger-icon">
              01
            </div>

            <div>
              <span>
                ENTRY POINT
              </span>

              <strong>
                {entryPoint}
              </strong>
            </div>

          </div>

          <div className="danger-arrow">
            ↓
          </div>

          <div className="danger-item">

            <div className="danger-icon warning">
              02
            </div>

            <div>
              <span>
                WEAKNESS
              </span>

              <strong>
                {weakness}
              </strong>
            </div>

          </div>

          <div className="danger-arrow">
            ↓
          </div>

          <div className="danger-item">

            <div className="danger-icon critical">
              03
            </div>

            <div>
              <span>
                CRITICAL ASSET
              </span>

              <strong>
                {criticalAsset}
              </strong>
            </div>

          </div>

        </div>

      </div>

      <div className="risk-stat-grid">

        <div className="risk-stat">

          <span>
            BLAST RADIUS
          </span>

          <strong>
            {blastRadius}
          </strong>

          <small>
            affected resources
          </small>

        </div>

        <div className="risk-stat">

          <span>
            DANGEROUS PATHS
          </span>

          <strong>
            {simulation
              ? simulation.remaining_paths?.length || 0
              : attackPaths.length}
          </strong>

          <small>
            detected routes
          </small>

        </div>

      </div>

      {primaryAttackPath?.blast_radius && (
        <div className="blast-radius-section">

          <div className="blast-radius-header">
            <div>
              <span className="section-label">
                IMPACT ANALYSIS
              </span>

              <h3>
                Affected Resources
              </h3>
            </div>

            <span className="blast-radius-count">
              {primaryAttackPath.blast_radius.affected_resource_count || 0}
            </span>
          </div>

          <p className="blast-radius-description">
            Resources reachable if the attack path is compromised.
          </p>

          <div className="affected-resource-list">
            {(
              primaryAttackPath.blast_radius.affected_resources || []
            ).map((resource) => {

              const isCritical =
                (
                  primaryAttackPath.blast_radius.critical_resources || []
                ).includes(resource);

              return (
                <div
                  className={`affected-resource ${
                    isCritical ? "critical-resource" : ""
                  }`}
                  key={resource}
                >
                  <span className="resource-status">
                    {isCritical ? "!" : "•"}
                  </span>

                  <span>
                    {resource}
                  </span>

                  {isCritical && (
                    <small>
                      CRITICAL
                    </small>
                  )}
                </div>
              );
            })}
          </div>

          <div className="blast-radius-footer">
            <span>
              Critical resources
            </span>

            <strong>
              {primaryAttackPath.blast_radius.critical_resource_count || 0}
            </strong>
          </div>

        </div>
      )}

      <div className="simulation-note">
        <span>i</span>
        <p>
          Blast radius is calculated from the current attack graph.
          What-If remediation is simulated on a copy; no cloud resources are changed.
        </p>
      </div>

    </div>
  );
}