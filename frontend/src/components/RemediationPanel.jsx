function formatAction(action) {
  const labels = {
    REMOVE_INTERNET_EXPOSURE:
      "Remove Internet Exposure",

    REDUCE_EXCESSIVE_PERMISSION:
      "Reduce Excessive Permission",

    REMOVE_ADMIN_PERMISSION:
      "Remove Admin Permission",

    REMOVE_PUBLIC_ACCESS:
      "Remove Public Access",

    REMOVE_DANGEROUS_CONNECTION:
      "Remove Dangerous Connection",
  };

  return labels[action] || action;
}

function formatResource(resource) {
  const labels = {
    api: "Internet API",
    server: "Web Server",
    iam: "IAM Role",
    iam_a: "IAM Role A",
    iam_b: "IAM Role B",
    database: "Critical Database",
  };

  return labels[resource] || resource;
}

function getDisruptionLabel(cost) {
  if (cost <= 3) {
    return "LOW";
  }

  if (cost <= 6) {
    return "MEDIUM";
  }

  return "HIGH";
}

function getDisruptionClass(cost) {
  if (cost <= 3) {
    return "low";
  }

  if (cost <= 6) {
    return "medium";
  }

  return "high";
}

function getActionDescription(action) {
  const descriptions = {
    REMOVE_INTERNET_EXPOSURE:
      "Remove the resource's direct internet exposure.",

    REDUCE_EXCESSIVE_PERMISSION:
      "Reduce excessive permissions and remove the associated permission path.",

    REMOVE_ADMIN_PERMISSION:
      "Remove unnecessary administrative privileges.",

    REMOVE_PUBLIC_ACCESS:
      "Restrict public access to the resource.",

    REMOVE_DANGEROUS_CONNECTION:
      "Remove the dangerous relationship between resources.",
  };

  return (
    descriptions[action] ||
    "Apply the recommended security control."
  );
}

function ActionBadge({ action }) {
  return (
    <span className="remediation-action-badge">
      {formatAction(action)}
    </span>
  );
}

function StrategyMetrics({ strategy }) {
  return (
    <div className="strategy-metrics">

      <div className="strategy-metric">
        <span>
          PATHS BROKEN
        </span>

        <strong>
          {strategy.broken_attack_paths ?? 0}
        </strong>
      </div>

      <div className="strategy-metric">
        <span>
          REMAINING
        </span>

        <strong>
          {strategy.remaining_attack_paths ?? 0}
        </strong>
      </div>

      <div className="strategy-metric">
        <span>
          SECURITY
        </span>

        <strong>
          {strategy.security_score ?? 0}%
        </strong>
      </div>

      <div className="strategy-metric">
        <span>
          DISRUPTION
        </span>

        <strong>
          {strategy.disruption_cost ?? 0}
        </strong>
      </div>

    </div>
  );
}

function SimulationResult({
  simulation,
}) {
  if (!simulation) {
    return null;
  }

  const beforePaths =
    simulation.before?.attack_paths ?? 0;

  const afterPaths =
    simulation.after?.attack_paths ?? 0;

  const beforeRisk =
    simulation.before?.risk_score ?? 0;

  const afterRisk =
    simulation.after?.risk_score ?? 0;

  const riskReduction =
    simulation.risk_reduction ?? 0;

  const pathBroken =
    simulation.path_broken === true;

  return (
    <div
      className={`simulation-result ${
        pathBroken
          ? "simulation-success"
          : "simulation-partial"
      }`}
    >

      <div className="simulation-result-header">

        <div className="simulation-result-icon">
          {pathBroken ? "✓" : "!"}
        </div>

        <div>

          <span className="eyebrow">
            WHAT-IF SIMULATION RESULT
          </span>

          <h3>
            {pathBroken
              ? "Attack Path Eliminated"
              : "Alternate Path Remains"}
          </h3>

        </div>

      </div>

      <div className="before-after-grid">

        <div className="before-after-card">

          <span>
            BEFORE
          </span>

          <strong>
            {beforePaths}
          </strong>

          <small>
            attack paths
          </small>

          <div className="risk-mini">
            Risk Score:{" "}
            <b>{beforeRisk}</b>
          </div>

        </div>

        <div className="transition-arrow">
          →
        </div>

        <div className="before-after-card">

          <span>
            AFTER
          </span>

          <strong>
            {afterPaths}
          </strong>

          <small>
            attack paths
          </small>

          <div className="risk-mini">
            Risk Score:{" "}
            <b>{afterRisk}</b>
          </div>

        </div>

      </div>

      <div className="simulation-metrics">

        <div>
          <span>
            RISK REDUCTION
          </span>

          <strong>
            {riskReduction}
          </strong>
        </div>

        <div>
          <span>
            PATH STATUS
          </span>

          <strong>
            {pathBroken
              ? "BROKEN"
              : "STILL ACTIVE"}
          </strong>
        </div>

      </div>

      {pathBroken ? (

        <div className="verification-message success">

          <span>
            ✓
          </span>

          <div>

            <strong>
              Remediation verified
            </strong>

            <p>
              CloudShield recalculated the
              security graph and confirmed
              that the dangerous attack path
              is no longer reachable.
            </p>

          </div>

        </div>

      ) : (

        <div className="verification-message warning">

          <span>
            ⚠
          </span>

          <div>

            <strong>
              Alternate attack path remains
            </strong>

            <p>
              The selected remediation reduced
              the attack surface, but at least
              one path to a critical asset is
              still reachable.
            </p>

          </div>

        </div>

      )}

      {simulation.multi_fix &&
        simulation.remediations?.length > 0 && (

        <div className="applied-remediations">

          <span className="section-label">
            APPLIED STRATEGY
          </span>

          {simulation.remediations.map(
            (remediation, index) => (

              <div
                className="applied-remediation"
                key={`${remediation.action}-${remediation.resource}-${index}`}
              >

                <span>
                  {index + 1}
                </span>

                <div>

                  <strong>
                    {formatAction(
                      remediation.action
                    )}
                  </strong>

                  <small>
                    {formatResource(
                      remediation.resource
                    )}

                    {remediation.target
                      ? ` → ${formatResource(
                          remediation.target
                        )}`
                      : ""}
                  </small>

                </div>

              </div>

            )
          )}

        </div>

      )}

    </div>
  );
}

export default function RemediationPanel({
  fixed = false,
  simulation = null,
  simulating = false,
  onFix,
  onFixSet,
  optimizedRemediations = [],
  selectedRemediation = null,
  onSelectRemediation,
}) {
  const bestStrategy =
    optimizedRemediations[0] || null;

  const hasSimulation =
    simulation !== null;

  const isProtected =
    simulation?.path_broken === true ||
    fixed === true;

  const isPartial =
    hasSimulation && !isProtected;

  const handleStrategySimulation = () => {
    if (!bestStrategy) {
      return;
    }

    const actions =
      bestStrategy.actions || [];

    if (
      actions.length > 1 &&
      onFixSet
    ) {
      onFixSet(
        actions.map((action) => ({
          action: action.action,
          resource: action.resource,
          target: action.target || null,
        }))
      );

      return;
    }

    if (actions.length === 1) {
      if (onFix) {
        onFix({
          action: actions[0].action,
          resource: actions[0].resource,
          target:
            actions[0].target || null,
        });
      }

      return;
    }

    if (selectedRemediation && onFix) {
      onFix(selectedRemediation);
    }
  };

  const handleIndividualFix = (
    strategy
  ) => {
    if (!strategy) {
      return;
    }

    const actions =
      strategy.actions || [];

    if (
      actions.length > 1 &&
      onFixSet
    ) {
      onFixSet(
        actions.map((action) => ({
          action: action.action,
          resource: action.resource,
          target: action.target || null,
        }))
      );

      return;
    }

    if (
      actions.length === 1 &&
      onFix
    ) {
      onFix({
        action: actions[0].action,
        resource: actions[0].resource,
        target:
          actions[0].target || null,
      });
    }
  };

  return (
    <div className="panel remediation-panel">

      <div className="panel-header">

        <div>

          <span className="eyebrow">
            REMEDIATION OPTIMIZER
          </span>

          <h2>
            Fix the Attack Path
          </h2>

          <p className="panel-subtitle">
            Find the smallest remediation
            strategy that breaks dangerous
            paths with minimal disruption.
          </p>

        </div>

        <span
          className={
            isProtected
              ? "status-badge safe"
              : isPartial
              ? "status-badge warning"
              : "status-badge critical"
          }
        >
          {isProtected
            ? "PROTECTED"
            : isPartial
            ? "PARTIAL FIX"
            : "ACTION REQUIRED"}
        </span>

      </div>

      {hasSimulation ? (

        <SimulationResult
          simulation={simulation}
        />

      ) : bestStrategy ? (

        <>

          <div className="best-strategy">

            <div className="best-strategy-top">

              <div>

                <span className="strategy-label">
                  🏆 RECOMMENDED STRATEGY
                </span>

                <h3>
                  {bestStrategy.action_count ===
                  1
                    ? "Minimum Effective Fix"
                    : "Optimized Multi-Fix Strategy"}
                </h3>

              </div>

              <div className="efficiency-badge">

                <span>
                  EFFICIENCY
                </span>

                <strong>
                  {bestStrategy.efficiency_score}
                </strong>

              </div>

            </div>

            <div className="strategy-actions">

              {(
                bestStrategy.actions ||
                []
              ).map(
                (action, index) => (

                  <div
                    className="strategy-action"
                    key={`${action.action}-${action.resource}-${index}`}
                  >

                    <div className="strategy-action-number">
                      {index + 1}
                    </div>

                    <div className="strategy-action-content">

                      <ActionBadge
                        action={
                          action.action
                        }
                      />

                      <strong>
                        {formatResource(
                          action.resource
                        )}
                      </strong>

                      <p>
                        {getActionDescription(
                          action.action
                        )}
                      </p>

                      {action.target && (
                        <small>
                          Target:{" "}
                          {formatResource(
                            action.target
                          )}
                        </small>
                      )}

                    </div>

                  </div>

                )
              )}

            </div>

            <StrategyMetrics
              strategy={
                bestStrategy
              }
            />

            <div className="strategy-footer">

              <div className="disruption-indicator">

                <span>
                  BUSINESS DISRUPTION
                </span>

                <strong
                  className={getDisruptionClass(
                    bestStrategy.disruption_cost
                  )}
                >
                  {getDisruptionLabel(
                    bestStrategy.disruption_cost
                  )}
                </strong>

              </div>

              <button
                className="primary-action"
                onClick={
                  handleStrategySimulation
                }
                disabled={simulating}
              >
                {simulating
                  ? "SIMULATING..."
                  : "SIMULATE BEST STRATEGY →"}
              </button>

            </div>

          </div>

          {optimizedRemediations.length >
            1 && (

            <div className="alternative-strategies">

              <div className="section-heading">

                <div>
                  <span className="eyebrow">
                    ALTERNATIVES
                  </span>

                  <h3>
                    Other Remediation Options
                  </h3>
                </div>

              </div>

              {optimizedRemediations
                .slice(1, 4)
                .map(
                  (strategy, index) => (

                    <div
                      className="alternative-card"
                      key={`${strategy.description}-${index}`}
                    >

                      <div className="alternative-rank">
                        #{index + 2}
                      </div>

                      <div className="alternative-content">

                        <strong>
                          {strategy.description}
                        </strong>

                        <div className="alternative-meta">

                          <span>
                            {strategy.broken_attack_paths}
                            {" "}
                            paths broken
                          </span>

                          <span>
                            {strategy.remaining_attack_paths}
                            {" "}
                            remaining
                          </span>

                          <span>
                            Security:{" "}
                            {strategy.security_score}%
                          </span>

                          <span>
                            Disruption:{" "}
                            {strategy.disruption_cost}
                          </span>

                        </div>

                      </div>

                      <button
                        className="secondary-action"
                        onClick={() =>
                          handleIndividualFix(
                            strategy
                          )
                        }
                        disabled={simulating}
                      >
                        Simulate
                      </button>

                    </div>

                  )
                )}

            </div>

          )}

        </>

      ) : (

        <div className="no-remediation">

          <div className="no-remediation-icon">
            ✓
          </div>

          <h3>
            No Remediation Required
          </h3>

          <p>
            CloudShield did not detect an
            actionable attack path in the
            current configuration.
          </p>

        </div>

      )}

    </div>
  );
}