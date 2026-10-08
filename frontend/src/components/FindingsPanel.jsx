export default function FindingsPanel({
  findings = [],
  summary = {},
}) {
  const severityClass = (severity) => {
    if (severity === "CRITICAL") return "critical";
    if (severity === "HIGH") return "high";
    if (severity === "MEDIUM") return "medium";
    return "low";
  };

  return (
    <div
      className="panel"
      style={{
        marginTop: "24px",
      }}
    >
      <div className="panel-header">
        <div>
          <span className="eyebrow">
            SECURITY FINDINGS
          </span>

          <h2>
            Detected Weaknesses
          </h2>

          <p
            style={{
              marginTop: "6px",
              opacity: 0.7,
            }}
          >
            Configuration weaknesses identified during CloudShield analysis.
          </p>
        </div>

        <span className="status-badge critical">
          {summary.total_findings || findings.length} FINDINGS
        </span>
      </div>

      {findings.length === 0 ? (
        <div
          style={{
            padding: "24px",
            textAlign: "center",
            opacity: 0.7,
          }}
        >
          No security findings detected.
        </div>
      ) : (
        <>
          <div
            style={{
              display: "flex",
              gap: "10px",
              flexWrap: "wrap",
              marginBottom: "18px",
            }}
          >
            <span className="status-badge critical">
              Critical: {summary.critical_findings || 0}
            </span>

            <span className="status-badge critical">
              High: {summary.high_findings || 0}
            </span>

            <span className="status-badge">
              Medium: {summary.medium_findings || 0}
            </span>

            <span className="status-badge">
              Low: {summary.low_findings || 0}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gap: "12px",
            }}
          >
            {findings.map((finding) => (
              <div
                key={finding.finding_id}
                style={{
                  padding: "18px",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: "10px",
                  background: "rgba(255,255,255,0.02)",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: "12px",
                    flexWrap: "wrap",
                  }}
                >
                  <div>
                    <strong>
                      {finding.finding_id}
                    </strong>

                    <span
                      style={{
                        marginLeft: "10px",
                        opacity: 0.7,
                      }}
                    >
                      {finding.type}
                    </span>
                  </div>

                  <span
                    className={`status-badge ${severityClass(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>
                </div>

                <div
                  style={{
                    marginTop: "12px",
                    display: "grid",
                    gap: "7px",
                  }}
                >
                  <div>
                    <strong>Resource:</strong>{" "}
                    {finding.resource || "N/A"}
                  </div>

                  <div style={{ opacity: 0.8 }}>
                    {finding.description}
                  </div>

                  <div style={{ opacity: 0.7 }}>
                    <strong>Impact:</strong>{" "}
                    {finding.impact}
                  </div>

                  <div style={{ opacity: 0.7 }}>
                    <strong>Evidence:</strong>{" "}
                    {finding.evidence}
                  </div>

                  <div
                    style={{
                      marginTop: "5px",
                      opacity: 0.9,
                    }}
                  >
                    <strong>Remediation:</strong>{" "}
                    {finding.remediation}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
