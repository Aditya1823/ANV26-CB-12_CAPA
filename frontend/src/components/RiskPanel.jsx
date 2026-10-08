export default function RiskPanel({ fixed }) {
  return (
    <div className="panel risk-panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">SECURITY ASSESSMENT</span>
          <h2>Risk Analysis</h2>
        </div>

        <span className={fixed ? "status-badge safe" : "status-badge critical"}>
          {fixed ? "SECURE" : "CRITICAL"}
        </span>
      </div>

      <div className="risk-score">
        <div className={fixed ? "score safe-score" : "score"}>
          {fixed ? "18" : "92"}
        </div>

        <div>
          <strong>{fixed ? "Low Risk" : "Critical Risk"}</strong>
          <p>
            {fixed
              ? "Critical attack path has been broken."
              : "Critical asset is reachable from an exposed entry point."}
          </p>
        </div>
      </div>

      <div className="risk-details">
        <div>
          <span>Entry Point</span>
          <strong>Public API</strong>
        </div>

        <div>
          <span>Weakness</span>
          <strong>Excessive IAM Permission</strong>
        </div>

        <div>
          <span>Critical Asset</span>
          <strong>Customer Database</strong>
        </div>

        <div>
          <span>Blast Radius</span>
          <strong>4 Resources</strong>
        </div>
      </div>
    </div>
  );
}
