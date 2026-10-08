export default function RemediationPanel({ fixed, onFix }) {
  return (
    <div className="panel remediation-panel">
      <div className="panel-header">
        <div>
          <span className="eyebrow">REMEDIATION</span>
          <h2>Recommended Fix</h2>
        </div>
      </div>

      {!fixed ? (
        <>
          <div className="fix-card">
            <div className="fix-icon">🛡</div>
            <div>
              <h3>Remove database permission</h3>
              <p>
                Remove unnecessary database access from the Web Server IAM
                role.
              </p>
            </div>
          </div>

          <div className="impact">
            <span>Expected Impact</span>
            <strong>Breaks the critical attack path</strong>
          </div>

          <button className="simulate-button" onClick={onFix}>
            SIMULATE FIX
          </button>
        </>
      ) : (
        <div className="success-box">
          <div className="success-icon">✓</div>
          <h3>Attack Path Broken</h3>
          <p>
            The simulated IAM permission removal prevents the Web Server from
            reaching the Customer Database.
          </p>

          <div className="after-result">
            <div>
              <span>Before</span>
              <strong className="danger-text">1 Attack Path</strong>
            </div>

            <div className="arrow">→</div>

            <div>
              <span>After</span>
              <strong className="success-text">0 Attack Paths</strong>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
