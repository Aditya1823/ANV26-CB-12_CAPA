import { useState } from "react";
import AttackGraph from "./AttackGraph";
import RiskPanel from "./RiskPanel";
import RemediationPanel from "./RemediationPanel";
import { mockData } from "../data/mockData";

export default function Dashboard() {
  const [fixed, setFixed] = useState(false);

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">C</div>
          <div>
            <h1>CloudShield</h1>
            <span>Cloud Attack Path Analyzer</span>
          </div>
        </div>

        <div className="header-status">
          <span className="live-dot"></span>
          Synthetic Environment
        </div>
      </header>

      <main className="dashboard">
        <section className="hero">
          <div>
            <span className="eyebrow">SECURITY OVERVIEW</span>
            <h2>Cloud Attack Path Analysis</h2>
            <p>
              Detect hidden paths from exposed cloud resources to critical
              assets and simulate remediation.
            </p>
          </div>

          <div className={fixed ? "overall-status safe" : "overall-status"}>
            <span>{fixed ? "✓" : "!"}</span>
            <div>
              <small>OVERALL STATUS</small>
              <strong>{fixed ? "PROTECTED" : "CRITICAL RISK"}</strong>
            </div>
          </div>
        </section>

        <section className="stats-grid">
          <div className="stat-card">
            <span>RESOURCES</span>
            <strong>{mockData.stats.resources}</strong>
            <small>Analyzed</small>
          </div>

          <div className="stat-card">
            <span>ATTACK PATHS</span>
            <strong>{fixed ? 0 : mockData.stats.attackPaths}</strong>
            <small>{fixed ? "All paths blocked" : "Critical paths found"}</small>
          </div>

          <div className="stat-card">
            <span>CRITICAL ASSETS</span>
            <strong>{mockData.stats.criticalAssets}</strong>
            <small>Protected targets</small>
          </div>

          <div className="stat-card">
            <span>RISK SCORE</span>
            <strong className={fixed ? "score-green" : "score-red"}>
              {fixed ? 18 : mockData.stats.riskScore}
            </strong>
            <small>{fixed ? "Low risk" : "Critical"}</small>
          </div>
        </section>

        <section className="section-title">
          <div>
            <span className="eyebrow">ATTACK GRAPH</span>
            <h2>Detected Attack Path</h2>
          </div>

          <span className={fixed ? "path-status fixed" : "path-status"}>
            {fixed ? "● PATH BROKEN" : "● ACTIVE PATH"}
          </span>
        </section>

        <AttackGraph fixed={fixed} />

        <section className="two-column">
          <RiskPanel fixed={fixed} />
          <RemediationPanel fixed={fixed} onFix={() => setFixed(true)} />
        </section>
      </main>
    </div>
  );
}
