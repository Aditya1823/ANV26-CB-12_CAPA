function getPersonaIcon(personaId, personaName) {
  const key = `${personaId || ""} ${personaName || ""}`.toLowerCase();

  if (key.includes("internet")) {
    return "🌐";
  }

  if (
    key.includes("privilege") ||
    key.includes("escalator")
  ) {
    return "🔑";
  }

  if (
    key.includes("data") ||
    key.includes("thief")
  ) {
    return "🗄️";
  }

  return "🎯";
}

function getPersonaClass(personaId, personaName) {
  const key = `${personaId || ""} ${personaName || ""}`.toLowerCase();

  if (key.includes("internet")) {
    return "internet";
  }

  if (
    key.includes("privilege") ||
    key.includes("escalator")
  ) {
    return "privilege";
  }

  if (
    key.includes("data") ||
    key.includes("thief")
  ) {
    return "data";
  }

  return "default";
}

function getPriorityLabel(score, maxScore) {
  if (!maxScore || maxScore <= 0) {
    return "LOW PRIORITY";
  }

  const percentage =
    (score / maxScore) * 100;

  if (percentage >= 80) {
    return "HIGH PRIORITY";
  }

  if (percentage >= 50) {
    return "MEDIUM PRIORITY";
  }

  return "LOW PRIORITY";
}

function getFactorLabel(factor) {
  const labels = {
    internet_exposed:
      "Internet Exposure",

    excessive_permission:
      "Excessive Permission",

    admin_permission:
      "Admin Permission",

    critical_asset:
      "Critical Asset",
  };

  return (
    labels[factor] ||
    factor
      ?.replaceAll("_", " ")
      ?.replace(/\b\w/g, (char) =>
        char.toUpperCase()
      ) ||
    "Security Factor"
  );
}

export default function PersonaPanel({
  personaRankings = {},
}) {
  const personaEntries =
    Object.entries(personaRankings);

  if (personaEntries.length === 0) {
    return (
      <div className="panel persona-panel">

        <div className="panel-header">

          <div>
            <span className="eyebrow">
              ADVERSARY MODELING
            </span>

            <h2>
              Adversary Persona Engine
            </h2>
          </div>

        </div>

        <div className="persona-empty">
          No adversary persona analysis
          available for this scenario.
        </div>

      </div>
    );
  }

  return (
    <div className="panel persona-panel">

      <div className="panel-header">

        <div>

          <span className="eyebrow">
            ADVERSARY MODELING
          </span>

          <h2>
            Adversary Persona Engine
          </h2>

          <p className="panel-subtitle">
            Different attackers prioritize
            different attack paths.
          </p>

        </div>

        <span className="status-badge">
          {personaEntries.length} PERSONAS
        </span>

      </div>

      <div className="persona-grid">

        {personaEntries.map(
          ([personaId, personaData]) => {
            const rankings =
              Array.isArray(personaData)
                ? personaData
                : personaData?.ranked_paths ||
                  personaData?.paths ||
                  [];

            if (rankings.length === 0) {
              return (
                <div
                  className="persona-card"
                  key={personaId}
                >

                  <div className="persona-card-header">

                    <div className="persona-icon">
                      {getPersonaIcon(
                        personaId
                      )}
                    </div>

                    <div>
                      <h3>
                        {personaData?.persona ||
                          personaData?.name ||
                          personaId}
                      </h3>

                      <span>
                        No attack paths
                      </span>
                    </div>

                  </div>

                </div>
              );
            }

            const sortedRankings =
              [...rankings].sort(
                (a, b) =>
                  (b.persona_score || 0) -
                  (a.persona_score || 0)
              );

            const highestScore =
              sortedRankings[0]
                ?.persona_score || 0;

            const topPath =
              sortedRankings[0];

            const personaName =
              topPath?.persona ||
              personaData?.persona ||
              personaData?.name ||
              personaId;

            const description =
              topPath?.description ||
              personaData?.description ||
              "Prioritizes attack paths based on its adversary behavior model.";

            const personaClass =
              getPersonaClass(
                personaId,
                personaName
              );

            return (
              <div
                className={`persona-card ${personaClass}`}
                key={personaId}
              >

                <div className="persona-card-header">

                  <div className="persona-icon">
                    {getPersonaIcon(
                      personaId,
                      personaName
                    )}
                  </div>

                  <div className="persona-title">

                    <h3>
                      {personaName}
                    </h3>

                    <span>
                      {getPriorityLabel(
                        highestScore,
                        highestScore
                      )}
                    </span>

                  </div>

                </div>

                <p className="persona-description">
                  {description}
                </p>

                <div className="persona-score">

                  <div>

                    <span>
                      TOP PATH SCORE
                    </span>

                    <strong>
                      {Math.round(
                        highestScore
                      )}
                    </strong>

                  </div>

                  <div className="persona-path">

                    <span>
                      PRIORITIZED PATH
                    </span>

                    <strong>
                      {topPath?.entry_point ||
                        "Unknown"}
                      {" → "}
                      {topPath?.target ||
                        "Unknown"}
                    </strong>

                  </div>

                </div>

                <div className="persona-factors">

                  <span className="factor-heading">
                    WHY THIS PATH?
                  </span>

                  {(
                    topPath?.factors || []
                  )
                    .slice(0, 4)
                    .map(
                      (factor, index) => (
                        <div
                          className="factor-row"
                          key={`${factor.factor}-${index}`}
                        >

                          <span>
                            {getFactorLabel(
                              factor.factor
                            )}
                          </span>

                          <strong>
                            +
                            {Math.round(
                              factor.contribution
                            )}
                          </strong>

                        </div>
                      )
                    )}

                </div>

                {sortedRankings.length >
                  1 && (

                  <div className="persona-alternates">

                    <span>
                      OTHER PATH PRIORITIES
                    </span>

                    {sortedRankings
                      .slice(1, 3)
                      .map(
                        (path, index) => (
                          <div
                            className="alternate-path"
                            key={`${path.entry_point}-${path.target}-${index}`}
                          >

                            <span>
                              {path.entry_point}
                              {" → "}
                              {path.target}
                            </span>

                            <strong>
                              {Math.round(
                                path.persona_score ||
                                  0
                              )}
                            </strong>

                          </div>
                        )
                      )}

                  </div>

                )}

              </div>
            );
          }
        )}

      </div>

      <div className="persona-explanation">

        <div className="persona-explanation-icon">
          🧠
        </div>

        <div>

          <strong>
            Why persona-based analysis?
          </strong>

          <p>
            CloudShield does not assume every
            attacker follows the same strategy.
            The Persona Engine re-ranks detected
            attack paths according to attacker
            behavior, helping security teams
            prioritize the paths most relevant
            to a specific threat.
          </p>

        </div>

      </div>

    </div>
  );
}