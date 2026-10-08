export const mockData = {
  stats: {
    resources: 8,
    attackPaths: 1,
    criticalAssets: 1,
    riskScore: 92,
    blastRadius: 4,
  },

  attackPath: [
    { id: "internet", label: "Internet", type: "entry" },
    { id: "api", label: "Public API", type: "normal" },
    { id: "server", label: "Web Server", type: "normal" },
    { id: "iam", label: "Excessive IAM", type: "weakness" },
    { id: "database", label: "Customer Database", type: "critical" },
  ],

  remediation: {
    title: "Remove database permission",
    description:
      "Remove unnecessary database access from the Web Server IAM role.",
    impact: "Breaks the critical attack path",
  },
};
