from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import (
    AnalyzeRequest,
    SimulateRemediationRequest,
    SimulateRemediationSetRequest,
)

from graph_builder import build_security_graph
from analyzer import find_attack_paths
from risk_engine import calculate_path_risk
from blast_radius import calculate_blast_radius
from remediation import generate_remediations
from optimizer import optimize_remediations
from persona_engine import rank_paths_by_persona
from what_if import simulate_remediation
from alternate_paths import find_alternate_paths
from what_if import simulate_remediation_set


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="CloudShield API",
    description=(
        "Cloud Attack Path Analyzer "
        "& Remediation Optimizer"
    ),
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "project": "CloudShield",
        "status": "running",
    }


# ============================================================
# ANALYZE
# ============================================================

@app.post("/analyze")
def analyze(
    request: AnalyzeRequest
):

    # --------------------------------------------------------
    # BUILD SECURITY GRAPH
    # --------------------------------------------------------

    graph = build_security_graph(
        request.configuration
    )

    # --------------------------------------------------------
    # FIND ATTACK PATHS
    # --------------------------------------------------------

    attack_paths = find_attack_paths(
        graph
    )

    results = []

    # --------------------------------------------------------
    # ANALYZE EVERY ATTACK PATH
    # --------------------------------------------------------

    for attack_path in attack_paths:

        path = attack_path["path"]

        risk = calculate_path_risk(
            graph,
            path
        )

        blast_radius = calculate_blast_radius(
            graph,
            path
        )

        alternate_paths = find_alternate_paths(
            graph,
            path
        )

        remediations = generate_remediations(
            graph,
            path
        )

        results.append({

            "entry_point":
                attack_path["entry_point"],

            "target":
                attack_path["target"],

            "path":
                path,

            "length":
                attack_path["length"],

            "risk_score":
                risk["score"],

            "severity":
                risk["severity"],

            "risk_reasons":
                risk["reasons"],

            "blast_radius":
                blast_radius,

            "alternate_paths":
                alternate_paths,

            "remediations":
                remediations,
        })


    # ========================================================
    # REMEDIATION OPTIMIZER
    # ========================================================

    optimized_remediations = optimize_remediations(
        graph,
        attack_paths
    )


    # ========================================================
    # ADVERSARY PERSONA ENGINE
    # ========================================================

    persona_rankings = {}

    personas = [
        "internet_opportunist",
        "privilege_escalator",
        "data_thief",
    ]

    for persona_id in personas:

        persona_rankings[
            persona_id
        ] = rank_paths_by_persona(
            graph,
            attack_paths,
            persona_id
        )


    # ========================================================
    # SUMMARY
    # ========================================================

    risk_scores = [
        item["risk_score"]
        for item in results
    ]

    summary = {

        "total_resources":
            len(
                request.configuration.resources
            ),

        "critical_assets":
            sum(
                1
                for resource
                in request.configuration.resources
                if resource.critical
            ),

        "dangerous_paths":
            len(results),

        "highest_risk":
            max(
                risk_scores,
                default=0
            ),
    }


    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "project":
            "CloudShield",

        "summary":
            summary,

        "attack_paths":
            results,

        "optimized_remediations":
            optimized_remediations,

        "persona_rankings":
            persona_rankings,
    }


# ============================================================
# SINGLE-FIX WHAT-IF SIMULATION
# ============================================================

@app.post("/simulate")
def simulate(
    request: SimulateRemediationRequest
):

    # --------------------------------------------------------
    # BUILD ORIGINAL GRAPH
    # --------------------------------------------------------

    graph = build_security_graph(
        request.configuration
    )

    # --------------------------------------------------------
    # ORIGINAL ATTACK PATHS
    # --------------------------------------------------------

    original_paths = find_attack_paths(
        graph
    )

    original_risk = 0

    if original_paths:

        original_risk = max(

            calculate_path_risk(
                graph,
                path["path"]
            )["score"]

            for path
            in original_paths
        )


    # --------------------------------------------------------
    # APPLY SINGLE REMEDIATION
    # --------------------------------------------------------

    simulation = simulate_remediation(
        graph,
        request.remediation
    )


    # --------------------------------------------------------
    # REMAINING RISK
    # --------------------------------------------------------

    remaining_risk = 0

    if simulation["paths"]:

        remaining_risk = max(

            path["risk_score"]

            for path
            in simulation["paths"]
        )


    # --------------------------------------------------------
    # RISK REDUCTION
    # --------------------------------------------------------

    risk_reduction = max(
        0,
        original_risk - remaining_risk
    )


    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {

        "project":
            "CloudShield",

        "remediation": {

            "action":
                request.remediation.action,

            "resource":
                request.remediation.resource,

            "target":
                request.remediation.target,
        },

        "before": {

            "attack_paths":
                len(original_paths),

            "risk_score":
                original_risk,
        },

        "after": {

            "attack_paths":
                simulation[
                    "remaining_attack_paths"
                ],

            "risk_score":
                remaining_risk,
        },

        "risk_reduction":
            risk_reduction,

        "path_broken":
            simulation[
                "path_broken"
            ],

        "remaining_paths":
            simulation[
                "paths"
            ],
    }


# ============================================================
# MULTI-FIX WHAT-IF SIMULATION
# ============================================================

@app.post("/simulate-set")
def simulate_set(
    request: SimulateRemediationSetRequest
):

    # --------------------------------------------------------
    # BUILD ORIGINAL GRAPH
    # --------------------------------------------------------

    graph = build_security_graph(
        request.configuration
    )


    # --------------------------------------------------------
    # ORIGINAL ATTACK PATHS
    # --------------------------------------------------------

    original_paths = find_attack_paths(
        graph
    )

    original_risk = 0

    if original_paths:

        original_risk = max(

            calculate_path_risk(
                graph,
                path["path"]
            )["score"]

            for path
            in original_paths
        )


    # --------------------------------------------------------
    # APPLY REMEDIATION SET
    # --------------------------------------------------------

    simulation = simulate_remediation_set(
        graph,
        request.remediations
    )


    # --------------------------------------------------------
    # REMAINING RISK
    # --------------------------------------------------------

    remaining_risk = 0

    if simulation["paths"]:

        remaining_risk = max(

            path["risk_score"]

            for path
            in simulation["paths"]
        )


    # --------------------------------------------------------
    # PATH REDUCTION
    # --------------------------------------------------------

    original_count = len(
        original_paths
    )

    remaining_count = simulation[
        "remaining_attack_paths"
    ]

    broken_paths = max(
        0,
        original_count - remaining_count
    )


    # --------------------------------------------------------
    # RISK REDUCTION
    # --------------------------------------------------------

    risk_reduction = max(
        0,
        original_risk - remaining_risk
    )


    # --------------------------------------------------------
    # SECURITY PERCENTAGE
    # --------------------------------------------------------

    security_percentage = round(

        (
            broken_paths
            / max(original_count, 1)
        ) * 100,

        2
    )


    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {

        "project":
            "CloudShield",

        "remediations": [

            {
                "action":
                    remediation.action,

                "resource":
                    remediation.resource,

                "target":
                    remediation.target,
            }

            for remediation
            in request.remediations
        ],

        "before": {

            "attack_paths":
                original_count,

            "risk_score":
                original_risk,
        },

        "after": {

            "attack_paths":
                remaining_count,

            "risk_score":
                remaining_risk,
        },

        "broken_attack_paths":
            broken_paths,

        "security_percentage":
            security_percentage,

        "risk_reduction":
            risk_reduction,

        "path_broken":
            simulation[
                "path_broken"
            ],

        "remaining_paths":
            simulation[
                "paths"
            ],
    }