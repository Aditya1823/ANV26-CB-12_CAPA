PERSONAS = {
    "internet_opportunist": {
        "name": "Internet Opportunist",

        "description": (
            "Prioritizes externally exposed attack "
            "surfaces and publicly reachable resources."
        ),

        "weights": {
            "internet_exposed": 2.0,
            "excessive_permission": 0.9,
            "critical_asset": 1.0,
            "admin_permission": 0.7
        }
    },

    "privilege_escalator": {
        "name": "Privilege Escalator",

        "description": (
            "Prioritizes excessive and administrative "
            "privileges that enable privilege escalation."
        ),

        "weights": {
            "internet_exposed": 0.8,
            "excessive_permission": 1.8,
            "critical_asset": 1.0,
            "admin_permission": 2.2
        }
    },

    "data_thief": {
        "name": "Data Thief",

        "description": (
            "Prioritizes attack paths that reach "
            "sensitive or critical data assets."
        ),

        "weights": {
            "internet_exposed": 0.8,
            "excessive_permission": 1.1,
            "critical_asset": 2.2,
            "admin_permission": 1.0
        }
    }
}