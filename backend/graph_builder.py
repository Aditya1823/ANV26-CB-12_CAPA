import networkx as nx
from models import CloudConfiguration


def build_security_graph(config: CloudConfiguration) -> nx.DiGraph:
    """
    Convert cloud configuration into a directed security graph.
    """

    graph = nx.DiGraph()

    # Add resources as graph nodes
    for resource in config.resources:
        graph.add_node(
            resource.id,
            type=resource.type,
            internet_exposed=resource.internet_exposed,
            critical=resource.critical,
            excessive_permission=resource.excessive_permission,
            admin_permission=resource.admin_permission,
            public_access=resource.public_access,
            sensitivity=resource.sensitivity
        )

    # Add connections as graph edges
    for connection in config.connections:
        graph.add_edge(
            connection.source,
            connection.target,
            type=connection.type,
            permission=connection.permission,
            dangerous=connection.dangerous
        )

    return graph