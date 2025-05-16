from datetime import datetime, timezone
from enum import Enum
import json
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlow
from typing import Dict, Set
from collections import defaultdict

from typing import List
from datetime import datetime
from uuid import UUID

from typing import List
from uuid import uuid4
from core.models.dtos.Threat import Threat


def generate_mermaid_from_dataflow(dataflow_report: DataFlowReport) -> str:
    """
    Generate a Mermaid.js representation of the data flow from a DataFlowReport.

    :param dataflow_report: A DataFlowReport instance.
    :return: Mermaid.js format string representation of the data flow diagram.
    """
    mermaid = ["graph TD;"]  # Start the Mermaid diagram

    # Mapping of components by ID
    component_map = {}

    # Add nodes (External Entities, Processes, Data Stores)
    for entity in dataflow_report.external_entities:
        mermaid.append(f'    {entity.id}(("External Entity: {entity.name}"))')
        component_map[entity.id] = entity

    for process in dataflow_report.processes:
        mermaid.append(f'    {process.id}["Process: {process.name}"]')
        component_map[process.id] = process

    for store in dataflow_report.data_stores:
        mermaid.append(f'    {store.id}[("Data Store: {store.name}")]')
        component_map[store.id] = store

    # Add Trust Boundaries (Subgraphs)
    for boundary in dataflow_report.trust_boundaries:
        mermaid.append(f'    subgraph {boundary.id}["{boundary.name}"]')
        for component_id in boundary.component_ids:
            if component_id in component_map:
                mermaid.append(f"        {component_id}")
        mermaid.append("    end")

    # Add edges (Data Flows)
    for node in (
        dataflow_report.external_entities
        + dataflow_report.processes
        + dataflow_report.data_stores
    ):
        for flow in node.data_flows:
            mermaid.append(f"    {node.id} -->|{flow.data_type}| {flow.destination_id}")

    return "\n".join(mermaid)  # Returns the Mermaid diagram as a string


# def generate_dot_from_dataflow(dataflow_report: DataFlowReport) -> str:
#     """
#     Generate a DOT representation of the data flow from a DataFlowReport.

#     :param dataflow_report: A DataFlowReport instance.
#     :return: DOT format string representation of the data flow diagram.
#     """
#     dot = Digraph(comment="Data Flow Diagram")

#     # Mapping of components by ID
#     component_map = {}

#     # Add nodes (External Entities, Processes, Data Stores)
#     for entity in dataflow_report.external_entities:
#         dot.node(
#             str(entity.id), f"External Entity: {entity.name}", shape="parallelogram"
#         )
#         component_map[entity.id] = entity

#     for process in dataflow_report.processes:
#         dot.node(str(process.id), f"Process: {process.name}", shape="box")
#         component_map[process.id] = process

#     for store in dataflow_report.data_stores:
#         dot.node(str(store.id), f"Data Store: {store.name}", shape="cylinder")
#         component_map[store.id] = store

#     # Add Trust Boundaries (Subgraphs)
#     for boundary in dataflow_report.trust_boundaries:
#         with dot.subgraph(name=f"cluster_{boundary.id}") as sub:
#             sub.attr(label=boundary.name, color="blue")
#             for component_id in boundary.component_ids:
#                 if component_id in component_map:
#                     sub.node(str(component_id))

#     # Add edges (Data Flows)
#     for node in (
#         dataflow_report.external_entities
#         + dataflow_report.processes
#         + dataflow_report.data_stores
#     ):
#         for flow in node.data_flows:
#             dot.edge(str(node.id), str(flow.destination_id), label=flow.data_type)

#     return dot.source  # Returns the DOT string representation


def generate_threat_model_report(threat_model: ThreatModel) -> str:
    """Generates a Markdown-formatted Threat Model Report."""

    # Header
    report = f"# Threat Model Report: {threat_model.name}\n"
    report += f"**Generated on:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
    report += f"## Summary\n{threat_model.summary}\n\n"

    # Asset Information
    report += "## Asset Information\n"
    report += f"- **Name:** {threat_model.asset.name}\n"
    report += f"- **Description:** {threat_model.asset.description}\n"
    report += f"- **Internet Facing:** {'Yes' if threat_model.asset.internet_facing else 'No'}\n"
    report += f"- **Authentication Type:** {threat_model.asset.authn_type.name}\n"
    report += (
        f"- **Data Classification:** {threat_model.asset.data_classification.name}\n\n"
    )

    # Repo Information
    report += "## Repository Information\n"
    for i, repo in enumerate(sorted(threat_model.repos, key=lambda r: r.name), 1):
        report += f"- **Name:** {repo.name}\n"
        report += f"- **Description:** {repo.description}\n"
        report += f"- **URL:** {repo.url}\n"

    # Data Flow Reports
    report += "## Data Flow Reports\n"
    for i, report_data in enumerate(threat_model.data_flow_reports, 1):
        report += f"### Report {i}\n"
        report += f"**Overview:** {report_data.overview}\n\n"

        diagram = generate_mermaid_from_dataflow(report_data)
        report += f"### Diagram {i}\n```mermaid\n{diagram}\n```\n\n"

        # External Entities
        if report_data.external_entities:
            report += "#### External Entities\n"
            for entity in sorted(report_data.external_entities, key=lambda e: e.name):
                report += f"- **{entity.name}**: {entity.description}\n"
            report += "\n"

        # Processes
        if report_data.processes:
            report += "#### Processes\n"
            for process in sorted(report_data.processes, key=lambda p: p.name):
                report += f"- **{process.name}**: {process.description}\n"
            report += "\n"

        # Data Stores
        if report_data.data_stores:
            report += "#### Data Stores\n"
            for store in sorted(report_data.data_stores, key=lambda s: s.name):
                report += f"- **{store.name}**: {store.description}\n"
            report += "\n"

        # Trust Boundaries
        if report_data.trust_boundaries:
            report += "#### Trust Boundaries\n"
            for boundary in sorted(report_data.trust_boundaries, key=lambda b: b.name):
                report += f"- **{boundary.name}**: {boundary.description}\n"
            report += "\n"

    # Threat Table (Summary)
    report += "## Threat Table\n"
    if threat_model.threats:
        report += "| Threat | STRIDE Category | Attack Vector | Impact Level | Risk Rating | Affected Components |\n"
        report += "|---|---|---|---|---|---|\n"
        for threat in sorted(threat_model.threats, key=lambda t: t.name):
            components_str = ", ".join(threat.component_names)
            report += (
                f"| {threat.name} "
                f"| {threat.stride_category.name} "
                f"| {threat.attack_vector} "
                f"| {threat.impact_level.name} "
                f"| {threat.risk_rating.name} "
                f"| {components_str} |\n"
            )
        report += "\n"
    else:
        report += "No threats identified.\n\n"

    # Threats Section
    report += "## Threats Identified\n"
    if threat_model.threats:
        for threat in sorted(threat_model.threats, key=lambda t: t.name):
            report += f"### {threat.name}\n"
            report += f"**Description:** {threat.description}\n"
            report += f"**STRIDE Category:** {threat.stride_category.name}\n"
            report += f"**Affected Components:** {', '.join(threat.component_names)}\n"
            report += f"**Attack Vector:** {threat.attack_vector}\n"
            report += f"**Impact Level:** {threat.impact_level.name}\n"
            report += f"**Risk Rating:** {threat.risk_rating.name}\n"
            report += "**Mitigations:**\n"
            for mitigation in threat.mitigations:
                report += f"- {mitigation}\n"
            report += "\n"
    else:
        report += "No threats identified.\n\n"

    def process_files(title, files):
        if not files:
            return f"## {title}\nNo files flagged for {title}.\n\n"

        files_str = f"## {title}\n"
        files_str += "\n".join(
            f"- **{file.file_path}**: {file.justification}" for file in files
        )
        files_str += "\n\n"
        return files_str

    if threat_model.data_flow_reports:
        reviewed_files = [
            file
            for report in threat_model.data_flow_reports
            for file in report.reviewed
        ]
        should_files = [
            file
            for report in threat_model.data_flow_reports
            for file in report.should_review
        ]
        should_not_files = [
            file
            for report in threat_model.data_flow_reports
            for file in report.should_not_review
        ]
        could_files = [
            file
            for report in threat_model.data_flow_reports
            for file in report.could_review
        ]
        could_not_files = [
            file
            for report in threat_model.data_flow_reports
            for file in report.could_not_review
        ]

        report += f"# Files:\n"
        report += process_files(
            "Reviewed", sorted(reviewed_files, key=lambda f: f.file_path)
        )
        report += process_files(
            "Should Review", sorted(should_files, key=lambda f: f.file_path)
        )
        report += process_files(
            "Should Not Review", sorted(should_not_files, key=lambda f: f.file_path)
        )
        report += process_files(
            "Could Review", sorted(could_files, key=lambda f: f.file_path)
        )
        report += process_files(
            "Could Not Review", sorted(could_not_files, key=lambda f: f.file_path)
        )

    return report


def generate_mermaid_dataflow_diagram(report: DataFlowReport) -> str:
    """
    Generates a Mermaid.js 'flowchart LR' diagram string from a DataFlowReport (or AgentDataFlowReport).
    It handles External Entities, Processes, Data Stores, and Trust Boundaries.
    """

    # 1. Gather references to all node collections
    external_entities = report.external_entities
    processes = report.processes
    data_stores = report.data_stores
    trust_boundaries = report.trust_boundaries

    # 2. Build a lookup of all components by UUID -> { name, description, type }
    components: Dict[str, Dict] = {}

    def add_component(comp, comp_type: str):
        comp_id = str(comp.id)
        components[comp_id] = {
            "name": comp.name,
            "description": comp.description,
            "type": comp_type,
        }

    for ee in external_entities:
        add_component(ee, "ExternalEntity")
    for proc in processes:
        add_component(proc, "Process")
    for ds in data_stores:
        add_component(ds, "DataStore")

    # 3. Map component IDs to their trust boundary name
    boundary_map: Dict[str, str] = {}
    for tb in trust_boundaries:
        for comp_id in tb.component_ids:
            boundary_map[str(comp_id)] = tb.name

    # 4. Gather data flows (keyed by flow ID to avoid duplicates)
    flows: Dict[str, Dict] = {}

    def record_flow(flow_id: str, source_id: str, destination_id: str, name: str):
        flows[flow_id] = {
            "source_id": source_id,
            "destination_id": destination_id,
            "name": name,
        }

    def handle_data_flows(node_id: str, data_flows):
        """
        For each DataFlow, decide the source/destination based on 'direction'.
        'outgoing'/'write': node -> destination
        'incoming'/'read': destination -> node
        'bidirectional': create two edges (or one with a special label).
        """
        for df in data_flows:
            df_id = str(df.id)
            dest_id = str(df.destination_id)
            flow_name = df.name
            direction = df.direction.lower()

            if direction in ["outgoing", "write"]:
                source_id = node_id
                record_flow(df_id, source_id, dest_id, flow_name)
            elif direction in ["incoming", "read"]:
                source_id = dest_id
                record_flow(df_id, source_id, node_id, flow_name)
            elif direction == "bidirectional":
                # Represent bidirectional with two flows or a special label
                record_flow(
                    df_id + "_fw", node_id, dest_id, flow_name + " (bidirectional)"
                )
                record_flow(
                    df_id + "_bw", dest_id, node_id, flow_name + " (bidirectional)"
                )

    # Collect data flows from each type of node
    for ee in external_entities:
        handle_data_flows(str(ee.id), ee.data_flows)
    for proc in processes:
        handle_data_flows(str(proc.id), proc.data_flows)
    for ds in data_stores:
        handle_data_flows(str(ds.id), ds.data_flows)

    # 5. Prepare the Mermaid lines
    mermaid_lines = ["flowchart LR"]

    # -- Helper to escape special characters that cause Mermaid parse errors --
    def sanitize_for_mermaid(text: str) -> str:
        """
        Escapes parentheses (and can be extended for other special characters).
        Prevents parse errors in Mermaid subgraph and node labels.
        """
        # Replace '(' and ')' with '\(' and '\)'
        # Optionally, do the same for [ ] or other characters if needed.
        text = text.replace("(", "\\(").replace(")", "\\)")
        return text

    # 5a. Organize subgraphs by trust boundary
    boundary_components_map: Dict[str, Set[str]] = defaultdict(set)
    for comp_id, b_name in boundary_map.items():
        boundary_components_map[b_name].add(comp_id)

    placed_components = set()

    def render_component(comp_id: str, info: Dict) -> str:
        """
        Returns a Mermaid node definition, e.g.:
          comp_id["Name\n(Type)\nDescription"]
        """
        name_type = f"{sanitize_for_mermaid(info['name'])}\\n({info['type']})"
        desc = sanitize_for_mermaid(info["description"]).replace("\n", " ")
        return f'{comp_id}["{name_type}\\n{desc}"]'

    # 5b. Render each trust boundary as a subgraph
    for tb in trust_boundaries:
        b_name_sanitized = sanitize_for_mermaid(tb.name)
        b_desc_sanitized = sanitize_for_mermaid(tb.description)
        subgraph_id = b_name_sanitized.replace(" ", "_")

        mermaid_lines.append(
            f'  subgraph {subgraph_id} ["{b_name_sanitized}\\n{b_desc_sanitized}"]'
        )

        for comp_id in boundary_components_map[tb.name]:
            if comp_id in components:
                node_label = render_component(comp_id, components[comp_id])
                mermaid_lines.append(f"    {node_label}")
                placed_components.add(comp_id)

        mermaid_lines.append("  end")

    # 5c. Render any components not in a boundary
    for comp_id, info in components.items():
        if comp_id not in placed_components:
            mermaid_lines.append(f"  {render_component(comp_id, info)}")

    # 6. Render edges for flows
    for flow_id, flow_info in flows.items():
        src = flow_info["source_id"]
        dst = flow_info["destination_id"]
        flow_name = sanitize_for_mermaid(flow_info["name"]).replace("\n", " ")
        if src in components and dst in components:
            mermaid_lines.append(f"  {src} -->|{flow_name}| {dst}")

    # 7. Return the final diagram string
    return "\n".join(mermaid_lines)
