from datetime import datetime, timezone
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.ThreatModel import ThreatModel


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


def generate_dot_from_dataflow(dataflow_report: DataFlowReport) -> str:
    """
    Generate a DOT representation of the data flow from a DataFlowReport.

    :param dataflow_report: A DataFlowReport instance.
    :return: DOT format string representation of the data flow diagram.
    """
    dot = Digraph(comment="Data Flow Diagram")

    # Mapping of components by ID
    component_map = {}

    # Add nodes (External Entities, Processes, Data Stores)
    for entity in dataflow_report.external_entities:
        dot.node(
            str(entity.id), f"External Entity: {entity.name}", shape="parallelogram"
        )
        component_map[entity.id] = entity

    for process in dataflow_report.processes:
        dot.node(str(process.id), f"Process: {process.name}", shape="box")
        component_map[process.id] = process

    for store in dataflow_report.data_stores:
        dot.node(str(store.id), f"Data Store: {store.name}", shape="cylinder")
        component_map[store.id] = store

    # Add Trust Boundaries (Subgraphs)
    for boundary in dataflow_report.trust_boundaries:
        with dot.subgraph(name=f"cluster_{boundary.id}") as sub:
            sub.attr(label=boundary.name, color="blue")
            for component_id in boundary.component_ids:
                if component_id in component_map:
                    sub.node(str(component_id))

    # Add edges (Data Flows)
    for node in (
        dataflow_report.external_entities
        + dataflow_report.processes
        + dataflow_report.data_stores
    ):
        for flow in node.data_flows:
            dot.edge(str(node.id), str(flow.destination_id), label=flow.data_type)

    return dot.source  # Returns the DOT string representation


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
    for i, repo in enumerate(threat_model.repos, 1):
        report += f"- **Name:** {repo.name}\n"
        report += f"- **Description:** {repo.description}\n"
        report += f"- **URL:** {repo.url}\n"

    # Data Flow Diagrams
    report += "## Data Flow Diagrams\n"
    for i, diagram in enumerate(threat_model.data_flow_diagrams, 1):
        report += f"### Diagram {i}\n```\n{diagram}\n```\n\n"

    # Data Flow Reports
    report += "## Data Flow Reports\n"
    for i, report_data in enumerate(threat_model.data_flow_reports, 1):
        report += f"### Report {i}\n"
        report += f"**Overview:** {report_data.overview}\n\n"

        # External Entities
        if report_data.external_entities:
            report += "#### External Entities\n"
            for entity in report_data.external_entities:
                report += f"- **{entity.name}**: {entity.description}\n"
            report += "\n"

        # Processes
        if report_data.processes:
            report += "#### Processes\n"
            for process in report_data.processes:
                report += f"- **{process.name}**: {process.description}\n"
            report += "\n"

        # Data Stores
        if report_data.data_stores:
            report += "#### Data Stores\n"
            for store in report_data.data_stores:
                report += f"- **{store.name}**: {store.description}\n"
            report += "\n"

        # Trust Boundaries
        if report_data.trust_boundaries:
            report += "#### Trust Boundaries\n"
            for boundary in report_data.trust_boundaries:
                report += f"- **{boundary.name}**: {boundary.description}\n"
            report += "\n"

    # Threat Table (Summary)
    report += "## Threat Table\n"
    if threat_model.threats:
        report += "| Threat | STRIDE Category | Attack Vector | Impact Level | Risk Rating | Affected Components |\n"
        report += "|---|---|---|---|---|---|\n"
        for threat in threat_model.threats:
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
        for threat in threat_model.threats:
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
        report += process_files("Reviewed", reviewed_files)
        report += process_files("Should Review", should_files)
        report += process_files("Should Not Review", should_not_files)
        report += process_files("Could Review", could_files)
        report += process_files("Could Not Review", could_not_files)

    return report
