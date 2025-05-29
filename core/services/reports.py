from datetime import datetime, timezone
from enum import Enum
import json
from logging import config
from core.agents.chat_model_manager import ChatModelManager
from core.services.threat_model_config import ThreatModelConfig
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.ThreatModel import ThreatModel
from core.agents.diagram_agent import DiagramAgent
from core.models.dtos.DataFlowReport import DataFlow
from typing import Dict, Set
from collections import defaultdict

from typing import List
from datetime import datetime
from uuid import UUID

from typing import List
from uuid import uuid4
from core.models.dtos.Threat import Threat


def generate_threat_model_report(
    threat_model_config: ThreatModelConfig, threat_model: ThreatModel
) -> str:
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

        report += f"### Diagram {i}\n```mermaid\n{report_data.diagram}\n```\n\n"

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
    report += "## Threat Table Summary\n"
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

    # ATT&CK Table (Summary)
    report += "## MITRE ATT&CK Table Summary\n"
    if threat_model.attacks:
        report += "| DFD Component | ATT&CK Tactic | Technique ID and Name | Reason for Relevance | Mitigation |\n"
        report += "|---|---|---|---|---|\n"
        for attack in threat_model.attacks:
            report += (
                f"| {attack.component_id} "
                f"| {attack.attack_tactic} "
                f"| {attack.technique_id} - {attack.technique_name} "
                f"| {attack.reason_for_relevance} "
                f"| {attack.mitigation or 'N/A'} |\n"
            )
        report += "\n"
    else:
        report += "No ATT&CKs identified.\n\n"

    # ATT&CK Section
    report += "## MITRE ATT&CKs Identified\n"
    if threat_model.attacks:
        for i, attack in enumerate(threat_model.attacks, 1):
            report += f"### ATT&CK Mapping {i}\n"
            report += f"**DFD Component:** {attack.component_id}\n"
            report += f"**ATT&CK Tactic:** {attack.attack_tactic}\n"
            report += f"**Technique ID and Name:** {attack.technique_id} - {attack.technique_name}\n"
            report += f"**Reason for Relevance:** {attack.reason_for_relevance}\n"
            report += f"**Mitigation:** {attack.mitigation or 'N/A'}\n\n"
    else:
        report += "No ATT&CKs identified.\n\n"

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
