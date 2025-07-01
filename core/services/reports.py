from datetime import datetime, timezone
from typing import List

from core.models.dtos.File import File
from core.models.dtos.ThreatModel import ThreatModel
from core.services.threat_model_config import ThreatModelConfig


def process_files(title, files: List[File]) -> str:
    if not files:
        return f"## {title}\nNo files flagged for {title}.\n\n"

    files_str = f"## {title}\n"
    files_str += "\n".join(
        f"- **{file.file_path}**: {file.justification}" for file in files
    )
    files_str += "\n\n"
    return files_str


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

        repo = next(
            (r for r in threat_model.repos if r.uuid == report_data.repository_uuid),
            None,
        )
        if report_data.repository_uuid is None:
            merged_repo_names = ", ".join(repo.name for repo in threat_model.repos)
            report_title = f"Merged Report ({merged_repo_names})"
        else:
            report_title = f"Report {repo.name}"
        report += f"### {report_title}\n"
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

        sorted_threats = sorted(report_data.threats, key=lambda t: t.name)

        # Threats Section
        report += "### Threats Identified\n"
        if report_data.threats:
            for threat in sorted_threats:
                report += f"### ⚠️ {threat.name}\n\n"
                report += "| Field | Value |\n"
                report += "|-------|-------|\n"
                report += f"| **ID** | {threat.uuid} |\n"
                report += f"| **Category** | {threat.stride_category.name} |\n"
                report += f"| **Impact Level** | {threat.impact_level.name} |\n"
                report += f"| **Risk Rating** | {threat.risk_rating.name} |\n"
                report += f"| **Affected Components** | {', '.join(threat.component_names)} |\n\n"
                report += f"**📝 Description:**\n{threat.description}\n\n"
                report += f"**🎯 Attack Vector:**\n{threat.attack_vector}\n\n"
                report += "**🛡️ Mitigations:**\n"
                for mitigation in threat.mitigations:
                    report += f"- {mitigation}\n"
                report += "\n"
        else:
            report += "No threats identified.\n\n"

        # Sort attacks by technique_name for consistent reporting
        sorted_attacks = sorted(report_data.attacks, key=lambda a: a.technique_name)

        # ATT&CK Section
        report += "### MITRE ATT&CKs Identified\n"
        if report_data.attacks:
            for attack in sorted_attacks:
                report += f"### 🔐 {attack.technique_name}\n\n"
                report += "| Field | Value |\n"
                report += "|-------|-------|\n"
                report += f"| **ID** | {attack.uuid} |\n"
                report += f"| **Tactic** | {attack.attack_tactic} |\n"
                report += f"| **Technique ID & Name** | {attack.technique_id} – {attack.technique_name} |\n"
                report += f"| **URL** | {attack.url or 'N/A'} |\n"
                report += f"| **Component** | {attack.component or 'N/A'} |\n"
                report += f"| **Component ID** | {attack.component_uuid} |\n"
                report += f"| **Is Sub‑technique?** | {attack.is_subtechnique} |\n"
                if attack.is_subtechnique:
                    report += f"| **Parent Technique** | {attack.parent_id} – {attack.parent_name} |\n"
                report += "\n"
                report += (
                    f"**📝 Reason for Relevance:**\n{attack.reason_for_relevance}\n\n"
                )
                report += f"**🛡️ Mitigations:**\n- {attack.mitigation or 'N/A'}\n\n"
        else:
            report += "No ATT&CKs identified.\n\n"

        report += f"### Files:\n"
        report += process_files(
            "Reviewed", sorted(report_data.reviewed, key=lambda f: f.file_path)
        )
        report += process_files(
            "Should Review",
            sorted(report_data.should_review, key=lambda f: f.file_path),
        )
        report += process_files(
            "Should Not Review",
            sorted(report_data.should_not_review, key=lambda f: f.file_path),
        )
        report += process_files(
            "Could Review", sorted(report_data.could_review, key=lambda f: f.file_path)
        )
        report += process_files(
            "Could Not Review",
            sorted(report_data.could_not_review, key=lambda f: f.file_path),
        )

    return report
