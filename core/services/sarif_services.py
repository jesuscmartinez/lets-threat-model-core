import json
import attr
from typing import List
from sarif_om import (
    SarifLog,
    Tool,
    Run,
    Artifact,
    ArtifactLocation,
    ArtifactContent,
    MultiformatMessageString,
    ReportingDescriptor,
    Result,
    Message,
    ToolComponent,
    PhysicalLocation,
    Region,
    Location,
)
from itertools import chain
from core.models.dtos.DataFlowReport import DataFlowReport
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import StrideCategory


def get_threat_results(data_flow: DataFlowReport) -> List[Result]:
    """
    Extracts threats from a DataFlowReport.

    Args:
        data_flow (DataFlowReport): The data flow report containing threats.

    Returns:
        List[Result]: A list of threats extracted from the data flow report.
    """
    results = []
    for threat in data_flow.threats:
        rule_id = f"STRIDE-{threat.stride_category.name}"
        mitigations_text = "\n".join(f"- {m}" for m in threat.mitigations)
        description = (
            f"#{threat.name}\n"
            f"## Description:\n{threat.description}\n"
            f"## Attack Vector:\n{threat.attack_vector}\n"
            f"## Mitigation\n{mitigations_text}"
        )

        locations = [
            Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(
                        uri=", ".join(threat.component_names),
                        uri_base_id="%SRCROOT%",
                    ),
                    region=Region(start_line=1, start_column=1),
                )
            )
        ]

        result = Result(
            rule_id=rule_id,
            level="warning",
            kind="review",
            message=Message(text=description),
            locations=locations,
            properties={
                "id": str(threat.uuid),
                "security-severity": str(threat.impact_level.score),
                "name": threat.name,
                "description": threat.description,
                "stride_category": threat.stride_category.name,
                "component_names": threat.component_names,
                "component_ids": [str(cid) for cid in threat.component_uuids],
                "attack_vector": threat.attack_vector,
                "impact_level": threat.impact_level.value,
                "risk_rating": threat.risk_rating.value,
                "mitigations": threat.mitigations,
            },
        )
        results.append(result)

    return results


def get_attack_results(data_flow: DataFlowReport) -> List[Result]:
    """
    Extracts attack patterns from a DataFlowReport.

    Args:
        data_flow (DataFlowReport): The data flow report containing attack patterns.

    Returns:
        List[Result]: A list of attack patterns extracted from the data flow report.
    """
    results = []
    for attack in data_flow.attacks:
        technique = f"{attack.technique_id}: {attack.technique_name}"
        description = (
            f"## Component:\n{attack.component}\n"
            f"## Tactic:\n{attack.attack_tactic}\n"
            f"## Technique:\n{technique}\n"
            f"## Relevance:\n{attack.reason_for_relevance or 'N/A'}\n"
            f"## Mitigation:\n{attack.mitigation}\n"
            f"## Reference:\n{attack.url or 'N/A'}"
        )

        locations = [
            Location(
                physical_location=PhysicalLocation(
                    artifact_location=ArtifactLocation(
                        uri=attack.component,
                        uri_base_id="%SRCROOT%",
                    ),
                    region=Region(start_line=1, start_column=1),
                )
            )
        ]

        result = Result(
            rule_id="MITRE",
            level="warning",
            kind="review",
            message=Message(text=description),
            locations=locations,
            properties={
                "id": str(attack.uuid),
                "component_id": str(attack.component_uuid),
                "tactic": attack.attack_tactic,
                "technique_id": attack.technique_id,
                "technique_name": attack.technique_name,
                "reason_for_relevance": attack.reason_for_relevance,
                "mitigation": attack.mitigation,
                "url": attack.url,
                "is_subtechnique": attack.is_subtechnique,
                "parent_id": attack.parent_id,
                "parent_name": attack.parent_name,
            },
        )
        results.append(result)

    return results


def generate_sarif_log_with_om(threat_model: ThreatModel) -> SarifLog:

    # Create rules
    rules = []
    for category in StrideCategory:
        rule = ReportingDescriptor(
            id=f"STRIDE-{category.name}",
            name=category.value,
            short_description=MultiformatMessageString(text=category.name),
            full_description=MultiformatMessageString(text=category.description),
            help_uri=category.external_resource,
        )
        rules.append(rule)

    # Add MITRE ATT&CK rule descriptor
    mitre_rule = ReportingDescriptor(
        id="MITRE",
        name="MITRE ATT&CK",
        short_description=MultiformatMessageString(text="MITRE ATT&CK technique"),
        full_description=MultiformatMessageString(
            text="This issue relates to a technique from the MITRE ATT&CK framework."
        ),
        help_uri="https://attack.mitre.org/",
    )
    rules.append(mitre_rule)

    # Create tool
    tool = Tool(
        driver=ToolComponent(
            name="Lets Threat Model",
            information_uri="https://github.com/jesuscmartinez/lets-threat-model-core",
            rules=rules,
        )
    )

    # Create artifacts
    artifact_uri = (
        f"asset-{threat_model.asset.name.lower().replace(' ', '_')}.threat-model"
    )
    artifact = Artifact(
        location=ArtifactLocation(uri=artifact_uri, uri_base_id="%SRCROOT%"),
        contents=ArtifactContent(text=json.dumps(threat_model.model_dump(mode="json"))),
        mime_type="application/json",
        encoding="utf-8",
    )

    # Create results
    results = []
    # Flatten and add threat results
    results.extend(
        chain.from_iterable(
            get_threat_results(data_flow)
            for data_flow in threat_model.data_flow_reports
        )
    )

    # Flatten and add attack results
    results.extend(
        chain.from_iterable(
            get_attack_results(data_flow)
            for data_flow in threat_model.data_flow_reports
        )
    )

    # Create run
    run = Run(tool=tool, results=results, artifacts=[artifact])

    # Create SARIF log
    sarif_log = SarifLog(version="2.1.0", runs=[run])

    return sarif_log


def sarif_log_to_schema_dict(obj):
    if isinstance(obj, list):
        return [sarif_log_to_schema_dict(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: sarif_log_to_schema_dict(v) for k, v in obj.items()}
    elif hasattr(obj, "__attrs_attrs__"):
        result = {}
        for field in attr.fields(obj.__class__):
            key = field.metadata.get("schema_property_name", field.name)
            value = getattr(obj, field.name)
            if value is not None:
                result[key] = sarif_log_to_schema_dict(value)
            elif key == "properties":
                result[key] = {}  # Ensure empty object for properties if None
        return result
    else:
        return obj
