import json
import attr
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
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import StrideCategory


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
    for threat in threat_model.threats:
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
                "id": str(threat.id),
                "data_flow_report_id": str(threat.data_flow_report_id),
                "security-severity": str(threat.impact_level.score),
                "name": threat.name,
                "description": threat.description,
                "stride_category": threat.stride_category.name,
                "component_names": threat.component_names,
                "component_ids": [str(cid) for cid in threat.component_ids],
                "attack_vector": threat.attack_vector,
                "impact_level": threat.impact_level.value,
                "risk_rating": threat.risk_rating.value,
                "mitigations": threat.mitigations,
            },
        )
        results.append(result)

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
