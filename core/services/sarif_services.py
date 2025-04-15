import logging
from typing import List, Optional
import uuid
import json

from collections import defaultdict

from core.models.SarifLog import (
    Region,
    Result,
    Rule,
    ArtifactLocation,
    Location,
    Run,
    SarifLog,
    PhysicalLocation,
    Message,
    Tool,
    ToolDriver,
    Artifact,
    ArtifactContent,
)
from core.models.dtos.DataFlowReport import (
    Component,
    DataFlow,
    DataFlowReport,
    ExternalEntity,
    Node,
)
from core.models.dtos.Threat import Threat
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import Level, StrideCategory

logger = logging.getLogger(__name__)

NAME = "Lets Threat Model"
INFO_URI = "https://github.com/jesuscmartinez/lets-threat-model-core"

class SarifGenerator:
    def __init__(self, threat_model: ThreatModel):
        self.threat_model = threat_model
        self.id_to_index = {}
        self.rule_id_to_index = {}

    def create_stride_rules(self) -> List[Rule]:
        rules = []
        for index, category in enumerate(StrideCategory):
            rule_id = f"STRIDE-{category.name}"
            self.rule_id_to_index[rule_id] = index
            rules.append(
                Rule(
                    id=rule_id,
                    name=category.value,
                    shortDescription=Message(text=category.name),
                    fullDescription=Message(text=category.description),
                    helpUri=category.external_resource,
                )
            )
        return rules

    def get_artifacts(self) -> List[Artifact]:
        to_snake = lambda s: "_".join(s.lower().split())
        uri = f"asset-{to_snake(self.threat_model.asset.name)}.threat-model"

        threat_model_json = self.threat_model.model_dump(mode="json")

        return [
            Artifact(
                location=ArtifactLocation(uri=uri, uriBaseId="%SRCROOT%"),
                contents=ArtifactContent(text=json.dumps(threat_model_json)),
                mimeType="application/json",
                encoding="utf-8",
            )
        ]

    def get_results(self) -> List[Result]:
        results = []
        to_snake = lambda s: "_".join(s.lower().split())
        kind_map = {
            "external_entities": "external_entity",
            "processes": "process",
            "data_stores": "data_store",
            "trust_boundaries": "trust_boundary",
        }

        report_map = defaultdict(list)
        for report in self.threat_model.data_flow_reports:
            report_map[report.id].append(report)

        repo_map = defaultdict(list)
        for repo in self.threat_model.repos:
            repo_map[repo.id].append(repo)

        for threat in self.threat_model.threats:
            rule_id = f"STRIDE-{threat.stride_category.name}"
            rule_index = self.rule_id_to_index.get(rule_id, -1)

            mitigations_text = "\n".join(f"- {m}" for m in threat.mitigations)
            description = (
                f"#{threat.name}\n"
                f"## Description:\n{threat.description}\n"
                f"## Attack Vector:\n{threat.attack_vector}\n"
                f"## Mitigation\n{mitigations_text}"
            )

            report = report_map.get(threat.data_flow_report_id, [None])[0]

            if report:
                matching_repos = repo_map.get(report.repository_id, [])
                repo = matching_repos[0] if matching_repos else None

            uri = (
                f"asset-{to_snake(self.threat_model.asset.name)}.repo-{to_snake(repo.name)}"
                if repo
                else f"asset-{to_snake(self.threat_model.asset.name)}"
            )

            locations = [
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(
                            uri=f"{uri}.{kind_map[key]}-{to_snake(component.name)}",
                            uriBaseId="%SRCROOT%",
                        ),
                        region=Region(startLine=1, startColumn=1),
                    )
                )
                for key in kind_map
                for component in getattr(report, key, [])
            ]

            properties = {
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
            }

            results.append(
                Result(
                    ruleId=rule_id,
                    ruleIndex=rule_index,
                    level="warning",
                    kind="review",
                    message=Message(text=description),
                    locations=locations,
                    properties=properties,
                )
            )

        return results

    def generate_sarif_log(self) -> SarifLog:
        tool_driver = ToolDriver(
            name=NAME,
            informationUri=INFO_URI,
            rules=self.create_stride_rules(),
        )
        tool = Tool(driver=tool_driver)
        return SarifLog(
            runs=[
                Run(
                    tool=tool,
                    results=self.get_results(),
                    artifacts=self.get_artifacts(),
                )
            ]
        )


def get_threat_model_from_sarif_log(sarif_log: SarifLog) -> Optional[ThreatModel]:
    for run in sarif_log.runs:
        for artifact in getattr(run, "artifacts", []) or []:
            if artifact.contents and artifact.contents.text:
                try:
                    data = json.loads(artifact.contents.text)
                    return ThreatModel.model_validate(data)
                except Exception as e:
                    logger.warning(
                        f"Failed to load threat model from artifact contents: {e}"
                    )
    return None
