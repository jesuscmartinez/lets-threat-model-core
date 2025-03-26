from core.models.dtos import DataFlowReport
from core.models.dtos.Threat import Threat
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import StrideCategory


class SarifGenerator:
    """
    A class to generate SARIF logs (as dictionaries) for a given ThreatModel.

    This implementation builds the SARIF log using dictionary structures.
    """

    def __init__(self, threat_model: ThreatModel):
        self.threat_model = threat_model
        # Mapping from component id (as a string) to a sequential index for logical locations.
        self.id_to_index = {}
        # Mapping from rule id to its index in the rules array.
        self.rule_id_to_index = {}

    @staticmethod
    def _to_snake_case(s: str) -> str:
        return "_".join(s.lower().split())

    def create_stride_rules(self):
        """
        Create a list of SARIF rules (as dictionaries) for each STRIDE category.
        """
        rules = []
        index = 0
        for category in StrideCategory:
            rule_id = f"STRIDE-{category.name}"
            self.rule_id_to_index[rule_id] = index
            rule = {
                "id": rule_id,
                "name": category.value,
                "shortDescription": {"text": category.name},
                "fullDescription": {"text": category.description},
                "helpUri": category.external_resource,
            }
            rules.append(rule)
            index += 1
        return rules

    def get_results(self):
        """
        Creates SARIF results (as dictionaries) for each threat in the threat model.
        """
        results = []
        for threat in self.threat_model.threats:
            rule_id = f"STRIDE-{threat.stride_category.name}"
            rule_index = self.rule_id_to_index.get(rule_id, -1)
            description = (
                f"{threat.name}\n"
                f"{threat.description}\n"
                "Attack Vector\n"
                f"{threat.attack_vector}\n"
                "Mitigation\n"
                f"{threat.mitigations}"
            )

            # Get the matching data flow report for context.
            report = next(
                (
                    r
                    for r in self.threat_model.data_flow_reports
                    if r.id == threat.data_flow_report_id
                ),
                None,
            )

            repo = next(
                (
                    repo
                    for repo in self.threat_model.repos
                    if report is not None and repo.id == report.repository_id
                ),
                None,
            )

            uri = (
                f"asset-{self._to_snake_case(self.threat_model.asset.name)}.repo-{self._to_snake_case(repo.name)}"
                if repo
                else self.threat_model.asset.name
            )

            locations = []
            # Assuming the report has attributes with lists of components for context.
            kind_map = {
                "external_entities": "external_entity",
                "processes": "process",
                "data_stores": "data_store",
                "trust_boundaries": "trust_boundary",
            }
            for key in kind_map.keys():
                for component in getattr(report, key, []):
                    location = {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"{uri}.{kind_map[key]}-{self._to_snake_case(component.name)}",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                    locations.append(location)

            result = {
                "ruleIndex": rule_index,
                "ruleId": rule_id,
                "level": "warning",
                "kind": "review",
                "message": {"text": description},
                "locations": locations,
                "partialFingerprints": {"threat_model_id": str(threat.id)},
                "properties": {"security-severity": str(threat.impact_level.score)},
            }

            results.append(result)
        return results

    def generate_sarif_log(self, previous_log=None):
        """
        Generates a SARIF log as a dictionary for the threat model.
        """
        rules = self.create_stride_rules()
        results = self.get_results()

        tool_driver = {
            "name": "Lets Threat Model",
            "informationUri": "https://github.com/jesuscmartinez/lets-threat-model-core",
            "rules": rules,
        }
        tool = {"driver": tool_driver}

        run = {
            "tool": tool,
            "results": results,
            # "artifacts": artifacts,  # Artifacts can be added similarly if needed.
        }

        sarif_log = {"version": "2.1.0", "runs": [run]}
        return sarif_log
