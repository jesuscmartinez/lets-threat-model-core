from calendar import c
from tarfile import data_filter
import unittest
import json
from pathlib import Path
from uuid import uuid4
from jsonschema import validate, ValidationError

from core.models.dtos.Asset import Asset
from core.models.dtos.DataFlowReport import DataFlowReport, ExternalEntity
from core.models.dtos.MitreAttack import Attack
from core.models.dtos.Threat import Threat
from core.models.dtos.ThreatModel import ThreatModel
from core.models.enums import StrideCategory, Level, AuthnType, DataClassification
from core.models.dtos.Repository import Repository
from core.services.sarif_services import (
    generate_sarif_log_with_om,
    sarif_log_to_schema_dict,
)
from sarif_om import SarifLog
import urllib.request


class TestSarifLogSchemaValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):

        # Create a consistent Asset instance.
        cls.asset = Asset(
            uuid=uuid4(),
            name="Test Asset",
            description="Test asset description",
            internet_facing=False,
            authn_type=AuthnType.BASIC,
            data_classification=DataClassification.PUBLIC,
        )

        # Create a consistent Repository instance linked to the Asset.
        cls.repo = Repository(
            uuid=uuid4(),
            asset_uuid=cls.asset.uuid,
            name="Test Repo",
            url="test repo",
        )

        # Create a dummy ExternalEntity with only required fields.
        cls.dummy_component = ExternalEntity(
            uuid=uuid4(),
            name="My Component",
            description="A dummy external entity component.",
            data_flows=[],
        )

        # Create a DataFlowReport using the imported DataFlowReport class.
        cls.data_flow_report_id = uuid4()
        cls.data_flow_report = DataFlowReport(
            uuid=cls.data_flow_report_id,
            processes=[],
            external_entities=[cls.dummy_component],
            data_stores=[],
            trust_boundaries=[],
            repository_uuid=cls.repo.uuid,
        )
        # Set repository_id on the DataFlowReport.
        cls.data_flow_report.repository_uuid = cls.repo.uuid

        # Create a consistent Threat instance that uses the DataFlowReport.
        cls.dummy_threat = Threat(
            uuid=uuid4(),
            data_flow_report_uuid=cls.data_flow_report_id,
            name="Test Threat",
            description="Test threat description",
            stride_category=StrideCategory.SPOOFING,
            component_names=[cls.dummy_component.name],
            component_uuids=[cls.dummy_component.uuid],
            attack_vector="Network",
            impact_level=Level.HIGH,
            risk_rating=Level.CRITICAL,
            mitigations=["Mitigation1"],
        )

        cls.dummy_attack = Attack(
            uuid=uuid4(),
            component_uuid=cls.dummy_component.uuid,
            component=cls.dummy_component.name,
            attack_tactic="Execution",
            technique_id="T1059.003",
            technique_name="Windows Command Shell",
            reason_for_relevance="Attacker could spawn cmd.exe after uploading a web shell.",
            mitigation="Disable interactive shells and monitor command‑line events.",
            url="https://attack.mitre.org/techniques/T1059/003/",
            is_subtechnique=True,
            parent_id="T1059",
            parent_name="Command and Scripting Interpreter",
        )

        cls.data_flow_report.attacks = [cls.dummy_attack]
        cls.data_flow_report.threats = [cls.dummy_threat]

        cls.threat_model = ThreatModel(
            uuid=uuid4(),
            name="Test Threat Model",
            summary="This is a test threat model",
            asset=cls.asset,
            repos=[cls.repo],
            data_flow_reports=[cls.data_flow_report],
        )
        # Load SARIF 2.1.0 schema
        schema_url = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

        with urllib.request.urlopen(schema_url) as response:
            cls.sarif_schema = json.loads(response.read().decode())

    def test_sarif_log_matches_schema(cls):
        # Generate SARIF log
        sarif_log: SarifLog = generate_sarif_log_with_om(cls.threat_model)
        sarif_dict = sarif_log_to_schema_dict(sarif_log)

        # Validate against SARIF schema
        try:
            validate(instance=sarif_dict, schema=cls.sarif_schema)
        except ValidationError as e:
            cls.fail(f"SARIF log failed schema validation: {e.message}")
