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
            id=uuid4(),
            name="Test Asset",
            description="Test asset description",
            internet_facing=False,
            authn_type=AuthnType.BASIC,
            data_classification=DataClassification.PUBLIC,
        )

        # Create a consistent Repository instance linked to the Asset.
        cls.repo = Repository(
            id=uuid4(),
            asset_id=cls.asset.id,
            name="Test Repo",
            url="test repo",
        )

        # Create a dummy ExternalEntity with only required fields.
        cls.dummy_component = ExternalEntity(
            id=uuid4(),
            name="My Component",
            description="A dummy external entity component.",
            data_flows=[],
        )

        # Create a DataFlowReport using the imported DataFlowReport class.
        cls.data_flow_report_id = uuid4()
        cls.data_flow_report = DataFlowReport(
            id=cls.data_flow_report_id,
            processes=[],
            external_entities=[cls.dummy_component],
            data_stores=[],
            trust_boundaries=[],
            repository_id=cls.repo.id,
        )
        # Set repository_id on the DataFlowReport.
        cls.data_flow_report.repository_id = cls.repo.id

        # Create a consistent Threat instance that uses the DataFlowReport.
        cls.dummy_threat = Threat(
            id=uuid4(),
            data_flow_report_id=cls.data_flow_report_id,
            name="Test Threat",
            description="Test threat description",
            stride_category=StrideCategory.SPOOFING,
            component_names=["Component1"],
            component_ids=[uuid4()],
            attack_vector="Network",
            impact_level=Level.HIGH,
            risk_rating=Level.CRITICAL,
            mitigations=["Mitigation1"],
        )

        cls.threat_model = ThreatModel(
            id=uuid4(),
            name="Test Threat Model",
            summary="This is a test threat model",
            asset=cls.asset,
            repos=[cls.repo],
            data_flow_reports=[cls.data_flow_report],
            threats=[cls.dummy_threat],
            attacks=[
                Attack(
                    attack_tactic="Execution",
                    technique_id="T1059",
                    technique_name="Command and Scripting Interpreter",
                    component_id=uuid4(),
                    reason_for_relevance="Simulated attack for testing.",
                    mitigation="No mitigation required for test.",
                )
            ],
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
