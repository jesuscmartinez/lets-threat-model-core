import unittest
import tempfile
from pathlib import Path
from uuid import uuid4

from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport, ExternalEntity
from core.models.enums import StrideCategory, Level, AuthnType, DataClassification
from core.models.dtos.Threat import Threat
from core.services.sarif import SarifGenerator


class TestThreatModelGeneration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Create a temporary directory for test files (if needed)
        self.test_dir = tempfile.TemporaryDirectory()

        # Create a consistent Asset instance.
        self.asset = Asset(
            id=uuid4(),
            name="Test Asset",
            description="Test asset description",
            internet_facing=False,
            authn_type=AuthnType.BASIC,
            data_classification=DataClassification.PUBLIC,
        )

        # Create a consistent Repository instance linked to the Asset.
        self.repo = Repository(
            id=uuid4(),
            asset_id=self.asset.id,
            name="Test Repo",
            url="test repo",
        )

        # Create a dummy component.
        self.dummy_component = ExternalEntity(
            id=uuid4(), name="My Component", description="desc"
        )

        # Create a DataFlowReport using the imported DataFlowReport class.
        self.data_flow_report_id = uuid4()
        self.data_flow_report = DataFlowReport(
            id=self.data_flow_report_id,
            processes=[],
            external_entities=[self.dummy_component],
            data_stores=[],
            trust_boundaries=[],
        )
        # Set repository_id on the DataFlowReport.
        self.data_flow_report.repository_id = self.repo.id

        # Create a consistent Threat instance that uses the DataFlowReport.
        self.dummy_threat = Threat(
            id=uuid4(),
            data_flow_report_id=self.data_flow_report_id,
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

        # Create a ThreatModel using the above Asset, Repository, DataFlowReport, and Threat.
        self.threat_model = ThreatModel(
            id=uuid4(),
            name="Test Threat Model",
            summary="This is a test threat model",
            asset=self.asset,
            repos=[self.repo],
            data_flow_reports=[self.data_flow_report],
            threats=[self.dummy_threat],
        )

    def tearDown(self):
        self.test_dir.cleanup()

    def test_create_stride_rules(self):
        """
        Test that SarifGenerator.create_stride_rules() produces a dictionary for each member
        of the StrideCategory enum with the expected fields.
        """
        generator = SarifGenerator(self.threat_model)
        rules = generator.create_stride_rules()
        enum_members = list(StrideCategory)
        self.assertEqual(
            len(rules),
            len(enum_members),
            "The number of rules should equal the number of STRIDE categories.",
        )

        for rule in rules:
            # Check that rule id is of the format "STRIDE-{enum_member.name}"
            self.assertIn(
                rule["id"],
                [f"STRIDE-{member.name}" for member in enum_members],
                "Rule id should be a valid STRIDE value",
            )
            self.assertIn(
                rule["name"],
                [member.value for member in enum_members],
                "Rule name should be a valid STRIDE value",
            )
            # Verify that fullDescription is provided and contains text.
            self.assertIsNotNone(
                rule.get("fullDescription"), "Full description should not be None"
            )
            self.assertTrue(
                rule["fullDescription"].get("text"),
                "Full description text should not be empty",
            )
            # Help URI should be provided.
            self.assertIsNotNone(rule.get("helpUri"), "Help URI should be provided")

    async def test_generate_sarif_log(self):
        """
        Test that SarifGenerator.generate_sarif_log() produces a SARIF log dictionary that contains one run with at least one result,
        that the result references the correct rule for the threat, and that the constructed URIs use snake case.
        """
        generator = SarifGenerator(self.threat_model)
        sarif_log = generator.generate_sarif_log()
        self.assertIsInstance(
            sarif_log,
            dict,
            "The generated SARIF log should be a dictionary",
        )
        self.assertIn("runs", sarif_log, "SARIF log should contain 'runs'")
        self.assertEqual(
            len(sarif_log["runs"]),
            1,
            "There should be exactly one run in the SARIF log",
        )
        run = sarif_log["runs"][0]
        self.assertIn("results", run, "Run should contain 'results'")
        self.assertTrue(
            len(run["results"]) >= 1,
            "There should be at least one result in the run",
        )
        result = run["results"][0]
        expected_rule_id = f"STRIDE-{self.dummy_threat.stride_category.name}"
        self.assertEqual(
            result["ruleId"],
            expected_rule_id,
            "Result ruleId should match the threat's STRIDE category",
        )
        self.assertIn(
            "security-severity",
            result.get("properties", {}),
            "Result properties should include 'security-severity'",
        )
        self.assertEqual(
            result["properties"]["security-severity"],
            str(self.dummy_threat.impact_level.score),
            "Security severity should match impact level score",
        )
        # Verify that the location URIs use snake-case conversion.
        self.assertIn("locations", result, "Result should include locations")
        # Expected snake-case conversions:
        # asset: "Test Asset" -> "test_asset"
        # repo: "Test Repo" -> "test_repo"
        # external entity component: "My Component" -> "my_component"
        expected_uri_prefix = (
            "asset-test_asset.repo-test_repo.external_entity-my_component"
        )
        found = any(
            loc["physicalLocation"]["artifactLocation"]["uri"].startswith(
                expected_uri_prefix
            )
            for loc in result["locations"]
        )
        self.assertTrue(
            found,
            f"At least one location's URI should start with '{expected_uri_prefix}'",
        )


if __name__ == "__main__":
    unittest.main()
