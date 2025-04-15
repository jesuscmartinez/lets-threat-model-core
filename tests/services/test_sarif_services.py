import unittest
from unittest.mock import Mock, AsyncMock, patch
import tempfile
from pathlib import Path
from uuid import uuid4

from pydantic import SecretStr

from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.DataFlowReport import DataFlowReport, ExternalEntity
from core.models.enums import StrideCategory, Level, AuthnType, DataClassification
from core.models.dtos.Threat import Threat
from core.services.sarif_services import SarifGenerator
from core.services.threat_model_config import ThreatModelConfig
from core.models.SarifLog import (
    SarifLog,
    Run,
    Tool,
    ToolDriver,
    Rule,
    Result,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
)


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
            id=uuid4(),
            name="My Component",
            description="desc",
            entity_type="Component",
            organization="Test Organization",
            role="Test Role",
            privilege_level="Low",
            authentication_mechanism="None",
            trust_level="Medium",
            attack_surface_notes="No significant attack surface",
        )

        # Create a DataFlowReport using the imported DataFlowReport class.
        self.data_flow_report_id = uuid4()
        self.data_flow_report = DataFlowReport(
            id=self.data_flow_report_id,
            processes=[],
            external_entities=[self.dummy_component],
            data_stores=[],
            trust_boundaries=[],
            repository_id=self.repo.id,
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
                rule.id,
                [f"STRIDE-{member.name}" for member in enum_members],
                "Rule id should be a valid STRIDE value",
            )
            self.assertIn(
                rule.name,
                [member.value for member in enum_members],
                "Rule name should be a valid STRIDE value",
            )
            # Verify that fullDescription is provided and contains text.
            self.assertIsNotNone(
                rule.fullDescription, "Full description should not be None"
            )
            self.assertTrue(
                rule.fullDescription.text,
                "Full description text should not be empty",
            )
            # Help URI should be provided.
            self.assertIsNotNone(rule.helpUri, "Help URI should be provided")

    async def test_generate_sarif_log(self):
        """
        Test that SarifGenerator.generate_sarif_log() produces a SARIF log
        that follows the Pydantic SARIF schema.
        """
        generator = SarifGenerator(self.threat_model)
        sarif_log = generator.generate_sarif_log()

        # Check the top-level SARIF log structure
        self.assertEqual(sarif_log.version, "2.1.0", "SARIF version should be '2.1.0'")
        self.assertTrue(hasattr(sarif_log, "runs"), "SARIF log should contain 'runs'")
        self.assertEqual(
            len(sarif_log.runs),
            1,
            "There should be exactly one run in the SARIF log",
        )

        # Check the run's structure
        run = sarif_log.runs[0]
        self.assertTrue(hasattr(run, "tool"), "Run should contain 'tool'")
        self.assertTrue(hasattr(run, "results"), "Run should contain 'results'")

        # Validate the tool and its driver using attribute access
        tool = run.tool
        self.assertTrue(hasattr(tool, "driver"), "Tool should contain 'driver'")
        driver = tool.driver
        self.assertEqual(driver.name, "Lets Threat Model", "Tool driver name mismatch")
        self.assertEqual(
            driver.informationUri,
            "https://github.com/jesuscmartinez/lets-threat-model-core",
            "Tool driver informationUri mismatch",
        )
        self.assertIsInstance(driver.rules, list, "Rules should be a list")

        # Validate that there's at least one result
        self.assertTrue(
            len(run.results) >= 1, "There should be at least one result in the run"
        )
        result = run.results[0]

        # Check that the ruleId in the result matches the expected STRIDE category
        expected_rule_id = f"STRIDE-{self.dummy_threat.stride_category.name}"
        self.assertEqual(
            result.ruleId,
            expected_rule_id,
            "Result ruleId should match the threat's STRIDE category",
        )

        # Check that security-severity property is correctly set
        self.assertIn(
            "security-severity",
            result.properties,
            "Result properties should include 'security-severity'",
        )
        self.assertEqual(
            result.properties.get("security-severity"),
            str(self.dummy_threat.impact_level.score),
            "Security severity should match impact level score",
        )

        # Validate that result includes locations and that at least one location's URI is snake-cased correctly
        self.assertTrue(hasattr(result, "locations"), "Result should include locations")

        expected_uri_prefix = (
            "asset-test_asset.repo-test_repo.external_entity-my_component"
        )

        found = any(
            loc.physicalLocation.artifactLocation.uri.startswith(expected_uri_prefix)
            for loc in result.locations
        )
        self.assertTrue(
            found,
            f"At least one location's URI should start with '{expected_uri_prefix}'",
        )


if __name__ == "__main__":
    unittest.main()
