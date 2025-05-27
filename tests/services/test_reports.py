from unittest.mock import patch
import unittest
import json
from uuid import uuid4

import pytest
from core.models.dtos.DataFlowReport import DataFlowReport, AgentDataFlowReport
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.Threat import Threat
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.services.threat_model_config import ThreatModelConfig
from core.models.enums import AuthnType, DataClassification, StrideCategory, Level
from pydantic import SecretStr
from core.services.reports import (
    generate_threat_model_report,
)


class TestReports(unittest.TestCase):
    def setUp(self):
        # Initialize configuration using the threat_model_config fixture
        self.config = ThreatModelConfig(
            llm_provider="openai",
            categorization_agent_llm="gpt-4o-mini",
            report_agent_llm="gpt-4o-mini",
            threat_model_agent_llm="gpt-4o-mini",
            username="user",
            pat=SecretStr("token"),
            context_window=2048,
            max_output_tokens=512,
            review_max_file_in_batch=10,
            review_token_buffer=100,
            categorize_max_file_in_batch=10,
            categorize_token_buffer=100,
            categorize_only=False,
            completion_threshold=0.9,
            review_agent_llm="review_model",
        )

        # Create a dummy AgentDataFlowReport (with empty collections)
        self.agent_report = AgentDataFlowReport(
            overview="Test overview",
            external_entities=[],
            processes=[],
            data_stores=[],
            trust_boundaries=[],
        )
        # Create a dummy DataFlowReport instance with minimal data
        self.data_flow_report = DataFlowReport(
            id=uuid4(),
            repository_id=uuid4(),
            external_entities=[],
            processes=[],
            data_stores=[],
            trust_boundaries=[],
            should_review=[],
            reviewed=[],
            could_review=[],
            should_not_review=[],
            could_not_review=[],
            diagram="graph TD",
        )

        # Create a dummy Asset
        dummy_asset = Asset(
            id=uuid4(),
            name="Dummy Asset",
            description="Test asset description",
            internet_facing=False,
            authn_type=AuthnType.NONE,
            data_classification=DataClassification.PUBLIC,
        )

        # Create a dummy Repository
        dummy_repo = Repository(
            id=uuid4(),
            name="Dummy Repo",
            description="Test repository",
            # url="https://example.com/repo",
            local_path="/path/to/repo",
            asset_id=dummy_asset.id,
        )

        # Create a dummy ThreatModel that includes the asset, repository, and our data flow report
        self.threat_model = ThreatModel(
            id=uuid4(),
            name="Dummy Threat Model",
            summary="This is a test threat model.",
            asset=dummy_asset,
            repos=[dummy_repo],
            data_flow_reports=[self.data_flow_report],
            threats=[],
        )

        # Create a dummy Threat for testing SARIF generation.
        # (Ensure that your enums in Threat match the values used here.)
        self.threats = [
            Threat(
                id=uuid4(),
                data_flow_report_id=self.data_flow_report.id,
                name="Test Threat",
                description="This is a test threat description.",
                stride_category=StrideCategory.TAMPERING,
                component_names=["Component A"],
                component_ids=[uuid4()],
                attack_vector="Test attack vector",
                impact_level=Level.HIGH,
                risk_rating=Level.CRITICAL,
                mitigations=["Mitigation A", "Mitigation B"],
            )
        ]

    def test_generate_threat_model_report(self):
        """Test that the Markdown report contains key sections and asset information."""
        # mock_generate_diagram.return_value = "graph TD;\nA-->B"

        report = generate_threat_model_report(self.config, self.threat_model)
        self.assertIsInstance(report, str)
        self.assertIn("# Threat Model Report", report)
        self.assertIn(self.threat_model.asset.name, report)
        self.assertIn("graph TD", report)


if __name__ == "__main__":
    unittest.main()
