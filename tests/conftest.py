import pytest
from uuid import uuid4
from pydantic import SecretStr
import pytest
from regex import P
from core.models.dtos.DataFlowReport import (
    DataFlowReport,
    ExternalEntity,
    Process,
    DataStore,
    TrustBoundary,
)
from core.models.dtos.ThreatModel import ThreatModel
from core.models.dtos.Threat import Threat
from core.models.dtos.Asset import Asset
from core.models.dtos.Repository import Repository
from core.models.dtos.MitreAttack import Attack
from core.models.dtos.File import File
from core.services.threat_model_config import ThreatModelConfig
from core.models.enums import AuthnType, DataClassification, StrideCategory, Level


@pytest.fixture
def tm_config() -> ThreatModelConfig:
    return ThreatModelConfig(
        base_url="https://test.url",
        categorization_agent_llm="test_categorization_agent_llm",
        review_agent_llm="test_review_agent_llm",
        threat_model_agent_llm="test_threat_model_agent_llm",
        report_agent_llm="test_report_agent_llm",
        generate_mitre_attacks=True,
        generate_threats=True,
        generate_data_flow_reports=True,
    )


@pytest.fixture
def asset() -> Asset:
    return Asset(
        name="FullAsset",
        description="Asset description",
        internet_facing=True,
        authn_type=AuthnType.PASSWORD,
        data_classification=DataClassification.INTERNAL,
    )


@pytest.fixture
def repository(asset) -> Repository:
    return Repository(
        asset_uuid=asset.uuid,
        name="TestRepo",
        description="A test repository",
        url="https://example.com/repo",
    )


@pytest.fixture
def threat() -> Threat:
    return Threat(
        name="ThreatOne",
        stride_category=StrideCategory.TAMPERING,
        impact_level=Level.HIGH,
        risk_rating=Level.MEDIUM,
        component_names=["Comp1", "Comp2"],
        description="A threat description",
        attack_vector="Attack vector info",
        mitigations=["Mitigation A", "Mitigation B"],
    )


@pytest.fixture
def attack() -> Attack:
    return Attack(
        technique_id="T1000",
        technique_name="Technique A",
        url="https://attack.mitre.org/techniques/T1000/",
        component="ComponentX",
        component_uuid=uuid4(),
        is_subtechnique=False,
        parent_id=None,
        parent_name=None,
        reason_for_relevance="Highly relevant",
        mitigation="Use firewall",
    )


@pytest.fixture
def data_flow_report(repository, threat, attack) -> DataFlowReport:
    return DataFlowReport(
        repository_uuid=repository.uuid,
        overview="Data flow overview",
        diagram="graph TD;\nA-->B;",
        external_entities=[
            ExternalEntity(name="External1", description="An external entity")
        ],
        processes=[Process(name="Process1", description="A process")],
        data_stores=[DataStore(name="Store1", description="A data store")],
        trust_boundaries=[
            TrustBoundary(name="Boundary1", description="A trust boundary")
        ],
        threats=[threat],
        attacks=[attack],
        reviewed=[File(file_path="reviwed.py", justification="reviewed")],
        should_review=[
            File(file_path="should_review.py", justification="should be reviewed")
        ],
        should_not_review=[
            File(
                file_path="should_not_review.py", justification="should not be reviewed"
            )
        ],
        could_review=[
            File(file_path="could_review.py", justification="could be reviewed")
        ],
        could_not_review=[
            File(file_path="could_not_review.py", justification="Could not be reviewed")
        ],
    )


@pytest.fixture
def threat_model(asset, repository, data_flow_report) -> ThreatModel:
    """Fixture to create a complete ThreatModel instance."""

    # Create the ThreatModel instance
    return ThreatModel(
        name="FullTM",
        summary="Full model summary",
        asset=asset,
        repos=[repository],
        data_flow_reports=[data_flow_report],
    )


@pytest.fixture
def make_df(tmp_path):
    def _make(overview="o", repo_uuid=None):
        from uuid import uuid4

        base = {
            "uuid": uuid4(),
            "repository_uuid": repo_uuid or uuid4(),
            "overview": overview,
            **{
                k: []
                for k in (
                    "external_entities",
                    "processes",
                    "data_stores",
                    "trust_boundaries",
                    "threats",
                    "attacks",
                    "reviewed",
                    "should_review",
                    "should_not_review",
                    "could_review",
                    "could_not_review",
                )
            },
            "diagram": "",
        }
        return DataFlowReport.model_validate(base)

    return _make
