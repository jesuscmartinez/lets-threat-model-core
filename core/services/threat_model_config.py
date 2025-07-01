from openai import base_url
from pydantic import Field, SecretStr
from typing import Literal, ClassVar

from core.agents.repo_data_flow_agent_config import RepoDataFlowAgentConfig


class ThreatModelConfig(RepoDataFlowAgentConfig):
    """
    Extended configuration for threat model processing.
    """

    username: str = Field(
        default="default_user", description="Username for authentication"
    )
    pat: SecretStr = Field(
        default=SecretStr("default_secret"), description="Personal Access Token (PAT)"
    )

    llm_provider: str = Field(default="openai", description="LLM Provider")

    api_key: SecretStr = Field(
        default=SecretStr("default_api_key"),
        description="API key for the LLM provider",
    )

    base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for the LLM provider API",
    )

    categorization_agent_llm: str = Field(
        default="gpt-4o-mini", description="LLM model for categorization agent"
    )
    review_agent_llm: str = Field(
        default="gpt-4o-mini", description="LLM model for review agent"
    )
    threat_model_agent_llm: str = Field(
        default="gpt-4o-mini", description="LLM model for threat modeling"
    )
    report_agent_llm: str = Field(
        default="gpt-4o-mini", description="LLM model for report generation"
    )

    generate_mitre_attacks: bool = Field(
        default=True,
        description="Whether to generate MITRE ATT&CK tactics and techniques",
    )
    generate_threats: bool = Field(
        default=True,
        description="Whether to generate threats",
    )

    generate_data_flow_reports: bool = Field(
        default=True,
        description="Whether to generate data flow reports",
    )

    STRATEGY_PER_REPOSITORY: ClassVar[str] = "per-repository"
    STRATEGY_COMBINED: ClassVar[str] = "combined"
    STRATEGY_BOTH: ClassVar[str] = "both"

    data_flow_report_strategy: Literal["per-repository", "combined", "both"] = Field(
        default=STRATEGY_PER_REPOSITORY,
        description=(
            "Strategy for data flow reports in the threat model: "
            "'per-repository' for one report per repo, "
            "'combined' for a single merged report, "
            "'both' to include individual and combined reports."
        ),
    )
