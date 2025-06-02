from pydantic import Field, SecretStr

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
