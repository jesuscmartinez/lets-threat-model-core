from pydantic import Field, SecretStr

from core.agents.repo_data_flow_agent_config import RepoDataFlowAgentConfig


class ThreatModelConfig(RepoDataFlowAgentConfig):
    """
    Extended configuration for threat model processing.
    """

    username: str = Field(..., description="Username for authentication")
    pat: SecretStr = Field(..., description="Personal Access Token (PAT)")

    llm_provider: str = Field("openai", description="LLM Provider")
    categorization_agent_llm: str = Field(
        "gpt-4o-mini", description="LLM model for categorization agent"
    )
    review_agent_llm: str = Field(
        "gpt-4o-mini", description="LLM model for review agent"
    )
    threat_model_agent_llm: str = Field(
        "gpt-4o-mini", description="LLM model for threat modeling"
    )
    report_agent_llm: str = Field(
        "gpt-4o-mini", description="LLM model for report generation"
    )
