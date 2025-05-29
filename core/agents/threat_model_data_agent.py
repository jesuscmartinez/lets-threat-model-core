import logging
import logging
import json
from typing import Any, Dict

from pydantic import BaseModel, Field

# LangChain / local imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.agents.agent_tools import AgentHelper, ainvoke_with_retry
from langgraph.graph import StateGraph, START, END


logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pydantic Model for Graph State
# -----------------------------------------------------------------------------
class ThreatModelDataStateModel(BaseModel):
    """State object for threat model data generation."""

    threat_model: Dict[str, Any] = Field(default_factory=dict)
    summary: str = Field("", description="A summary of the threat model.")
    title: str = Field("", description="A generated title for the threat model.")


# -----------------------------------------------------------------------------
# Large Prompt (Constant)
# -----------------------------------------------------------------------------
SYSTEM_GENERATE_PROMPT = """\
Objective:
You are an expert in software threat modeling.

You will receive the following inputs:
1. **Asset**: Represents a specific resource or system entity.
2. **List[Repository]**: One or more code repositories associated with the asset.
3. **List[DataFlowReport]**: Detailed analyses of data flows within or related to the repositories.
4. **List[Threat]**: Identified threats associated with the asset and its repositories.
5. **Prior Summary** (optional): A previously generated summary of the threat model reports, if available.

Your task is to analyze this information and perform the following steps:

### 1. Title
Generate a concise, descriptive **title** that encapsulates the overall context of these data structures and their implications. The title should reflect the latest understanding of the system and any new insights.  
_(Example: "System Data Flow and Security Overview")_

### 2. Summary
Provide a comprehensive **summary** that:
- Describes the role and significance of the **Asset** in the system.
- Explains the purpose of the **Repositories** and their connection to the asset.
- Discusses the relevance and key insights from the **DataFlowReports**, including how they illustrate the flow of data, the involved entities, processes, data stores, and trust boundaries.
- Identifies and highlights the **Threats**, explaining their potential impact on the asset and the system's security posture.

### 3. Refine or Expand Previous Summary (if provided)
If a **prior summary** is provided:
- Refine or expand the previous summary to incorporate any **new information** from the latest report.
- Ensure the updated summary remains coherent and comprehensive, reflecting the **latest understanding** of the system.
- Do **not** simply repeat previous content—integrate new findings and insights while maintaining clarity and conciseness.

### Output Format:
- **Title**: A clear, concise title.
- **Summary**: An updated summary that builds upon the prior summary (if provided) and integrates all new information.
"""


# -----------------------------------------------------------------------------
# ThreatModelDataAgent
# -----------------------------------------------------------------------------
class ThreatModelDataAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state: ThreatModelDataStateModel) -> ThreatModelDataStateModel:
        """
        Convert the nested data in 'threat_model' from UUID to 'uuid_X' references
        for easier internal handling.
        """
        threat_model = state.threat_model

        # Validate the presence of required fields
        if "asset" not in threat_model or threat_model["asset"] is None:
            raise ValueError("Asset data is missing in threat_model")

        if (
            "data_flow_reports" not in threat_model
            or threat_model["data_flow_reports"] is None
        ):
            raise ValueError("Data flow reports are missing in threat_model")

        if "threats" not in threat_model or threat_model["threats"] is None:
            raise ValueError("Threat data is missing in threat_model")

        # Convert asset
        numbered_asset = self.agent_helper.convert_uuids_to_ids(threat_model["asset"])
        threat_model["asset"] = numbered_asset

        # Convert data flow reports
        data_flow_reports = threat_model["data_flow_reports"]
        numbered_reports = [
            self.agent_helper.convert_uuids_to_ids(report)
            for report in data_flow_reports
        ]
        threat_model["data_flow_reports"] = numbered_reports

        # Convert threats
        threats = threat_model["threats"]
        numbered_threats = [
            self.agent_helper.convert_uuids_to_ids(threat) for threat in threats
        ]
        threat_model["threats"] = numbered_threats

        # Update state
        state.threat_model = threat_model
        return state

    async def generate(
        self, state: ThreatModelDataStateModel
    ) -> ThreatModelDataStateModel:
        """
        Use the LLM to generate a title and summary for the threat model data.
        """
        logger.info("🔍 Starting threat model data generation...")

        # Pydantic model for LLM results
        class Result(BaseModel):
            """
            Represents the structured output of an LLM-generated threat model result.

            This model provides a title and a summary report for the generated
            threat model, ensuring clear and structured documentation of findings.
            """

            title: str = Field(..., description="Title for the summary.")
            summary: str = Field(
                ..., description="A summary report of the threat model."
            )

        # Prepare system & user prompts
        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_GENERATE_PROMPT
        )
        user_prompt = HumanMessagePromptTemplate.from_template(
            "Previous Summary:\n{previous_summary}\n\n"
            "Asset:\n{asset}\n\n"
            "DataFlowReport:\n{data_flow_report}\n\n"
            "Threats:\n{threats}\n"
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # Build chain with structured output
        chain = prompt | self.model.with_structured_output(
            schema=Result.model_json_schema()
        )

        # Prepare inputs
        threat_model = state.threat_model
        asset = threat_model.get("asset", {})
        reports = threat_model.get("data_flow_reports", [])
        threats = threat_model.get("threats", [])

        # Start with an empty summary
        previous_summary = "No previous summary available."

        # Loop over each data flow report, progressively building the summary
        for idx, report in enumerate(reports):
            logger.info(f"📄 Generating summary for report {idx + 1}/{len(reports)}...")

            overview = report.get("overview", "No overview available.")

            # Prepare inputs for this iteration
            chain_inputs = {
                "previous_summary": previous_summary,
                "asset": json.dumps(asset, sort_keys=True),
                "data_flow_report": json.dumps(
                    overview, sort_keys=True
                ),  # Singular report
                "threats": json.dumps(threats, sort_keys=True),
            }

            # Invoke the chain with retry logic
            result = await ainvoke_with_retry(chain, chain_inputs)

            # Ensure result is parsed correctly
            if isinstance(result, dict):
                result = Result(**result)

            # Update the running summary with the latest result
            previous_summary = result.summary

        state.title = result.title
        state.summary = result.summary

        logger.info("✅ Threat model data generation complete.")
        logger.debug("Generated title: %s", state.title)
        logger.debug("Generated summary: %s", state.summary)

        return state

    def get_workflow(self) -> StateGraph:
        """
        Defines and compiles the workflow for threat model data generation.
        """
        workflow = StateGraph(ThreatModelDataStateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("generate", self.generate)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "generate")
        workflow.add_edge("generate", END)

        return workflow.compile()
