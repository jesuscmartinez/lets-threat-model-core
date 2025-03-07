import logging
import os
import json
import asyncio
import re
from typing import Any, Dict, List

from pydantic import BaseModel, Field

# LangChain / local imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
    AIMessagePromptTemplate,
)
from langchain_core.output_parsers import JsonOutputParser
from core.models.dtos.DataFlowReport import AgentDataFlowReport
from core.models.dtos.Threat import AgentThreat
from core.models.dtos.Asset import Asset
from core.models.enums import StrideCategory, Level
from core.agents.agent_tools import AgentHelper, is_o1
from langgraph.graph import StateGraph, START, END

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pydantic Model for the Graph State
# -----------------------------------------------------------------------------
class ThreatGraphStateModel(BaseModel):
    """Holds the state for threat modeling: data flow, identified threats, and the asset."""

    data_flow_report: Dict[str, Any] = Field(default_factory=dict)
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    asset: Dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------------------------------------
# Large Prompt Texts (Constants)
# -----------------------------------------------------------------------------
SYSTEM_PROMPT_ANALYZE = """\
Objective:
Perform a comprehensive STRIDE-based threat analysis on the provided **Component**. Evaluate the Component with the provided context of Asset data and DataFlowReport.

Additional Instructions:
    - If a single threat scenario plausibly fits multiple STRIDE categories (e.g., both Tampering and Repudiation), create a separate threat entry for each category instead of listing multiple categories in a single entry.
    - Use concrete examples from the Asset and AgentDataFlowReport (e.g., naming specific Processes, DataFlows, or DataStores) to illustrate how each threat might apply in practice
    - For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, EoP), list multiple realistic threats if applicable—do **not** limit to just one.

For each threat identified, provide:
    1. Name: The name of the identified threat.
    2. Description: A detailed description of the threat.
    3. STRIDE Category: STRIDE security category.
    4. Component Name: The name of the component impacted by the threat.
    5. Component UUID: The ID of the component impacted by the threat.
    6. Attack Vector: A detailed explanation of how the attack is executed.
    7. Impact Level: The potential harm to the system or its stakeholders.
    8. Risk Level: A qualitative or quantitative assessment of how likely the threat is to occur and how severe its impact could be (e.g., Low, Medium, High).
    9. Mitigations: Recommended controls, countermeasures, or design changes. Where applicable, reference relevant standards or frameworks (e.g., OWASP, NIST, ISO) for implementing recommended controls.

Guidelines for Analysis:
    1. Component Evaluation
        • Processes
            • Review all input_data and output_data for each Process.
            • Assess if malicious data manipulation or insufficient validation could lead to Spoofing, Tampering, or Information Disclosure.
            • Evaluate whether a process could be forced into denying service (DoS) or inadvertently provide elevated privileges (EoP).
        • DataStores
            • Examine data_inputs and data_outputs for access control weaknesses.
            • Identify if stored data is vulnerable to Tampering, Information Disclosure, or potential Repudiation events (e.g., inadequate logging).
            • Consider if the DataStore’s availability is critical (DoS) or if its controls are weak enough to permit unauthorized privilege escalation (EoP).
        • ExternalEntities
            • Verify authentication/identification methods to prevent Spoofing.
            • Evaluate input from external sources for malicious manipulation or tampering.
            • Check if external entities can deny actions (Repudiation) or disrupt services (DoS).
            • Consider scenarios where they gain Elevation of Privilege through unprotected interfaces.
        • TrustBoundaries
            • Identify all boundaries (e.g., network segments, application layers, user-to-system interfaces).
            • Determine whether crossing these boundaries introduces heightened risks of Spoofing, Tampering, Information Disclosure, or Repudiation.
            • Analyze boundary validation and enforcement mechanisms for resilience against DoS and EoP attacks.
    2. Threat Mapping for DataFlows
        • DataFlow Source and Destination
            • Map each DataFlow to its originating component (Process, ExternalEntity, DataStore) and its target.
            • Assess how the data type, flow direction, or protocol could expose the system to Spoofing or Information Disclosure.
            • Consider unprotected inbound/outbound requests, especially across trust boundaries.
        • Data Sensitivity & Integrity
            • Examine whether confidentiality and integrity controls (e.g., encryption, checksums, digital signatures) are in place to prevent Tampering or Disclosure.
            • Determine if inadequate logging or validation leads to Repudiation risks.
        • Availability & Privilege
            • Evaluate if the data flow can be disrupted (leading to DoS).
            • Check whether flaws in flow handling could grant undesired permissions (EoP).
    3. Trust Boundary Assessment
        • Cross-Boundary Risks
            • Document each point where a Process or DataFlow crosses a TrustBoundary.
            • Determine the potential for Spoofing (misidentifying entities) and Tampering (altering data).
            • Assess whether boundary-crossing data could be exposed to unauthorized parties (Information Disclosure).
            • Evaluate risk of Repudiation when logs or audit trails do not carry over across boundaries.
        • Security Controls & Enforcement
            • Identify existing protective measures at each boundary (firewalls, proxies, gateways, etc.) and gauge effectiveness against DoS or EoP attacks.
            • Suggest additional or improved controls where weaknesses are found.

Format Instructions:
{format_instructions}
"""

SYSTEM_PROMPT_CONSOLIDATE = """\
Objective:
Identify and merge only truly similar threats, ensuring each merged threat retains all relevant attack vectors, affected components, and mitigation strategies.
    - Do NOT merge threats if they are not similar.
    - Do NOT merge threats if they are different categories.

Instructions:
1. Check for Similarity Before Merging
    • Consider threats similar if they have:
        • Overlapping descriptions (addressing the same security concern).
        • Similar attack vectors (i.e., the method of exploitation is the same or nearly identical).
        • The same or closely related affected components.
        • Comparable mitigation strategies (if mitigations significantly differ, they may not be the same threat).
    • Do NOT merge threats if:
        • They describe fundamentally different attack scenarios.
        • They target completely unrelated components with different impacts.

2. Merge Threats Following These Rules:
    • Threat Name: Create a general name that reflects all merged threats.
    • Description: Combine relevant details while preserving all exploitation scenarios.
    • Components & IDs: Include all affected components.
    • Attack Vectors: Merge attack techniques into a single detailed vector covering all variations.
    • Impact Level & Risk Rating: Select the highest level from the merged threats.
    • Mitigations: Aggregate all mitigation steps into a single actionable list.

Format Instructions:
{format_instructions}
"""


# -----------------------------------------------------------------------------
# ThreatModelAgent
# -----------------------------------------------------------------------------
class ThreatModelAgent:
    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    # -------------------------------------------------------------------------
    # Workflow Steps
    # -------------------------------------------------------------------------
    def initialize(self, state: ThreatGraphStateModel) -> ThreatGraphStateModel:
        """
        Convert the state's asset and data_flow_report from UUID to the
        internal 'uuid_X' numbering scheme for easier reference.
        """
        # Convert asset to numbered IDs
        numbered_asset = self.agent_helper.convert_uuids_to_ids(state.asset)
        state.asset = numbered_asset

        # Convert data flow report to numbered IDs
        numbered_report = self.agent_helper.convert_uuids_to_ids(state.data_flow_report)
        state.data_flow_report = numbered_report

        return state

    def clean_up(self, state: ThreatGraphStateModel) -> ThreatGraphStateModel:
        """
        Convert threats from 'uuid_X' back to original UUID strings at the end of the workflow.
        """
        threats = [
            self.agent_helper.convert_ids_to_uuids(threat) for threat in state.threats
        ]
        state.threats = threats
        return state

    async def analyze(self, state: ThreatGraphStateModel) -> ThreatGraphStateModel:
        """
        Perform STRIDE-based threat analysis across all components in the data_flow_report.
        Each component is processed separately, and the identified threats are aggregated.
        """
        logger.info("🔍 Starting threat model analysis...")

        class Result(BaseModel):
            """
            Represents the result of a security analysis.

            This model contains a list of identified threats detected during
            the threat modeling process.
            """

            threats: List[AgentThreat] = Field(..., description="Identified threats.")

        parser = JsonOutputParser(pydantic_object=Result)
        format_instructions = parser.get_format_instructions()

        if is_o1(self.model):
            system_prompt = AIMessagePromptTemplate.from_template(
                SYSTEM_PROMPT_ANALYZE,
                partial_variables={"format_instructions": format_instructions},
            )
        else:
            system_prompt = SystemMessagePromptTemplate.from_template(
                SYSTEM_PROMPT_ANALYZE,
                partial_variables={"format_instructions": format_instructions},
            )
        user_prompt = HumanMessagePromptTemplate.from_template(
            "Component:\n{component}\n\nAsset:\n{asset}\nAgentDataFlowReport:\n{data_flow_report}"
        )

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        chain = prompt | self.model.with_structured_output(
            schema=Result.model_json_schema()
        )

        # If we have an O1 model, we'll adapt the chain logic
        if is_o1(self.model):
            chain = prompt | self.model  # We'll parse after

        asset = state.asset
        report = state.data_flow_report

        # We'll define an async helper to process one component at a time
        async def process_component(
            component_data: Dict[str, Any]
        ) -> List[Dict[str, Any]]:
            """Invoke the LLM chain for a single component and return a list of threat dicts."""
            try:
                result = await chain.ainvoke(
                    {
                        "asset": json.dumps(asset),
                        "data_flow_report": json.dumps(report),
                        "component": json.dumps(component_data),
                    }
                )

                logging.debug(
                    f"✅ Threat analysis successful. Processed component: '{component_data.get('name', 'Unknown Component')}'. Result: {json.dumps(result, indent=2)}"
                )

                # If is O1, parse after the fact
                if is_o1(self.model):
                    cleaned_content = re.sub(r"```json|```", "", result.content).strip()
                    result = json.loads(cleaned_content)

                if isinstance(result, dict):
                    identified = result.get("threats", [])
                    logger.debug(
                        "Found %d threats in component analysis.", len(identified)
                    )
                    return identified
                return []
            except Exception as e:
                logger.error("❌ Error analyzing component: %s", e, exc_info=True)
                return []

        # Collect all components from the data_flow_report to be analyzed
        tasks = []
        for key in (
            "external_entities",
            "processes",
            "data_stores",
            "trust_boundaries",
        ):
            for component in report.get(key, []):
                tasks.append(process_component(component))

        # Process them concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Flatten the list of threats
        all_threats = []
        for res in results:
            if isinstance(res, Exception):
                logger.error("❌ An error occurred in threat analysis: %s", res)
                continue
            all_threats.extend(res)

        logger.info(
            "✅ Finished threat model analysis. Total threats found: %d",
            len(all_threats),
        )
        self.log_threat_state(all_threats)

        state.threats = all_threats
        return state

    def consolidate_threats(
        self, state: ThreatGraphStateModel
    ) -> ThreatGraphStateModel:
        """
        Takes the existing 'threats' in state and attempts to merge only truly similar
        threats within each STRIDE category.
        """
        logger.info("🔍 Starting threat consolidation analysis...")

        class ConsolidationResult(BaseModel):
            """
            Represents the consolidated result of a security analysis.

            This model aggregates identified threats from multiple analyses or
            different components of the system into a single structured result.
            """

            threats: List[AgentThreat] = Field(..., description="Identified threats.")

        parser = JsonOutputParser(pydantic_object=ConsolidationResult)

        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_PROMPT_CONSOLIDATE,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )
        user_prompt = HumanMessagePromptTemplate.from_template("Threats:\n{threats}")

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])
        chain = prompt | self.model.with_structured_output(
            schema=ConsolidationResult.model_json_schema()
        )

        # Group threats by stride_category
        threats = state.threats
        stride_groups = {}
        for threat in threats:
            category = threat.get("stride_category", "Unknown")
            stride_groups.setdefault(category, []).append(threat)

        # Process each category separately
        consolidated = []
        for category, group_list in stride_groups.items():
            try:
                result = chain.invoke(input={"threats": json.dumps(group_list)})
                merged = result.get("threats", [])
                consolidated.extend(merged)
            except Exception as e:
                logger.error(
                    "❌ Error consolidating threats in category %s: %s", category, e
                )

        logger.info(
            "✅ Finished threat consolidation analysis. Total: %d", len(consolidated)
        )
        self.log_threat_state(consolidated)
        state.threats = consolidated
        return state

    # -------------------------------------------------------------------------
    # Logging / Reporting Helpers
    # -------------------------------------------------------------------------
    def log_threat_state(self, threats: List[Dict[str, Any]]) -> None:
        """
        Logs a summary of identified threats, including STRIDE distribution and risk levels.
        """
        if not threats:
            logger.warning("No threats identified.")
            return

        # Initialize counters for STRIDE categories and risk levels
        stride_counts = {
            "Spoofing": 0,
            "Tampering": 0,
            "Repudiation": 0,
            "Information Disclosure": 0,
            "Denial of Service": 0,
            "Elevation of Privilege": 0,
        }
        risk_counts = {
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0,
        }

        for threat in threats:
            stride = threat.get("stride_category", "Unknown")
            risk = threat.get("risk_rating", "Unknown")

            if stride in stride_counts:
                stride_counts[stride] += 1
            else:
                logger.warning("⚠️ Unknown STRIDE category: %s", stride)

            if risk in risk_counts:
                risk_counts[risk] += 1
            else:
                logger.warning("⚠️ Unknown Risk Rating: %s", risk)

        logger.info(
            "🚨 Threat Summary:\n"
            "  ⚠️ Total Threats: %d\n"
            "  🔐 STRIDE Breakdown:\n"
            "    🕵️ Spoofing: %d\n"
            "    ✍️ Tampering: %d\n"
            "    📝 Repudiation: %d\n"
            "    🔓 Information Disclosure: %d\n"
            "    ⛔ Denial of Service: %d\n"
            "    📈 Elevation of Privilege: %d\n"
            "  🔥 Risk Levels:\n"
            "    🟢 Low: %d\n"
            "    🟡 Medium: %d\n"
            "    🔴 High: %d\n"
            "    🛑 Critical: %d",
            len(threats),
            stride_counts["Spoofing"],
            stride_counts["Tampering"],
            stride_counts["Repudiation"],
            stride_counts["Information Disclosure"],
            stride_counts["Denial of Service"],
            stride_counts["Elevation of Privilege"],
            risk_counts["Low"],
            risk_counts["Medium"],
            risk_counts["High"],
            risk_counts["Critical"],
        )

        # Log each threat in detail
        for threat in threats:
            logger.info(
                "🚨 Threat: %s\n"
                "  📌 Description: %s\n"
                "  🎯 STRIDE Category: %s\n"
                "  🏗️ Components: %s\n"
                "  🔍 Attack Vector: %s\n"
                "  ⚠️ Impact Level: %s\n"
                "  🔥 Risk Rating: %s\n"
                "  🛡️ Mitigations: %s",
                threat.get("name", "Unknown Threat"),
                threat.get("description", "No description provided"),
                threat.get("stride_category", "Unknown"),
                threat.get("component_names", "Unknown Component"),
                threat.get("attack_vector", "No attack vector"),
                threat.get("impact_level", "Unknown"),
                threat.get("risk_rating", "Unknown"),
                threat.get("mitigations", "No mitigation provided"),
            )

    # -------------------------------------------------------------------------
    # Workflow
    # -------------------------------------------------------------------------
    def get_workflow(self):
        """
        Define the workflow for threat model analysis and compile it.
        """
        workflow = StateGraph(ThreatGraphStateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("analyze", self.analyze)
        workflow.add_node("clean_up", self.clean_up)
        # If you want to add consolidation step, uncomment and place appropriately:
        # workflow.add_node("consolidate_threats", self.consolidate_threats)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "analyze")
        workflow.add_edge("analyze", "clean_up")
        # workflow.add_edge("analyze", "consolidate_threats")
        # workflow.add_edge("consolidate_threats", "clean_up")
        workflow.add_edge("clean_up", END)

        return workflow.compile()
