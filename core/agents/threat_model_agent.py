import asyncio
import json
import logging

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
from core.models.dtos.Threat import AgentThreat
from core.agents.agent_tools import (
    AgentHelper,
    ainvoke_with_retry,
    invoke_with_retry,
)
from langgraph.graph import StateGraph, START, END
from trustcall import create_extractor

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
"""


# -----------------------------------------------------------------------------
# ThreatModelAgent
# -----------------------------------------------------------------------------
class ThreatModelAgent:
    """Threat modeling agent that performs STRIDE analysis and consolidation."""

    def __init__(self, model: BaseChatModel) -> None:
        self.model = model
        self.agent_helper = AgentHelper()

    # -------------------------------------------------------------------------
    # Workflow Steps
    # -------------------------------------------------------------------------
    def initialize(self, state: ThreatGraphStateModel) -> ThreatGraphStateModel:
        """Initialize the state by converting UUIDs to internal numbered IDs."""
        logger.info("Initializing threat modeling state...")

        state.asset = self.agent_helper.convert_uuids_to_ids(state.asset)
        state.data_flow_report = self.agent_helper.convert_uuids_to_ids(
            state.data_flow_report
        )

        return state

    def finalize(self, state: ThreatGraphStateModel) -> ThreatGraphStateModel:
        """Clean up the state by converting internal numbered IDs back to UUIDs."""
        logger.info("Cleaning up threat modeling state...")

        state.threats = [
            self.agent_helper.convert_ids_to_uuids(threat) for threat in state.threats
        ]

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

        system_prompt_template = SYSTEM_PROMPT_ANALYZE

        # Select the appropriate system prompt template
        system_prompt = SystemMessagePromptTemplate.from_template(
            system_prompt_template,
        )

        user_prompt = HumanMessagePromptTemplate.from_template(
            """\
            <component>
            {component}
            </component>

            <asset>
            {asset}
            </asset>
            
            <data_flow_report>
            {data_flow_report}
            </data_flow_report>
            """
        )

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        chain = prompt | create_extractor(
            self.model, tools=[Result], tool_choice="Result"
        )

        asset = state.asset
        report = state.data_flow_report

        tasks = [
            self._process_component(component, asset, report, chain)
            for key in (
                "external_entities",
                "processes",
                "data_stores",
                "trust_boundaries",
            )
            for component in sorted(
                report.get(key, []), key=lambda c: c.get("name", "")
            )
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_threats: List[Dict[str, Any]] = []
        for res in results:
            if isinstance(res, Exception):
                logger.error("❌ An error occurred in component analysis", exc_info=res)
                continue
            if isinstance(res, list):
                all_threats.extend(res)

        logger.info(
            "✅ Finished threat model analysis. Total threats found: %d",
            len(all_threats),
        )
        self._log_threat_state(all_threats)

        state.threats = all_threats
        return state

    async def _process_component(
        self,
        component_data: Dict[str, Any],
        asset: Dict[str, Any],
        report: Dict[str, Any],
        chain: Any,
    ) -> List[Dict[str, Any]]:
        """Helper to process a single component asynchronously."""
        try:
            logger.debug(
                "Processing component: %s",
                component_data.get("name", "Unknown Component"),
            )

            result = await ainvoke_with_retry(
                chain,
                {
                    "asset": json.dumps(asset, sort_keys=True),
                    "data_flow_report": json.dumps(report, sort_keys=True),
                    "component": json.dumps(component_data, sort_keys=True),
                },
            )

            threats = result["responses"][0].threats
            logger.debug(
                "Identified %d threats in component: %s",
                len(threats),
                component_data.get("name", "Unknown Component"),
            )

            return threats

        except Exception as e:
            logger.exception(
                "❌ Error analyzing component '%s': %s",
                component_data.get("name", "Unknown Component"),
                str(e),
            )
            return []

    # def consolidate_threats(
    #     self, state: ThreatGraphStateModel
    # ) -> ThreatGraphStateModel:
    #     """Consolidate similar threats within each STRIDE category."""
    #     logger.info("🔍 Starting threat consolidation...")

    #     class ConsolidationResult(BaseModel):
    #         """
    #         Represents the consolidated result of a security analysis.

    #         This model aggregates identified threats from multiple analyses or
    #         different components of the system into a single structured result.
    #         """

    #         threats: List[AgentThreat]

    #     parser = JsonOutputParser(pydantic_object=ConsolidationResult)
    #     system_prompt = SystemMessagePromptTemplate.from_template(
    #         SYSTEM_PROMPT_CONSOLIDATE,
    #         partial_variables={"format_instructions": parser.get_format_instructions()},
    #     )
    #     user_prompt = HumanMessagePromptTemplate.from_template(
    #         "<threats>\n{threats}\n</threats>"
    #     )
    #     prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

    #     chain = prompt | self.model.with_structured_output(
    #         schema=ConsolidationResult.model_json_schema()
    #     )

    #     stride_groups: Dict[str, List[Dict[str, Any]]] = {}
    #     for threat in state.threats:
    #         category = threat.get("stride_category", "Unknown")
    #         stride_groups.setdefault(category, []).append(threat)

    #     consolidated: List[Dict[str, Any]] = []
    #     for category, group_list in stride_groups.items():
    #         try:
    #             logger.info("Consolidating threats in category: %s", category)

    #             result = invoke_with_retry(
    #                 chain, {"threats": json.dumps(group_list, sort_keys=True)}
    #             )

    #             merged_threats = result.get("threats", [])
    #             consolidated.extend(merged_threats)
    #         except Exception as e:
    #             logger.exception(
    #                 "❌ Error consolidating threats in category '%s'", category
    #             )

    #     logger.info(
    #         "✅ Finished threat consolidation. Total consolidated threats: %d",
    #         len(consolidated),
    #     )
    #     self._log_threat_state(consolidated)

    #     state.threats = consolidated
    #     return state

    # -------------------------------------------------------------------------
    # Logging / Reporting Helpers
    # -------------------------------------------------------------------------
    def _log_threat_state(self, threats: List[AgentThreat]) -> None:
        """Log summary of identified threats, including STRIDE distribution and risk levels."""
        if not threats:
            logger.warning("No threats identified.")
            return

        stride_counts = {
            category: 0
            for category in (
                "Spoofing",
                "Tampering",
                "Repudiation",
                "Information Disclosure",
                "Denial of Service",
                "Elevation of Privilege",
            )
        }
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}

        for threat in threats:
            stride = getattr(threat, "stride_category", "Unknown")
            risk = getattr(threat, "risk_rating", "Unknown")

            stride_counts[stride] = stride_counts.get(stride, 0) + 1
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        logger.info(
            f"🚨 Threat Summary:\n"
            f"  ⚠️ Total Threats: {len(threats)}\n"
            f"  🔐 STRIDE Breakdown:\n"
            f"    🕵️ Spoofing: {stride_counts['Spoofing']}\n"
            f"    ✍️ Tampering: {stride_counts['Tampering']}\n"
            f"    📝 Repudiation: {stride_counts['Repudiation']}\n"
            f"    🔓 Information Disclosure: {stride_counts['Information Disclosure']}\n"
            f"    ⛔ Denial of Service: {stride_counts['Denial of Service']}\n"
            f"    📈 Elevation of Privilege: {stride_counts['Elevation of Privilege']}\n"
            f"  🔥 Risk Levels:\n"
            f"    🟢 Low: {risk_counts['Low']}\n"
            f"    🟡 Medium: {risk_counts['Medium']}\n"
            f"    🔴 High: {risk_counts['High']}\n"
            f"    🛑 Critical: {risk_counts['Critical']}"
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
        workflow.add_node("finalize", self.finalize)
        # If you want to add consolidation step, uncomment and place appropriately:
        # workflow.add_node("consolidate_threats", self.consolidate_threats)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "analyze")
        workflow.add_edge("analyze", "finalize")
        # workflow.add_edge("analyze", "consolidate_threats")
        # workflow.add_edge("consolidate_threats", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()
