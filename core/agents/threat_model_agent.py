from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from langchain_core.output_parsers import JsonOutputParser
from core.models.dtos.DataFlowReport import DataFlowReport, AgentDataFlowReport
from core.agents.agent_tools import AgentHelper
from langgraph.graph import StateGraph, START, END
import logging
import os
from typing import TypedDict, List, Dict
from pydantic import BaseModel, Field
from core.models.dtos.Threat import AgentThreat
from core.models.dtos.Asset import Asset
from core.models.enums import StrideCategory, Level
import json
import asyncio

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class GraphState(TypedDict):
    data_flow_report: Dict
    threats: List[Dict]
    asset: Dict


class ThreatModelAgent:

    def __init__(self, model: BaseChatModel):
        self.model = model
        self.agent_helper = AgentHelper()

    def initialize(self, state) -> GraphState:

        # Convert asset to uuid_X dict
        asset = state.get("asset")
        numbered_asset = self.agent_helper.convert_uuids_to_numbered_ids(asset)
        state["asset"] = numbered_asset

        # Convert data flow report to uuid_X dict
        data_flow_report = state.get("data_flow_report")
        numbered_report = self.agent_helper.convert_uuids_to_numbered_ids(
            data_flow_report
        )

        state["data_flow_report"] = numbered_report

        return state

    def clean_up(self, state) -> GraphState:

        threats = [
            self.agent_helper.convert_numbered_ids_to_uuids(threat)
            for threat in state.get("threats", [])
        ]

        state["threats"] = threats

        return state

    async def analyze(self, state: GraphState) -> GraphState:
        logger.info("🔍 Starting threat model analysis...")

        class Result(BaseModel):
            threats: List[AgentThreat] = Field(..., description="Identified threats.")

        parser = JsonOutputParser(pydantic_object=Result)

        system_prompt = SystemMessagePromptTemplate.from_template(
            """
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
            6. Attack Vector: A detialed explaination of how the attack is executed.
            7. Impact Level: The potential harm to the system or its stakeholders.
            8. Risk Level: A qualitative or quantitative assessment of how likely the threat is to occur and how severe its impact could be (e.g., Low, Medium, High).
            9. Mitigations: Recommended controls, countermeasures, or design changes. Where applicable, reference relevant standards or frameworks (e.g., OWASP, NIST, ISO) for implementing recommended controls.
                                         
        Guidelines for Analysis:
            1. Component Evaluation
                •	Processes
                    •	Review all input_data and output_data for each Process.
                    •	Assess if malicious data manipulation or insufficient validation could lead to Spoofing, Tampering, or Information Disclosure.
                    •	Evaluate whether a process could be forced into denying service (DoS) or inadvertently provide elevated privileges (EoP).
                •	DataStores
                    •	Examine data_inputs and data_outputs for access control weaknesses.
                    •	Identify if stored data is vulnerable to Tampering, Information Disclosure, or potential Repudiation events (e.g., inadequate logging).
                    •	Consider if the DataStore’s availability is critical (DoS) or if its controls are weak enough to permit unauthorized privilege escalation (EoP).
                •	ExternalEntities
                    •	Verify authentication/identification methods to prevent Spoofing.
                    •	Evaluate input from external sources for malicious manipulation or tampering.
                    •	Check if external entities can deny actions (Repudiation) or disrupt services (DoS).
                    •	Consider scenarios where they gain Elevation of Privilege through unprotected interfaces.
                •	TrustBoundaries
                    •	Identify all boundaries (e.g., network segments, application layers, user-to-system interfaces).
                    •	Determine whether crossing these boundaries introduces heightened risks of Spoofing, Tampering, Information Disclosure, or Repudiation.
                    •	Analyze boundary validation and enforcement mechanisms for resilience against DoS and EoP attacks.
            2. Threat Mapping for DataFlows
                •	DataFlow Source and Destination
                    •	Map each DataFlow to its originating component (Process, ExternalEntity, DataStore) and its target.
                    •	Assess how the data type, flow direction, or protocol could expose the system to Spoofing or Information Disclosure.
                    •	Consider unprotected inbound/outbound requests, especially across trust boundaries.
                •	Data Sensitivity & Integrity
                    •	Examine whether confidentiality and integrity controls (e.g., encryption, checksums, digital signatures) are in place to prevent Tampering or Disclosure.
                    •	Determine if inadequate logging or validation leads to Repudiation risks.
                •	Availability & Privilege
                    •	Evaluate if the data flow can be disrupted (leading to DoS).
                    •	Check whether flaws in flow handling could grant undesired permissions (EoP).
            3. Trust Boundary Assessment
                •	Cross-Boundary Risks
                    •	Document each point where a Process or DataFlow crosses a TrustBoundary.
                    •	Determine the potential for Spoofing (misidentifying entities) and Tampering (altering data).
                    •	Assess whether boundary-crossing data could be exposed to unauthorized parties (Information Disclosure).
                    •	Evaluate risk of Repudiation when logs or audit trails do not carry over across boundaries.
                •	Security Controls & Enforcement
                    •	Identify existing protective measures at each boundary (firewalls, proxies, gateways, etc.) and gauge effectiveness against DoS or EoP attacks.
                    •	Suggest additional or improved controls where weaknesses are found.
        """,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        user_prompt = HumanMessagePromptTemplate.from_template(
            "Component:\n{component}\n\nAsset:\n{asset}\nAgentDataFlowReport:\n{data_flow_report}"
        )

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        chain = prompt | self.model.with_structured_output(
            schema=Result.model_json_schema()
        )

        asset = state.get("asset")
        report = state.get("data_flow_report")

        async def process_component(component):
            try:
                result = await chain.ainvoke(
                    input={
                        "asset": json.dumps(asset),
                        "data_flow_report": json.dumps(report),
                        "component": json.dumps(component),
                    }
                )

                if isinstance(result, dict):
                    logger.debug(
                        f"Number of threats identified: {len(result.get('threats', []))}"
                    )
                    return result.get("threats", [])

                return []

            except Exception as e:
                logger.error("❌ Error processing batch: %s", e)
                return []

        tasks = [
            process_component(component)
            for key in (
                "external_entities",
                "processes",
                "data_stores",
                "trust_boundaries",
            )
            for component in (report.get(key) or [])
        ]
        threats = await asyncio.gather(*tasks, return_exceptions=True)

        threats = [
            threat
            for sublist in threats
            if isinstance(sublist, list)
            for threat in sublist
        ]

        logger.info("✅ Finished threat model analysis.")
        self.log_threat_state(threats)

        state["threats"] = threats

        return state

    def consolidate_threats(self, state) -> GraphState:
        logger.info("🔍 Starting threat consolidation analysis...")
        threats = state.get("threats", [])

        class Result(BaseModel):
            threats: List[AgentThreat] = Field(..., description="Identified threats.")

        parser = JsonOutputParser(pydantic_object=Result)

        input_example = [
            {
                "name": "Repudiation of Asset Submission",
                "description": "Users may deny submitting asset data or the contents of their submission, leading to difficulties in tracking changes or actions taken in the system.",
                "stride_category": "Repudiation",
                "component_name": "User",
                "component_id": "uuid_2",
                "attack_vector": "A user submits asset data and later claims they did not submit it, leading to a lack of accountability.",
                "impact_level": "Medium",
                "risk_rating": "Medium",
                "mitigations": [
                    "Implement robust logging mechanisms to record user actions and submissions, ensuring they are tamper-proof."
                ],
            },
            {
                "name": "Repudiation of Threat Model Generation Requests",
                "description": "Users may deny having submitted a Threat Model Generation Request if sufficient logging is not in place, leading to accountability issues.",
                "stride_category": "Repudiation",
                "component_name": "Threat Management Boundary",
                "component_id": "uuid_16",
                "attack_vector": "A user submits a request for threat model generation but later denies it due to insufficient logging.",
                "impact_level": "Medium",
                "risk_rating": "Medium",
                "mitigations": [
                    "Ensure all requests and actions are logged securely and cannot be altered."
                ],
            },
            {
                "name": "Denial of Service via API Flooding",
                "description": "An attacker floods the API with excessive requests to cause service degradation or downtime.",
                "stride_category": "Denial of Service",
                "component_name": "Backend API",
                "component_id": "uuid_10",
                "attack_vector": "Attacker uses botnets to flood the API with numerous requests, consuming all resources and making it unavailable.",
                "impact_level": "High",
                "risk_rating": "Critical",
                "mitigations": [
                    "Implement rate limiting, request throttling, and deploy a Web Application Firewall (WAF)."
                ],
            },
            {
                "name": "Denial of Service via Database Overload",
                "description": "An attacker sends a high volume of queries to the database, overloading it and making it slow or unresponsive.",
                "stride_category": "Denial of Service",
                "component_name": "PostgreSQL Database",
                "component_id": "uuid_21",
                "attack_vector": "The attacker sends multiple expensive queries to the database, consuming all resources and making legitimate queries fail.",
                "impact_level": "High",
                "risk_rating": "High",
                "mitigations": [
                    "Implement query rate limiting, optimize database performance, and use caching mechanisms."
                ],
            },
        ]

        output_example_1 = {
            "name": "Repudiation of User and Threat Model Submission",
            "description": "Users may deny submitting asset data or threat model generation requests due to insufficient logging, leading to accountability issues and difficulty tracking changes.",
            "stride_category": "Repudiation",
            "component_names": ["User", "Threat Management Boundary"],
            "component_ids": ["uuid_2", "uuid_16"],
            "attack_vector": "A user submits an asset or threat model request and later denies having done so, exploiting a lack of logging and audit mechanisms.",
            "impact_level": "Medium",
            "risk_rating": "Medium",
            "mitigations": [
                "Implement robust logging mechanisms to track and secure all user actions.",
                "Ensure request logs are immutable and tamper-proof to prevent denial of actions.",
            ],
        }

        output_example_2 = [
            {
                "name": "Denial of Service via API Flooding",
                "description": "An attacker floods the API with excessive requests to cause service degradation or downtime.",
                "stride_category": "Denial of Service",
                "component_name": "Backend API",
                "component_id": "uuid_10",
                "attack_vector": "Attacker uses botnets to flood the API with numerous requests, consuming all resources and making it unavailable.",
                "impact_level": "High",
                "risk_rating": "Critical",
                "mitigations": [
                    "Implement rate limiting, request throttling, and deploy a Web Application Firewall (WAF)."
                ],
            },
            {
                "name": "Denial of Service via Database Overload",
                "description": "An attacker sends a high volume of queries to the database, overloading it and making it slow or unresponsive.",
                "stride_category": "Denial of Service",
                "component_name": "PostgreSQL Database",
                "component_id": "uuid_21",
                "attack_vector": "The attacker sends multiple expensive queries to the database, consuming all resources and making legitimate queries fail.",
                "impact_level": "High",
                "risk_rating": "High",
                "mitigations": [
                    "Implement query rate limiting, optimize database performance, and use caching mechanisms."
                ],
            },
        ]

        system_prompt = SystemMessagePromptTemplate.from_template(
            """
        Objective:
        Identify and merge only truly similar threats, ensuring each merged threat retains all relevant attack vectors, affected components, and mitigation strategies.
            - Do NOT merge threats if they are not similar.
            - Do NOT merge threats if they are different categories.

        Instructions:
        1. Check for Similarity Before Merging
            •	Consider threats similar if they have:
            •	Overlapping descriptions (addressing the same security concern).
            •	Similar attack vectors (i.e., the method of exploitation is the same or nearly identical).
            •	The same or closely related affected components.
            •	Comparable mitigation strategies (if mitigations significantly differ, they may not be the same threat).
            •	Do NOT merge threats if:
                •	They describe fundamentally different attack scenarios.
                •	They target completely unrelated components with different impacts.

        2. Merge Threats Following These Rules:
            •	Threat Name: Create a general name that reflects all merged threats.
            •	Description: Combine relevant details while preserving all exploitation scenarios.
            •	Components & IDs: Include all affected components.
            •	Attack Vectors: Merge attack techniques into a single detailed vector covering all variations.
            •	Impact Level & Risk Rating: Select the highest level from the merged threats.
            •	Mitigations: Aggregate all mitigation steps into a single actionable list.

        Example Input:
        ```json
        {input_example}
        ```

        Example Output:
        1. Merge Similar Threats (They Address the Same Issue)
            ```json
            {output_example_1}
            ```

        2. Do NOT Merge Threats (Different Attack Methods & Targets)
            •	“Denial of Service via API Flooding” and “Denial of Service via Database Overload” should NOT be merged because they involve different attack vectors and affected components.

            They remain separate threats, but clearly defined:
            ```json
            {output_example_2}
            ```

        Format Instructions:
        {format_instructions}
        """,
            partial_variables={
                "input_example": json.dumps(input_example),
                "output_example_1": json.dumps(output_example_1),
                "output_example_2": json.dumps(output_example_2),
                "format_instructions": parser.get_format_instructions(),
            },
        )

        user_prompt = HumanMessagePromptTemplate.from_template("Threats:\n{threats}")

        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        chain = prompt | self.model.with_structured_output(
            schema=Result.model_json_schema()
        )

        # Group threats by STRIDE category
        stride_groups = {}
        for threat in threats:
            category = threat["stride_category"]
            if category not in stride_groups:
                stride_groups[category] = []
            stride_groups[category].append(threat)

        # Process Each STRIDE Category Separately
        consolidated_threats = []
        for category, threats_in_category in stride_groups.items():
            result = chain.invoke(input={"threats": json.dumps(threats_in_category)})

            merged_threats = result.get("threats", [])
            consolidated_threats.extend(merged_threats)

        logger.info("✅ Finished threat consolidation analysis.")
        self.log_threat_state(consolidated_threats)
        state["threats"] = consolidated_threats

        return state

    def log_threat_state(self, threats: List[dict]):
        """Logs a summary of identified threats, including STRIDE distribution and risk levels."""
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
            stride_category = threat.get("stride_category", "Unknown")
            risk_rating = threat.get("risk_rating", "Unknown")

            if stride_category in stride_counts:
                stride_counts[stride_category] += 1
            else:
                logger.warning(f"⚠️ Unknown STRIDE category: {stride_category}")

            if risk_rating in risk_counts:
                risk_counts[risk_rating] += 1
            else:
                logger.warning(f"⚠️ Unknown Risk Rating: {risk_rating}")

        # Log summary statistics
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

        # Log detailed threat information
        for threat in threats:
            logger.info(
                f"🚨 Threat: {threat.get('name', 'Unknown Threat')}\n"
                f"  📌 Description: {threat.get('description', 'No description provided')}\n"
                f"  🎯 STRIDE Category: {threat.get('stride_category', 'Unknown')}\n"
                f"  🏗️ Components: {threat.get('component_names', 'Unknown Component')}\n"
                f"  🔍 Attack Vector: {threat.get('attack_vector', 'No attack vector provided')}\n"
                f"  ⚠️ Impact Level: {threat.get('impact_level', 'Unknown')}\n"
                f"  🔥 Risk Rating: {threat.get('risk_rating', 'Unknown')}\n"
                f"  🛡️ Mitigations: {threat.get('mitigations', 'No mitigation provided')}"
            )

    def get_workflow(self):
        """Defines and compiles the workflow for threat model analysis."""
        workflow = StateGraph(GraphState)

        workflow.add_node("analyze", self.analyze)
        workflow.add_node("initialize", self.initialize)
        workflow.add_node("consolidate_threats", self.consolidate_threats)
        workflow.add_node("clean_up", self.clean_up)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "analyze")
        workflow.add_edge("analyze", "consolidate_threats")
        workflow.add_edge("consolidate_threats", "clean_up")
        workflow.add_edge("clean_up", END)

        return workflow.compile()
