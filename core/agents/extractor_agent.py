import json
import logging
import os
from typing import List, Optional

from anyio import TemporaryDirectory
from pydantic import BaseModel, Field
from core.agents.agent_tools import AgentHelper, ainvoke_with_retry
from core.models.dtos.DataFlowReport import AgentDataFlowReport
from core.models.dtos.File import File

from pydantic import BaseModel

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.models.dtos.File import File
from core.models.dtos.DataFlowReport import (
    AgentDataFlowReport,
    ExternalEntity,
    Process,
    DataStore,
    TrustBoundary,
)
from trustcall import create_extractor

from tests.core.agents.test_agent_tools import agent_helper

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """\
You are a Principal Software Architect with deep expertise in designing, analyzing, and documenting distributed software systems.
You think systematically, respect architectural principles, and avoid making unfounded assumptions.
You approach this task with methodical discipline, focusing on clarity, completeness, and correctness—especially in areas of trust boundaries, 
data flows, and component responsibilities.

Mind-set & Rules
────────────────
• Never invent components, security controls, or file paths that are not literally
  present in the file text.  
• If a security detail (e.g. encryption, auth) is missing, leave the field empty and
  add a note in the component’s description such as “⚠︎ Potential Security Gap:
  encryption not mentioned”.  
"""

# • Work incrementally: the `data_flow_report` you receive is the current baseline.
#   You must **not** rewrite or duplicate its content—only emit the *delta* you find
#   in the file.
# <existing_report>
# {data_flow_report}
# </existing_report>
# •	Use the provided DataFlowReport as the foundation.
USER_PROMPT = """\
<file_metadata>
{file_metadata}
</file_metadata>


Instructions:
    1. Review the new file_metadata to:
            •	Avoid Duplication: Ensure that new additions complement, rather than duplicate, existing information.
            •	Ensure Trust Boundary Placement: Every External Entity, Process, and Data Store must be explicitly placed within a Trust Boundary.
            •   Each component, External Entity, Process, Data Store and Trust Boundary, the report must contain a detailed compoenent description field that captures the following elements:
                •   Purpose (Why it exists in the system).
                •   Functionality (What it does and how it interacts with other components).
                •   Operational Details (How it processes, stores, or transfers data).
                •   Performance Aspects (Scalability, latency, or fault tolerance mechanisms).
                •   Dependencies (APIs, microservices, or third-party integrations it interacts with).
                •   Security Considerations:
                    - **ONLY document security details that are explicitly stated in the provided data**.
                    - **Do not assume security mechanisms (e.g., encryption, authentication) unless explicitly mentioned**.
                    - **If security details are missing**, flag them as **Potential Security Gaps** and recommend best practices.
    2. Identifying External Entities:
        •   Definition: External Entities represent systems, users, services, or organizations that interact with the system but exist outside its control.
        •   Identification Criteria:
            •   Entities that provide input to or receive output from the system.
            •   Components that exist outside the system’s direct management or control.
            •   External services (e.g., third-party APIs, databases managed by external organizations, authentication providers).
            •   Human users or roles that interface with the system (e.g., Administrators, End Users, Auditors).
            •   Systems that the application communicates with but does not own (e.g., external monitoring tools, external data sources, partner integrations).
    3.  Identifying Processes:
        •   Definition: Processes represent operations or transformations that handle, manipulate, or move data within the system.
        •   Identification Criteria:
            •   Components that perform computations, validations, or transformations on data.
            •   Internal system functions that act on input data and produce output data.
            •   Automated workflows, business logic execution, and procedural operations within the system.
            •   Services or microservices that process data within the system.
    4. Identifying Data Stores:
        •   Definition: Data Stores represent repositories where data is persistently stored within the system.
        •   Identification Criteria:
            •   Databases, file systems, or cloud storage services used for storing structured or unstructured data.
            •   Caches, session stores, or logs used to maintain state or track historical actions.
            •   Internal or external repositories that interact with system processes or external entities.
            •   Data stores with distinct access controls, security policies, and retention policies.
    5. Identifying Data Flows:
        •	Definition: Data Flows represent the movement of data between External Entities, Processes, Data Stores, and Configuration Sources within the system.
            •	Identification Criteria:
            •	Any logical connection where data moves from one component to another.
            •	Interfaces between system components, whether synchronous (e.g., API calls, direct connections) or asynchronous (e.g., messaging queues, event streams).
            •	Data transfers across trust boundaries, highlighting potential security concerns.
            •	Both automated and manual data exchanges within the system.
            •	Implicit Data Exchanges: Identify data dependencies that do not involve direct data movement but still establish a data dependency, such as:
                •	Configuration and Environment Variables (e.g., .env files, system settings, API keys, environment parameters).
                •	Read-Only Data Access (e.g., a process retrieving system configurations at runtime without modifying them).
                •	Implicit Service Dependencies (e.g., a service dynamically loading credentials from a configuration manager).
                •	Static and Dynamic Data Interactions:
            •	Static Data Access: When a component retrieves values from a configuration store, secret vault, or file-based settings.
                •	Dynamic Data Transfers: When a component sends or receives structured/unstructured data in motion (e.g., network communication, database queries).
    6. Identifying Trust Boundaries:
        •   Definition: Trust Boundaries represent security perimeters that define the separation of different levels of trust within a system.
        •   Identification Criteria:
            •   Boundaries where data moves between systems with different trust levels (e.g., between an internal application and an external API).
            •   Security domains that enforce authentication, authorization, or encryption requirements.
            •   Segmentation between internal and external networks, cloud and on-premise environments, or different user roles.
            •   Points where compliance regulations require enhanced security measures.
    7. Trust Boundary Enforcement
        •	Ensure that every component (External Entity, Process, Data Store) is assigned to at least one Trust Boundary.
        •	If a component is missing from a trust boundary, identify the most relevant boundary and associate it accordingly.
        •	If a new trust boundary is needed based on the context, create and define it explicitly.
        •	Ensure that components inside a trust boundary have consistent security constraints as per their assigned boundary.

###  Tasks
1. Read the <file_metadata>.  
2. Identify any External Entities, Processes, Data Stores, Data Flows, or
   Trust Boundaries that the file *explicitly* defines or references.  
"""


# -----------------------------------------------------------------------------
# Per‑File Extraction: Light-weight component delta schema
# -----------------------------------------------------------------------------
class ComponentDelta(BaseModel):
    """Light‑weight schema for Per‑File Extraction – the architecture facts we can extract from a single file."""

    external_entities: List[ExternalEntity] = Field(default_factory=list)
    data_stores: List[DataStore] = Field(default_factory=list)
    processes: List[Process] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)


class ExtractorAgent:
    """
    Extractor class to read files and extract architecture facts using a language model.
    """

    def __init__(self, directory: TemporaryDirectory, model: BaseChatModel):
        self.directory = directory
        self.model = model

    async def extract_per_file(
        self,
        file: File,
        current_report: AgentDataFlowReport,
    ) -> Optional[ComponentDelta]:
        """
        Read a single file from disk, send it to the model, and return a
        ComponentDelta describing any architecture facts found.
        """
        absolute_path = os.path.join(self.directory, file.file_path)

        try:
            with open(absolute_path, "r", encoding="utf-8") as fp:
                content = fp.read()
        except Exception as e:
            logger.error("❌ Unable to read %s: %s", file.file_path, e)
            return None

        # Prepare LLM chain
        system_tmpl = SystemMessagePromptTemplate.from_template(SYSTEM_PROMPT)
        user_tmpl = HumanMessagePromptTemplate.from_template(
            USER_PROMPT,
        )
        prompt = ChatPromptTemplate.from_messages([system_tmpl, user_tmpl])

        chain = prompt | create_extractor(
            self.model,
            tools=[ComponentDelta],
            tool_choice="ComponentDelta",
        )

        file_metadata = {
            "filename": os.path.basename(absolute_path),
            "filepath": file.file_path,
            "content": content,
        }

        try:
            result = await ainvoke_with_retry(
                chain,
                {
                    # "data_flow_report": current_report.model_dump_json(),
                    "file_metadata": json.dumps(file_metadata, sort_keys=True),
                },
            )
            delta: ComponentDelta = result["responses"][0]
            logger.info("✅ Extracted delta from %s", file.file_path)
            return delta
        except Exception as e:
            logger.error("❌ LLM extraction failed for %s: %s", file.file_path, e)
            return None
