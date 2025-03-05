import logging
import os
import asyncio
import fnmatch
import json

from typing import Optional, Set, List, Dict, Any
import re

from pydantic import BaseModel, Field, SecretStr
from git import Repo as GitRepo
from tempfile import TemporaryDirectory

# LangChain and local imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.prompts import (
    AIMessagePromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from langchain_core.output_parsers import JsonOutputParser
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langgraph.graph import StateGraph, START, END
from core.agents.agent_tools import AgentHelper, is_o1
from core.agents.chat_model_manager import ChatModelManager
from core.agents.repo_data_flow_agent_config import RepoDataFlowAgentConfig
from core.models.dtos.File import File
from core.models.dtos.DataFlowReport import AgentDataFlowReport

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Pydantic model for Graph State
# -----------------------------------------------------------------------------
class GraphStateModel(BaseModel):
    """Holds the state of our data flow analysis."""

    should_review: Set[File] = Field(default_factory=set)
    could_review: Set[File] = Field(default_factory=set)
    should_not_review: Set[File] = Field(default_factory=set)
    data_flow_report: Dict[str, Any] = Field(default_factory=dict)
    reviewed: Set[File] = Field(default_factory=set)
    could_not_review: Set[File] = Field(default_factory=set)


# -----------------------------------------------------------------------------
# Large Prompt Texts (store them in constants or in separate files)
# -----------------------------------------------------------------------------
SYSTEM_PROMPT_CATEGORIZATION = """\
You are an Principal Software Architect tasked with categorizing a provided list of file paths from a source code repository to aid in creating a data flow diagram. Each file path should be classified into one of the following categories based on its relevance and its relationship to the provided Data Flow Report:

1.	Should Review: Files that are highly relevant and likely contain critical information about external entities, processes, data stores and data flows directly involved in the system’s functionality. This includes the repository’s main README.md file, which often provides an overview of the project’s architecture and setup.
2.	Could Review: Files that may provide supplementary or contextual information about the codebase but are not critical for constructing the data flow diagram. These files can be reviewed if time permits.
3.	Should Not Review: Files that are unlikely to contain relevant information for the data flow diagram, such as auxiliary or unrelated files.

Categorization Criteria:
    •	Relevance to Data flow: Does the file path point to source code, configurations, or documentation related to data sources (e.g., database connections, API integrations), transformations (e.g., middleware, data processing logic), or data destinations (e.g., output files, APIs)? Or does the file path point to information related to the components in the Data Flow Report?
    •	README Inclusion: Always include the main README.md file under Should Review if present at the root level or in a relevant directory.
    •	File Type and Content:
        •	Source code files (e.g., .py, .js, .java) and configuration files (e.g., .env, .yml, .json) should typically be categorized as Should Review if they correspond to components referenced in the Data Flow Report.
        •	Documentation files beyond README.md (e.g., other .md or .txt files) may fall under Could Review depending on their content and how they relate to the Data Flow Report.
        •	Test files, static assets, and auto-generated files are typically Should Not Review.
    •	File Path Structure: The file’s location in the repository hierarchy (e.g., src/, config/, docs/) may provide clues about its relevance. For example:
        •	Files in src/ or config/ directories that are referenced in the Data Flow Report are more likely to be Should Review.
        •	Files in tests/ or assets/ are more likely to be Should Not Review unless explicitly referenced in the Data Flow Report.
    •	Contextual Importance: Does the file provide indirect support for understanding the system’s data flow or architecture (e.g., diagrams, high-level overviews)? Prioritize files that align with the entities and flows in the Data Flow Report.
    •	Redundancy: Mark files as Should Not Review that duplicate information already available in higher-priority files.

Categorization Process (To Avoid Hallucination)
    1.	Only use the provided file list and do not infer missing files.
    2.	Check if a file directly aligns with entities or processes in the Data Flow Report.
    3.	Categorize conservatively—if uncertain, classify as Could Review instead of assuming importance.
    4.	Do not create or assume extra files that are not in the input list.

Examples of Categorization:
    •	Should Review:
        •	README.md (main or highly relevant README files).
        •	src/main.py
        •	config/database.yml
        •	schemas/schema.sql
    •	Could Review:
        •	docs/architecture.md
        •	diagrams/dataflow.png
        •	notes/development_log.txt
    •	Should Not Review:
        •	tests/test_main.py
        •	static/styles.css
        •	node_modules/package.json
        •	README.md inside unrelated directories (e.g., node_modules/).
"""

SYSTEM_PROMPT_REVIEW = """\
You are an expert Principal Software Architect with extensive experience in designing, analyzing, and documenting software systems. Your task is to Generate or Update a detailed Data Flow Report by analyzing the provided File Data and enhancing the existing Data Flow Report. This updated report will serve as a foundation for understanding and evolving the system architecture.

Instructions:
    1.	Incremental Enhancement:
        •	Use the provided DataFlowReport as the foundation.
        •	Review the new context to:
            •	Add: Incorporate new external entities, processes, data flows, data stores, or trust boundaries identified in the context.
            •	Update: Enhance existing components in the report with additional details or clarifications from the context.
            •	Retain: Preserve any existing information in the report that is not explicitly contradicted or invalidated by the context.
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
    8.	Dynamic Integration:
        •	Compare the context and the existing DataFlowReport to determine:
            •	What new information should be added.
            •	What existing information should be clarified or expanded.
            •	Maintain coherence and continuity in the report by integrating new details seamlessly.

Format Instructions:
{format_instructions}
"""


# -----------------------------------------------------------------------------
# DataFlowAgent
# -----------------------------------------------------------------------------
class DataFlowAgent:
    def __init__(
        self,
        repo_url: str,
        directory: TemporaryDirectory,
        username: str,
        password: SecretStr,
        categorization_model: BaseChatModel,
        review_model: BaseChatModel,
        config: RepoDataFlowAgentConfig,
    ):
        self.categorize_model = categorization_model
        self.review_model = review_model
        self.repo_url = repo_url
        self.directory = directory
        self.agent_helper = AgentHelper()
        self.username = username
        self.password = password
        self.config = config
        # For ID conversions
        self.uuid_to_numbered_mapping = {}
        self.numbered_to_uuid_mapping = {}
        self.counter = 1

    # -------------------------------------------------------------------------
    # State Reporting
    # -------------------------------------------------------------------------
    def get_report_stats(self, state: GraphStateModel) -> str:
        """Return a string summarizing the DataFlowReport and file categorization counts."""

        # File review statistics
        count_should = len(state.should_review)
        count_could = len(state.could_review)
        count_should_not = len(state.should_not_review)
        count_reviewed = len(state.reviewed)
        count_could_not = len(state.could_not_review)
        total_files = (
            count_reviewed
            + count_should
            + count_could
            + count_should_not
            + count_could_not
        )

        # DataFlow statistics
        report = state.data_flow_report
        total_external_entities = len(report.get("external_entities", []))
        total_processes = len(report.get("processes", []))
        total_data_stores = len(report.get("data_stores", []))
        total_trust_boundaries = len(report.get("trust_boundaries", []))

        lines = [
            "📊 Data Flow Report Summary:",
            f"  🔹 Total Files: {total_files}",
            f"  ✅ Reviewed: {count_reviewed}",
            f"  ⚠️ Should Review: {count_should}",
            f"  🔍 Could Review: {count_could}",
            f"  🚫 Should Not Review: {count_should_not}",
            f"  ❌ Could Not Review: {count_could_not}\n",
            "📡 Data Flow Overview:",
            f"  🌎 External Entities: {total_external_entities}",
            f"  🔄 Processes: {total_processes}",
            f"  🗄️ Data Stores: {total_data_stores}",
            f"  🔐 Trust Boundaries: {total_trust_boundaries}\n",
        ]

        # External Entities
        for entity in report.get("external_entities", []):
            lines.append(
                f"🌍 External Entity: {entity['name']} - {entity['description']}"
            )
        # Processes
        for process in report.get("processes", []):
            lines.append(f"🔄 Process: {process['name']} - {process['description']}")
        # Data Stores
        for store in report.get("data_stores", []):
            lines.append(f"�️ Data Store: {store['name']} - {store['description']}")
        # Trust Boundaries
        for boundary in report.get("trust_boundaries", []):
            lines.append(
                f"� Trust Boundary: {boundary['name']} - {boundary['description']}"
            )

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Workflow Steps
    # -------------------------------------------------------------------------
    def initialize(self, state: GraphStateModel) -> GraphStateModel:
        """Prepare state before we start the rest of the workflow."""
        data_flow_report = state.data_flow_report
        updated = self.agent_helper.convert_uuids_to_ids(data_flow_report)
        state.data_flow_report = updated
        return state

    def clean_up(self, state: GraphStateModel) -> GraphStateModel:
        """Convert IDs back to original UUID style at end of workflow."""
        converted = self.agent_helper.convert_ids_to_uuids(state.data_flow_report)
        state.data_flow_report = converted
        return state

    def clone_repository(self, state: GraphStateModel) -> GraphStateModel:
        """Clone the repository into a temporary directory."""
        try:
            repo_url = self.repo_url
            username = self.username
            pat = self.password

            logger.info(
                "🛠️ Initiating repository clone: %s → %s",
                repo_url,
                self.directory,
            )

            repo_url = f"https://{username}:{pat}@{repo_url}"
            repo = GitRepo.clone_from(repo_url, self.directory)
            branch = repo.head.reference.name
            commit = repo.head.commit.hexsha
            logger.info(
                "✅ Successfully cloned repository: %s (Branch: %s | Commit: %s)",
                repo_url,
                branch,
                commit,
            )
        except Exception as e:
            logger.error(
                "❌ Failed to clone repository %s: %s",
                self.repo_url,
                str(e),
                exc_info=True,
            )
            raise e
        return state

    def rules_categorization(self, state: GraphStateModel) -> GraphStateModel:
        """Categorize files based on config-based inclusion/exclusion patterns."""
        logger.info("🔄 Starting rules-based categorization of files...")

        for root, _, files in os.walk(self.directory):
            for filename in files:
                absolute_path = os.path.join(root, filename)
                relative_path_str = os.path.relpath(absolute_path, self.directory)

                # Exclusion check
                if any(
                    fnmatch.fnmatch(relative_path_str, pattern)
                    for pattern in self.config.exclude_patterns
                ):
                    state.should_not_review.add(
                        File(
                            file_path=relative_path_str,
                            justification="Matched exclude rule.",
                        )
                    )
                    continue

                # Inclusion check
                if any(
                    fnmatch.fnmatch(relative_path_str, pattern)
                    for pattern in self.config.include_patterns
                ):
                    state.should_review.add(
                        File(
                            file_path=relative_path_str,
                            justification="Matched include rule.",
                        )
                    )
                    continue

                # Default to 'could_review'
                if not any(
                    f.file_path == relative_path_str for f in state.could_review
                ):
                    state.could_review.add(
                        File(file_path=relative_path_str, justification="")
                    )

        logger.info("✅ Finished rules based categorization.")
        logger.info(self.get_report_stats(state))
        return state

    async def categorize_files(self, state: GraphStateModel) -> GraphStateModel:
        """
        Use the categorization language model to refine which files:
          - Should Review
          - Could Review
          - Should Not Review
        """

        logger.info("🔄 Starting file categorization process with LLM...")

        # Consolidate 'should_review' + 'could_review' to feed to LLM
        files_to_categorize = state.should_review | state.could_review
        data_flow_report = state.data_flow_report

        if not files_to_categorize:
            logger.info("No files to categorize.")
            return state

        logger.info("Categorizing %d files via LLM rules...", len(files_to_categorize))

        # Prepare system & user prompts
        system_prompt = SystemMessagePromptTemplate.from_template(
            SYSTEM_PROMPT_CATEGORIZATION
        )
        user_prompt = HumanMessagePromptTemplate.from_template(
            """
            Data Flow Report:
            {data_flow_report}

            File Paths:
            {file_paths}
            """,
            partial_variables={"data_flow_report": json.dumps(data_flow_report)},
        )
        prompt = ChatPromptTemplate.from_messages([system_prompt, user_prompt])

        # We'll parse the LLM output into these fields
        class CategorizationResult(BaseModel):
            should_review: List[File]
            could_review: List[File]
            should_not_review: List[File]

        chain = prompt | self.categorize_model.with_structured_output(
            CategorizationResult
        )

        # Helper function to process a batch of file paths
        async def _batch_categorize_files(batch: List[str]) -> CategorizationResult:
            if not batch:
                return CategorizationResult(
                    should_review=[], could_review=[], should_not_review=[]
                )
            file_data = [{"file_path": fp} for fp in batch]
            result = await chain.ainvoke({"file_paths": json.dumps(file_data)})
            return result

        # We'll store the final results here before merging with 'state'
        new_state_sets = {
            "should_review": set(),
            "could_review": set(),
            "should_not_review": set(),
        }

        # Helper to merge LLM results into new_state_sets
        def _merge_categorization_results(result: CategorizationResult):
            # Add "Should Review" items
            for f in result.should_review:
                new_state_sets["should_review"].add(f)
                new_state_sets["could_review"].discard(f)
                new_state_sets["should_not_review"].discard(f)

            # Add "Could Review"
            for f in result.could_review:
                if f not in new_state_sets["should_review"]:
                    new_state_sets["could_review"].add(f)
                    new_state_sets["should_not_review"].discard(f)

            # Add "Should Not Review"
            for f in result.should_not_review:
                if (
                    f not in new_state_sets["should_review"]
                    and f not in new_state_sets["could_review"]
                ):
                    new_state_sets["should_not_review"].add(f)

        # Simple batching logic
        files_list = list(files_to_categorize)
        files_list.sort(key=lambda x: x.file_path)
        current_batch = []
        current_token_count = 0
        max_tokens = (
            self.config.context_window
            - self.config.max_output_tokens
            - self.categorize_model.get_num_tokens(
                prompt.format(file_paths="", data_flow_report="")
            )
        )

        tasks = []
        for fobj in files_list:
            path = fobj.file_path
            path_token_count = self.categorize_model.get_num_tokens(path)
            # If adding this file to current batch exceeds limit, push batch
            if (len(current_batch) >= self.config.categorize_max_file_in_batch) or (
                current_token_count + path_token_count > max_tokens
            ):
                tasks.append(_batch_categorize_files(current_batch))
                current_batch = []
                current_token_count = 0

            current_batch.append(path)
            current_token_count += path_token_count

        # Last batch if any
        if current_batch:
            tasks.append(_batch_categorize_files(current_batch))

        # Await all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error("❌ Error from categorization batch: %s", r)
                continue
            _merge_categorization_results(r)

        # Handle any uncategorized or fake files
        categorized_all = (
            new_state_sets["should_review"]
            | new_state_sets["could_review"]
            | new_state_sets["should_not_review"]
        )
        missing_files = files_to_categorize - categorized_all
        if missing_files:
            logger.warning(
                "⚠️ Some files not categorized. Marking them as 'Could Review'."
            )
            new_state_sets["could_review"].update(missing_files)

        # If the LLM invented files not in our original set, remove them
        fake_files = categorized_all - files_to_categorize
        if fake_files:
            logger.warning(
                "⚠️ The LLM produced files not in the original set. Removing them."
            )
            for cat in new_state_sets:
                new_state_sets[cat] = new_state_sets[cat] - fake_files

        # Merge final sets back into main state
        state.should_review = new_state_sets["should_review"]
        state.could_review = new_state_sets["could_review"]
        state.should_not_review.update(new_state_sets["should_not_review"])

        logger.info("✅ Finished file categorization via LLM.")
        logger.info(self.get_report_stats(state))
        return state

    def review_files(self, state: GraphStateModel) -> GraphStateModel:
        """
        Reviews files in `should_review`, updates the data_flow_report accordingly.
        """

        logger.info("🔄 Starting file review process with LLM...")

        files_to_review = state.should_review
        reviewed = state.reviewed
        could_not_review = state.could_not_review

        # Prepare the system prompt
        parser = JsonOutputParser(pydantic_object=AgentDataFlowReport)
        format_instructions = parser.get_format_instructions()

        if is_o1(self.review_model):
            system_template = AIMessagePromptTemplate.from_template(
                SYSTEM_PROMPT_REVIEW,
                partial_variables={"format_instructions": format_instructions},
            )
        else:
            system_template = SystemMessagePromptTemplate.from_template(
                SYSTEM_PROMPT_REVIEW,
                partial_variables={"format_instructions": format_instructions},
            )

        user_template = HumanMessagePromptTemplate.from_template(
            """
            Data Flow Report:
            {data_flow_report}

            File Data:
            {file_data}
            """
        )

        prompt = ChatPromptTemplate.from_messages([system_template, user_template])

        # For structured output
        chain = prompt | self.review_model.with_structured_output(
            schema=AgentDataFlowReport.model_json_schema()
        )

        # If we have an O1 model, we'll adapt the chain logic
        if is_o1(self.review_model):
            chain = prompt | self.review_model  # We'll parse after

        max_prompt_tokens = (
            self.config.context_window
            - self.config.max_output_tokens
            - self.review_model.get_num_tokens(
                prompt.format(file_data="", data_flow_report="")
            )
        )

        # Helper to chunk file content
        def _split_file_content(content: str, max_tokens: int) -> List[str]:
            splitter = RecursiveCharacterTextSplitter(
                chunk_size=max_tokens // 2,
                chunk_overlap=max_tokens // 10,
                length_function=self.review_model.get_num_tokens,
            )
            return splitter.split_text(content)

        number_of_files = len(files_to_review)
        processed_count = 0

        # We'll process until no more files in should_review
        while files_to_review:
            report_json = json.dumps(state.data_flow_report)
            report_token_count = self.review_model.get_num_tokens(report_json)

            # We'll collect multiple files for a single LLM call
            batch_files = []
            total_tokens_used = 0
            remaining_tokens = max_prompt_tokens - report_token_count
            files_in_batch = 0

            # Pop from the set to build a batch
            pop_list = []
            for fobj in files_to_review:
                absolute_path = os.path.join(self.directory, fobj.file_path)
                try:
                    with open(absolute_path, "r", encoding="utf-8") as fp:
                        file_content = fp.read()
                except Exception as e:
                    logger.error("❌ Error reading file %s: %s", fobj.file_path, str(e))
                    pop_list.append(fobj)
                    continue

                file_metadata = {
                    "filename": os.path.basename(absolute_path),
                    "filepath": fobj.file_path,
                    "content": file_content,
                }
                file_metadata_json = json.dumps(file_metadata)
                file_tokens = self.review_model.get_num_tokens(file_metadata_json)

                if file_tokens >= max_prompt_tokens:
                    # File is too large for even a single chunk under current settings
                    justification = (
                        f"File {fobj.file_path} is too large to process in one pass."
                    )
                    logger.warning("⚠️ " + justification)
                    could_not_review.add(
                        File(file_path=fobj.file_path, justification=justification)
                    )
                    pop_list.append(fobj)
                    continue

                # If it doesn't fit in the remaining context, let's chunk it
                if file_tokens >= remaining_tokens:
                    # Attempt chunking
                    chunks = _split_file_content(file_metadata_json, remaining_tokens)
                    for ch in chunks:
                        chunk_tokens = self.review_model.get_num_tokens(ch)
                        if total_tokens_used + chunk_tokens > remaining_tokens:
                            # No more room in this batch
                            break
                        batch_files.append(json.loads(ch))  # store as dict
                        total_tokens_used += chunk_tokens
                    pop_list.append(fobj)
                    reviewed.add(fobj)
                    files_in_batch += 1
                else:
                    # Enough space to add the entire file
                    batch_files.append(file_metadata)
                    total_tokens_used += file_tokens
                    pop_list.append(fobj)
                    reviewed.add(fobj)
                    files_in_batch += 1

                # Check if we hit batch limits
                if files_in_batch >= self.config.review_max_file_in_batch:
                    break

            # Remove from the original set
            for fobj in pop_list:
                files_to_review.remove(fobj)

            if not batch_files:
                # Possibly no files or all were too large.
                continue

            # Invoke the chain
            try:
                llm_result = chain.invoke(
                    {
                        "file_data": json.dumps(batch_files),
                        "data_flow_report": report_json,
                    }
                )
                processed_count += files_in_batch
                logger.info(
                    "Processed %d/%d files successfully.",
                    processed_count,
                    number_of_files,
                )

                # If is O1, parse after the fact
                if is_o1(self.review_model):
                    cleaned_content = re.sub(
                        r"```json|```", "", llm_result.content
                    ).strip()
                    llm_result = json.loads(cleaned_content)

                # Merge into the existing data_flow_report
                state.data_flow_report = llm_result

            except Exception as e:
                logger.error("❌ Error processing batch: %s", e, exc_info=True)

        # Update final sets
        state.reviewed = reviewed
        state.could_not_review = could_not_review
        state.should_review = files_to_review

        logger.info("✅ Finished file review process.")
        logger.info(self.get_report_stats(state))
        return state

    def categorize_only(self, state) -> bool:
        return self.config.categorize_only

    def done_reviewing(self, state: GraphStateModel) -> bool:
        """
        Determine if we've reviewed enough files based on COMPLETION_THRESHOLD
        and total file counts.
        """
        if self.config.categorize_only:
            return True

        count_should = len(state.should_review)
        count_could = len(state.could_review)
        count_reviewed = len(state.reviewed)
        total = count_reviewed + count_should + count_could

        if total == 0 or (count_should + count_could) == 0:
            logger.info("✅ No files found in state. Stopping review.")
            return True

        review_threshold = int(total * self.config.completion_threshold)
        if count_reviewed > review_threshold:
            logger.info("✅ Enough files reviewed. Stopping review process.")
            return True

        logger.info("❌ More files need review. Continuing.")
        return False

    # -------------------------------------------------------------------------
    # Build StateGraph Workflow
    # -------------------------------------------------------------------------
    def get_workflow(self):
        """
        Build the pipeline of states from start to finish.
        """
        workflow = StateGraph(GraphStateModel)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("clone_repository", self.clone_repository)
        workflow.add_node("rules_categorization", self.rules_categorization)
        workflow.add_node("categorize_only", self.categorize_only)
        workflow.add_node("review_files", self.review_files)
        workflow.add_node("categorize_filepaths", self.categorize_files)
        workflow.add_node("done_reviewing", self.done_reviewing)
        workflow.add_node("clean_up", self.clean_up)

        # Edges
        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "clone_repository")
        workflow.add_edge("clone_repository", "rules_categorization")

        # If we only want categorization, jump straight to "categorize_filepaths"
        # Otherwise, go into "review_files".
        workflow.add_conditional_edges(
            "rules_categorization",
            self.categorize_only,
            {
                True: "categorize_filepaths",
                False: "review_files",
            },
        )

        workflow.add_edge("review_files", "categorize_filepaths")
        workflow.add_conditional_edges(
            "categorize_filepaths",
            self.done_reviewing,
            {
                False: "review_files",
                True: "clean_up",
            },
        )
        workflow.add_edge("clean_up", END)

        return workflow.compile()
