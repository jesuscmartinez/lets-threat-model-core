import logging
import os
from typing import Any, TypedDict, List, Dict, Optional, Set
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import StateGraph, START, END
from tempfile import TemporaryDirectory
from langchain_core.prompts import (
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    ChatPromptTemplate,
)
from core.models.dtos.DataFlowReport import AgentDataFlowReport
from core.models.dtos.File import File
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser
import asyncio
import aiofiles
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pydantic import BaseModel, Field
import fnmatch
import json
from git import Repo as GitRepo
from core.agents.agent_tools import AgentHelper

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class Config:
    """
    Configuration class to store environment variables and runtime settings.
    """

    def __init__(
        self,
        context_window: int = 128000,
        username: Optional[str] = None,
        pat: Optional[str] = None,
        review_max_file_in_batch: int = 2,
        review_token_buffer: float = 0.5,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
        categorize_max_file_in_batch: int = 30,
        categorize_token_buffer: float = 0.5,
        completion_threshold: float = 0.3,
    ):
        # Environment variable defaults
        self.USERNAME = username
        self.PAT = pat

        self.CONTEXT_WINDOW = context_window

        # Review settings
        self.REVIEW_MAX_FILE_IN_BATCH = review_max_file_in_batch
        self.REVIEW_TOKEN_BUFFER = review_token_buffer

        # File patterns
        self.EXCLUDE_PATTERNS = exclude_patterns or [
            "**/node_modules/**",
            "*.log",
            "*.tmp",
            "test/**",
            "tests/**",
            "**/test/**",
            "**/tests/**",
            "**/__pycache__/**",
            ".DS_Store",
            "**/*.png",
            "**/*.jpg",
            "**/*.scss",
            "*.git/**",
            "*.gitignore",
            "*.dockerignore",
        ]

        self.INCLUDE_PATTERNS = include_patterns or [
            "README.md",
            "docker-compose.yml",
            "Dockerfile",
        ]

        # Categorization settings
        self.CATEGORIZE_MAX_FILE_IN_BATCH = categorize_max_file_in_batch
        self.CATEGORIZE_TOKEN_BUFFER = categorize_token_buffer

        # Completion threshold
        self.COMPLETION_THRESHOLD = completion_threshold

    def to_dict(self) -> Dict[str, Any]:
        """Returns the configuration as a dictionary for debugging or JSON export."""
        return {
            attr: getattr(self, attr) for attr in dir(self) if not attr.startswith("_")
        }

    def show_config(self):
        """Prints the configuration settings for debugging purposes."""
        for key, value in self.to_dict().items():
            print(f"{key}: {value}")


class GraphState(TypedDict):
    should_review: Set[File]
    could_review: Set[File]
    should_not_review: Set[File]
    data_flow_report: Dict
    reviewed: Set[File]
    could_not_review: Set[File]


class DataFlowAgent:
    def __init__(
        self,
        model: BaseChatModel,
        repo_url: str,
        directory: TemporaryDirectory,
        config: Config,
    ):
        self.model = model
        self.repo_url = repo_url
        self.directory = directory
        self.uuid_to_numbered_mapping = {}  # {original UUID -> "uuid_X"}
        self.numbered_to_uuid_mapping = {}  # {"uuid_X" -> original or new UUID}
        self.counter = 1  # Counter for "uuid_X" generation
        self.config = config
        self.agent_helper = AgentHelper()

    def get_report_stats(self, state: GraphState):
        """Logs the state of the DataFlowReport, including review statistics and data flow components."""

        # File review statistics
        count_should = len(state["should_review"])
        count_could = len(state["could_review"])
        count_should_not = len(state["should_not_review"])
        count_reviewed = len(state["reviewed"])
        count_could_not = len(state["could_not_review"])
        total_files = (
            count_reviewed
            + count_should
            + count_could
            + count_should_not
            + count_could_not
        )

        # DataFlow statistics
        report = AgentDataFlowReport.model_construct(
            **state.get(
                "data_flow_report", AgentDataFlowReport().model_dump(mode="json")
            )
        )

        total_external_entities = len(report.external_entities)
        total_processes = len(report.processes)
        total_data_stores = len(report.data_stores)
        total_trust_boundaries = len(report.trust_boundaries)

        # Build the log message
        log_messages = [
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

        # Log details of external entities
        for entity in report.external_entities:
            log_messages.append(
                f"🌍 External Entity: {entity['name']} - {entity['description']}"
            )

        # Log details of processes
        for process in report.processes:
            log_messages.append(
                f"🔄 Process: {process['name']} - {process['description']}"
            )

        # Log details of data stores
        for store in report.data_stores:
            log_messages.append(
                f"🗄️ Data Store: {store['name']} - {store['description']}"
            )

        # Log details of trust boundaries
        for boundary in report.trust_boundaries:
            log_messages.append(
                f"🔐 Trust Boundary: {boundary['name']} - {boundary['description']}"
            )

        # Convert list to string
        log_output = "\n".join(log_messages)

        # Return the log string
        return log_output

    def initialize(self, state: GraphState) -> GraphState:

        data_flow_report = state.get("data_flow_report")

        state["data_flow_report"] = self.agent_helper.convert_uuids_to_numbered_ids(
            data_flow_report
        )

        return state

    def clean_up(self, state: GraphState) -> GraphState:

        data_flow_report = state.get("data_flow_report")

        data_flow_report = self.agent_helper.convert_numbered_ids_to_uuids(
            data_flow_report
        )

        state["data_flow_report"] = data_flow_report

        return state

    def clone_repository(self, state: GraphState) -> GraphState:
        """Clone the repository into a temporary directory."""
        try:
            repo_url = self.repo_url
            dir = self.directory
            username = self.config.USERNAME
            pat = self.config.PAT

            logger.info(
                "🛠️ Initiating repository clone: %s → %s",
                repo_url,
                dir,
            )

            repo_url = f"https://{username}:{pat}@{repo_url}"
            repo = GitRepo.clone_from(repo_url, dir)
            branch = repo.head.reference.name
            commit = repo.head.commit.hexsha
            logger.info(
                "✅ Successfully cloned repository: %s (Branch: %s | Commit: %s)",
                repo_url,
                branch,
                commit,
            )

            return state
        except Exception as e:
            logger.error(
                "❌ Failed to clone repository %s: %s", repo_url, str(e), exc_info=True
            )
            raise e

    def rules_categorization(self, state) -> dict:
        """Categorizes files based on predefined inclusion/exclusion patterns."""

        logger.info("🔄 Starting rules based categorization of files...")
        logger.debug("Walking through the directory: %s", self.directory)

        should_review = state.setdefault("should_review", set())
        could_review = state.setdefault("could_review", set())
        should_not_review = state.setdefault("should_not_review", set())

        for root, _, files in os.walk(self.directory):
            for file in files:
                absolute_path = os.path.join(root, file)
                relative_path_str = os.path.relpath(absolute_path, self.directory)

                # Ensure EXCLUDE rules take precedence
                if any(
                    fnmatch.fnmatch(relative_path_str, pattern)
                    for pattern in self.config.EXCLUDE_PATTERNS
                ):
                    logger.debug("Excluding file: %s", relative_path_str)
                    should_not_review.add(
                        File(
                            file_path=relative_path_str,
                            justification="Matched exclude rule.",
                        )
                    )
                    continue  # Skip processing this file further

                # Check INCLUDE rules
                if any(
                    fnmatch.fnmatch(relative_path_str, pattern)
                    for pattern in self.config.INCLUDE_PATTERNS
                ):
                    logger.debug("Including file: %s", relative_path_str)
                    should_review.add(
                        File(
                            file_path=relative_path_str,
                            justification="Matched include rule.",
                        )
                    )
                    continue  # Skip processing this file further

                # ➖ Mark remaining files as "Could Review"
                if not any(f.file_path == relative_path_str for f in could_review):
                    could_review.add(
                        File(file_path=relative_path_str, justification="")
                    )
                    logger.debug("Marked file as 'Could Review': %s", relative_path_str)

        # Ensure `state` is updated before returning
        state["should_review"] = should_review
        state["could_review"] = could_review
        state["should_not_review"] = should_not_review

        logger.info("✅ Finished rules based categorization.")
        logger.info(self.get_report_stats(state))

        return state

    async def categorize_files(self, state) -> dict:
        """Categorize file into review categories."""
        logger.info("🔄 Starting file categorization process...")

        files = state.get("should_review", set()) | state.get("could_review", set())

        data_flow_report = state.get(
            "data_flow_report", AgentDataFlowReport().model_dump(mode="json")
        )

        if len(files) == 0:
            logger.info("No files to categorize.")
            return state

        class Result(BaseModel):
            should_review: Set[File] = Field(
                ..., description="List of files that must be reviewed."
            )
            could_review: Set[File] = Field(
                ..., description="List of files that are optional to review."
            )
            should_not_review: Set[File] = Field(
                ..., description="List of files that should not be reviewed."
            )

        logger.info("Categorizing %d files.", len(files))

        parser = PydanticOutputParser(pydantic_object=Result)

        system_prompt = SystemMessagePromptTemplate.from_template(
            """
        You are an intelligent assistant tasked with categorizing a list of file paths from a source code repository to aid in creating a data flow diagram. Each file path should be classified into one of the following categories based on its relevance and its relationship to the provided Data Flow Report:
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

        Format Instructions:
        {format_instructions}
        """,
            partial_variables={"format_instructions": parser.get_format_instructions()},
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

        max_context_tokens = self.config.CONTEXT_WINDOW
        max_prompt_tokens = int(
            max_context_tokens * self.config.CATEGORIZE_TOKEN_BUFFER
        ) - self.model.get_num_tokens(prompt.format(file_paths=""))

        new_state = {
            "should_review": set(),
            "could_review": set(),
            "should_not_review": set(),
        }

        async def process_batch(batch):
            if not batch:
                return None  # Avoid processing empty batches

            logger.debug("Processing batch with %d files.", len(batch))
            file_paths = [{"file_path": file_path} for file_path in batch]

            chain = prompt | self.model.with_structured_output(Result)
            try:
                result = await chain.ainvoke(
                    {
                        "file_paths": json.dumps(file_paths),
                    }
                )
                return result
            except Exception as e:
                logger.error("❌ Error processing batch: %s", e)
                return None

        async def aggregate_results(result):
            if result:  # Ensure a file is added to only one category
                for file in result.should_review:
                    # Move to should_review and ensure it's removed from other categories
                    new_state["should_review"].add(file)
                    new_state["could_review"].discard(file)
                    new_state["should_not_review"].discard(file)

                for file in result.could_review:
                    if file not in new_state["should_review"]:
                        # Move to could_review and ensure it's removed from should_not_review
                        new_state["could_review"].add(file)
                        new_state["should_not_review"].discard(file)

                for file in result.should_not_review:
                    if (
                        file not in new_state["should_review"]
                        and file not in new_state["could_review"]
                    ):
                        # Move to should_not_review only if not in other categories
                        new_state["should_not_review"].add(file)

        batch = []
        current_tokens = 0
        tasks = []

        for file in files:
            token_count = self.model.get_num_tokens(
                file.file_path
            )  # allow for the justification

            if (
                self.config.CATEGORIZE_MAX_FILE_IN_BATCH < len(batch)
                or current_tokens + token_count > max_prompt_tokens
            ):
                if batch:  # Avoid submitting empty batch
                    tasks.append(process_batch(batch))
                batch = []
                current_tokens = 0

            batch.append(file.file_path)
            current_tokens += token_count

        if batch:
            tasks.append(process_batch(batch))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error("❌ Error processing batch: %s", result)
            else:
                await aggregate_results(result)

        # Handle missing files
        all_categorized_files = (
            new_state["should_review"]
            | new_state["could_review"]
            | new_state["should_not_review"]
        )

        missing_files = files - all_categorized_files
        if missing_files:
            logger.warning(
                "⚠️ Uncategorized files detected: %d, New Could Review: %d",
                len(missing_files),
                len(new_state["could_review"]),
            )
            logger.debug(f"Uncategorized Files: {missing_files}")
            new_state["could_review"].update(missing_files)
            logger.debug("New Could Review: %d", len(new_state["could_review"]))

        # Handle fake files
        fake_files = all_categorized_files - files
        if fake_files:
            logger.warning("⚠️ Fake files detected and will be removed: %s", fake_files)
            logger.debug(
                "Fake files detected: %d, New Should Review: %d, New Could Review %d, New Should Not Review: %d",
                len(fake_files),
                len(new_state["should_review"]),
                len(new_state["could_review"]),
                len(new_state["should_not_review"]),
            )

            # Remove fake files from all categories
            new_state["should_review"].difference_update(fake_files)
            new_state["could_review"].difference_update(fake_files)
            new_state["should_not_review"].difference_update(fake_files)

            logger.debug(
                "After fake files removed. New Should Review: %d, New Could Review %d, New Should Not Review: %d",
                len(new_state["should_review"]),
                len(new_state["could_review"]),
                len(new_state["should_not_review"]),
            )

        # Update with the current state
        state["should_review"] = new_state["should_review"]
        state["could_review"] = new_state["could_review"]
        state["should_not_review"].update(new_state["should_not_review"])

        logger.info("✅ Finished file categorization.")
        logger.info(self.get_report_stats(state))

        return state

    async def review_files(self, state) -> dict:

        logger.info("🔄 Starting file review process...")

        # Ensure state is initialized properly
        files = state.get("should_review", set())
        reviewed = state.get("reviewed", set())
        could_not_review = state.get("could_not_review", set())

        parser = JsonOutputParser(pydantic_object=AgentDataFlowReport)

        system_template = SystemMessagePromptTemplate.from_template(
            """
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
                    •   Each component, External Entity, Process, Data Store, Data Flow and Trust Boundary, the report must contain a detailed compoenent description field that captures the following elements:
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
                •   Definition: Data Flows represent the movement of data between External Entities, Processes, and Data Stores within the system.
                •   Identification Criteria:
                    •   Any logical connection where data moves from one component to another.
                    •   Interfaces between system components, whether synchronous (e.g., API calls, direct connections) or asynchronous (e.g., messaging queues, event streams).
                    •   Data transfers between trust boundaries, highlighting potential security concerns.
                    •   Both automated and manual data exchanges within the system
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
        """,
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        user_template = HumanMessagePromptTemplate.from_template(
            """Data Flow Report:
        {data_flow_report}

        File Data:
        {file_data}
        """,
        )

        prompt = ChatPromptTemplate.from_messages([system_template, user_template])

        max_context_tokens = self.config.CONTEXT_WINDOW
        max_prompt_tokens = int(
            max_context_tokens * self.config.REVIEW_MAX_FILE_IN_BATCH
        ) - self.model.get_num_tokens(prompt.format(file_data="", data_flow_report=""))

        while files:

            report = state.get(
                "data_flow_report",
                AgentDataFlowReport().model_dump(mode="json"),
            )
            report_json = json.dumps(report)

            batch = []
            total_tokens_used = 0
            remaining_tokens = max_prompt_tokens - self.model.get_num_tokens(
                report_json
            )

            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=remaining_tokens // 2,
                chunk_overlap=remaining_tokens // 10,
                length_function=self.model.get_num_tokens,
            )

            files_in_batch = 0
            while (
                files
                and files_in_batch < self.config.REVIEW_MAX_FILE_IN_BATCH
                and total_tokens_used < max_prompt_tokens
            ):
                current_file = files.pop()
                relative_path = current_file.file_path
                absolute_path = os.path.join(self.directory, relative_path)

                try:
                    with open(absolute_path, "r", encoding="utf-8") as f:
                        file_content = f.read()

                    file_metadata = {
                        "filename": os.path.basename(absolute_path),
                        "filepath": relative_path,
                        "content": file_content,
                    }

                    file_metadata_json = json.dumps(file_metadata)

                    # Get the number of tokens
                    file_tokens = self.model.get_num_tokens(file_metadata_json)

                    if file_tokens >= max_prompt_tokens:
                        justification = f"File {relative_path} is too large to process in a single batch. Skipping."
                        logging.warning(f"⚠️ {justification}")
                        could_not_review.add(
                            File(file_path=relative_path, justification=justification)
                        )
                        continue

                    # Split large files dynamically
                    if file_tokens >= remaining_tokens:
                        file_chunks = text_splitter.split_text(file_metadata_json)
                    else:
                        file_chunks = [file_metadata_json]

                    for chunk in file_chunks:
                        chunk_tokens = self.model.get_num_tokens(chunk)

                        if chunk_tokens >= max_prompt_tokens:
                            justification = f"Chunk from {relative_path} is too large to process. Skipping."
                            logging.warning(f"⚠️ {justification}")
                            could_not_review.add(
                                File(
                                    file_path=relative_path, justification=justification
                                )
                            )
                            continue

                        # Stop adding more chunks when reaching the max token limit
                        if total_tokens_used + chunk_tokens >= max_prompt_tokens:
                            logging.info("Context window full, processing batch.")
                            break  # Stop adding more chunks, process the batch

                        batch.append(
                            file_metadata
                        )  # Pass the filemeta dict after calculating token usage
                        total_tokens_used += chunk_tokens

                    reviewed.add(current_file)  # Mark file as reviewed

                except Exception as e:
                    logging.error(
                        f"❌ Error reading file {relative_path}: {str(e)}",
                        exc_info=True,
                    )
                    continue
                finally:
                    # Count every file processed (even if skipped or errored) toward the batch limit.
                    files_in_batch += 1

            try:

                chain = prompt | self.model.with_structured_output(
                    schema=AgentDataFlowReport.model_json_schema()
                )

                report = chain.invoke(
                    input={
                        "file_data": json.dumps(batch),
                        "data_flow_report": report_json,
                    }
                )

                logging.info(
                    f"Processed batch successfully with {total_tokens_used} tokens."
                )

            except Exception as e:
                logging.error(f"❌ Error processing batch: {str(e)}", exc_info=True)

            state["data_flow_report"] = report
            state["reviewed"] = reviewed
            state["could_not_review"] = could_not_review
            state["should_review"] = files

            logging.info(
                "Batch completed. Remaining files will be processed in the next batch."
            )

        logger.info("✅ Finished file review process.")
        logger.info(self.get_report_stats(state))

        return state

    def done_reviewing(self, state) -> bool:
        """
        Determines whether there are more items to review based on the 80/20 rule.
        """

        # Count different categories
        count_should = len(state.get("should_review", set()))
        count_could = len(state.get("could_review", set()))
        count_reviewed = len(state.get("reviewed", set()))

        # Calculate total files considered
        total = count_reviewed + count_should + count_could

        # Prevent division by zero
        if total == 0 or count_should + count_could == 0:
            logging.info("✅ No files found in state. Defaulting to stopping review.")
            return True

        review_threshold = total * self.config.COMPLETION_THRESHOLD
        logging.debug(
            "Review Threshold (%d%% of total): %d",
            100 * self.config.COMPLETION_THRESHOLD,
            review_threshold,
        )
        logging.debug(f"Files Reviewed So Far: {count_reviewed}")

        if count_reviewed > review_threshold:
            logging.info("✅ Enough files reviewed. Stopping review process.")
            return True

        logging.info("❌ More files need review. Continuing review process.")
        return False

    def get_workflow(self):
        """Define the workflow for processing."""
        workflow = StateGraph(GraphState)

        workflow.add_node("initialize", self.initialize)
        workflow.add_node("clone_repository", self.clone_repository)
        workflow.add_node("rules_categorization", self.rules_categorization)
        workflow.add_node("review_files", self.review_files)
        workflow.add_node("categorize_filepaths", self.categorize_files)
        workflow.add_node("done_reviewing", self.done_reviewing)
        workflow.add_node("clean_up", self.clean_up)

        workflow.add_edge(START, "initialize")
        workflow.add_edge("initialize", "clone_repository")
        workflow.add_edge("clone_repository", "rules_categorization")
        workflow.add_edge("rules_categorization", "review_files")
        workflow.add_edge("review_files", "categorize_filepaths")
        workflow.add_conditional_edges(
            "categorize_filepaths",
            self.done_reviewing,
            {False: "review_files", True: "clean_up"},
        )
        workflow.add_edge("clean_up", END)

        return workflow.compile()
