import logging
from typing import Any
import uuid
from langchain.chat_models.base import BaseChatModel
from tenacity import (
    retry,
    retry_if_exception,
    wait_exponential,
    stop_after_attempt,
    before_sleep_log,
)
from langchain_core.runnables.base import Runnable
from langchain_core.runnables.utils import Input


logger = logging.getLogger(__name__)


class AgentHelper:
    """
    A helper class to convert UUIDs to numbered placeholders and vice versa in a data flow report.
    Attributes:
        uuid_to_numbered_mapping (dict): A mapping from original UUIDs to numbered placeholders.
        numbered_to_uuid_mapping (dict): A mapping from numbered placeholders to original or new UUIDs.
        counter (int): A counter for generating numbered placeholders.
    Methods:
        convert_uuids_to_ids(data_flow_report: dict) -> dict:
            Replaces all UUIDs in 'uuid', '_uuid', and '_uuids' fields with numbered placeholders ('uuid_X', 'uuid_2', etc.)
        convert_ids_to_uuids(data_flow_report: dict) -> dict:
    """

    def __init__(self):
        self.uuid_to_numbered_mapping = {}  # {original UUID -> "uuid_X"}
        self.numbered_to_uuid_mapping = {}  # {"uuid_X" -> original or new UUID}
        self.counter = 1  # Counter for "uuid_X" generation

    def convert_uuids_to_ids(self, data_flow_report: dict) -> dict:
        """
        Replaces all UUIDs in 'uuid', '_uuid', and '_uuids' fields with numbered placeholders ('uuid_1', 'uuid_2', etc.)
        and stores the mapping for restoration.
        """

        def replace_uuids(obj):
            """First pass: Replace all 'uuid' fields with 'uuid_X' values."""
            if isinstance(obj, dict):
                if "uuid" in obj and isinstance(obj["uuid"], str):
                    old_id = obj["uuid"]
                    if old_id not in self.uuid_to_numbered_mapping:
                        new_id = f"uuid_{self.counter}"
                        self.uuid_to_numbered_mapping[old_id] = new_id
                        self.numbered_to_uuid_mapping[new_id] = (
                            old_id  # Save for reverse mapping
                        )
                        self.counter += 1
                        logger.debug(f"Converted {old_id} -> {new_id}")

                    obj["uuid"] = self.uuid_to_numbered_mapping[old_id]

                for key, value in obj.items():
                    obj[key] = replace_uuids(value)

            elif isinstance(obj, list):
                obj = [replace_uuids(item) for item in obj]

            return obj

        def update_numbered_references(obj):
            if isinstance(obj, dict):
                # 1) Recurse over children first
                for key, value in list(obj.items()):
                    obj[key] = update_numbered_references(value)

                # 2) Now do the "_id" or "_ids" replacement
                for key, value in list(obj.items()):
                    if key.endswith("_uuid") and isinstance(value, str):
                        new_val = str(self.uuid_to_numbered_mapping.get(value, value))
                        obj[key] = new_val
                        logger.debug(f"Updated reference {key}: {value} -> {new_val}")

                    elif key.endswith("_uuids") and isinstance(value, list):
                        updated_list = [
                            str(self.uuid_to_numbered_mapping.get(cid, cid))
                            for cid in value
                        ]
                        logger.debug(
                            f"Updated reference list {key}: {value} -> {updated_list}"
                        )
                        obj[key] = updated_list

                return obj

            elif isinstance(obj, list):
                return [update_numbered_references(item) for item in obj]

            else:
                return obj

        logger.debug("Starting UUID to numbered ID conversion")
        logger.debug(f"Start input: {data_flow_report}")

        data_flow_report = replace_uuids(data_flow_report)
        data_flow_report = update_numbered_references(data_flow_report)

        logger.debug(f"Converted output: {data_flow_report}")
        logger.debug("Finished UUID to numbered ID conversion")
        return data_flow_report

    def convert_ids_to_uuids(self, data_flow_report: dict) -> dict:
        """
        Converts all 'uuid' placeholders (e.g., 'uuid_1') back to their original UUIDs if known.
        If the placeholder is not found in self.numbered_to_uuid_mapping, a new UUID is generated
        once and reused for any subsequent references to the same placeholder.
        """

        def get_or_create_uuid_for_placeholder(placeholder: str) -> str:
            """
            Checks if the placeholder is in numbered_to_uuid_mapping.
            If missing, generates a new UUID, stores it, and returns it.
            Ensures repeated references get the same new UUID.
            """
            if placeholder not in self.numbered_to_uuid_mapping:
                new_uuid = str(uuid.uuid4())
                self.numbered_to_uuid_mapping[placeholder] = new_uuid
                logger.debug(
                    f"Generated new UUID for missing placeholder '{placeholder}' -> {new_uuid}"
                )
            return self.numbered_to_uuid_mapping[placeholder]

        def replace_numbered_ids(obj):
            """
            First pass: Replace all literal 'uuid' fields with either known or newly generated UUIDs.
            """
            if isinstance(obj, dict):
                if "uuid" in obj and isinstance(obj["uuid"], str) and obj["uuid"]:
                    numbered_id = obj["uuid"]
                    # Get (or create) the corresponding UUID
                    original_uuid = get_or_create_uuid_for_placeholder(numbered_id)
                    obj["uuid"] = original_uuid
                    logger.debug(
                        f"Replaced 'uuid' placeholder {numbered_id} -> {original_uuid}"
                    )

                # Recurse into nested structures
                for key, value in list(obj.items()):
                    obj[key] = replace_numbered_ids(value)

            elif isinstance(obj, list):
                return [replace_numbered_ids(item) for item in obj]

            return obj

        def update_uuid_references(obj: Any):
            """
            Second pass: Update any fields ending in '_uuid' or '_uuids'
            to their corresponding UUIDs (existing or newly generated).
            """
            if isinstance(obj, dict):
                # Process '_id' fields
                for key, value in list(obj.items()):
                    if key.endswith("_uuid") and isinstance(value, str):
                        new_val = get_or_create_uuid_for_placeholder(value)
                        obj[key] = new_val
                        logger.debug(f"Updated reference {key}: {value} -> {new_val}")

                # Process '_uuids' fields
                for key, value in list(obj.items()):
                    if key.endswith("_uuids") and isinstance(value, list):
                        updated_list = [
                            get_or_create_uuid_for_placeholder(cid) for cid in value
                        ]
                        logger.debug(
                            f"Updated reference list {key}: {value} -> {updated_list}"
                        )
                        obj[key] = updated_list

                # Recurse into nested structures
                for key, value in list(obj.items()):
                    obj[key] = update_uuid_references(value)

            elif isinstance(obj, list):
                return [update_uuid_references(item) for item in obj]

            return obj

        logger.debug("Starting numbered ID to UUID conversion")
        logger.debug(f"Start input: {data_flow_report}")

        # First pass: Replace literal "id" fields
        data_flow_report = replace_numbered_ids(data_flow_report)

        # Second pass: Replace "_id" / "_ids" references
        data_flow_report = update_uuid_references(data_flow_report)

        logger.debug(f"Converted output: {data_flow_report}")
        logger.debug("Finished numbered ID to UUID conversion")

        return data_flow_report


def get_model_name(model: BaseChatModel):
    """Retrieve the model name from any BaseChatModel instance."""
    for attr in ["model_name", "model"]:
        if hasattr(model, attr):
            return getattr(model, attr)
    return "Unknown Model"


def is_rate_limit_error(exception: BaseException) -> bool:
    # Example for HTTP errors:
    if (
        hasattr(exception, "status_code")
        and getattr(exception, "status_code", None) == 429
    ):
        return True
    # OR parse error message or code if it's embedded in exception.args
    return False


# General async retry wrapper for any chain.ainvoke call
@retry(
    retry=retry_if_exception(is_rate_limit_error),
    wait=wait_exponential(multiplier=1, min=2, max=60),  # Exponential backoff
    stop=stop_after_attempt(5),  # Stop after 5 tries
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,  # Raise exception after all retries fail
)
async def ainvoke_with_retry(chain: Runnable, input: Input):
    # Optionally serialize inputs (if needed)
    # inputs = {k: json.dumps(v) for k, v in inputs.items()}  # Uncomment if your inputs need serialization

    logger.debug(f"Invoking chain with inputs: {input}")
    return await chain.ainvoke(input)


@retry(
    retry=retry_if_exception(is_rate_limit_error),
    wait=wait_exponential(multiplier=1, min=2, max=60),  # Exponential backoff
    stop=stop_after_attempt(5),  # Stop after 5 attempts
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,  # Raise the exception if it keeps failing
)
def invoke_with_retry(chain: Runnable, input: Input):
    """
    Wrapper function to retry chain.invoke() on rate limit (HTTP 429) errors.
    """
    logger.debug(f"Invoking chain synchronously with inputs: {input}")
    return chain.invoke(input)
