from pydantic import BaseModel
from uuid import UUID
from typing import Optional, Any


# Input schema for creating an Asset
class GenerateThreatModelCreate(BaseModel):
    asset_uuid: UUID

    class Config:
        from_attributes = True


class TaskRead(BaseModel):
    task_uuid: UUID  # Unique ID for the task
    status: str  # Task status: PENDING, STARTED, SUCCESS, FAILURE, etc.
    result: Optional[Any] = None  # Task result if available (None until successful)
    error: Optional[str] = None  # Error message if the task failed
