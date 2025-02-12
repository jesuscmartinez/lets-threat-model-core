from pydantic import BaseModel
from uuid import UUID


# Input schema for creating
class CreateRepository(BaseModel):
    name: str
    description: str | None = None
    url: str
    asset_id: UUID


# Output schema for returning data
class Repository(CreateRepository):
    id: UUID

    class Config:
        from_attributes = True
