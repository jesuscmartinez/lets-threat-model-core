from typing import Optional
from pydantic import BaseModel, field_validator, model_validator
from uuid import UUID


# Input schema for creating
class CreateRepository(BaseModel):
    name: str
    description: str | None = None
    url: Optional[str] = None
    local_path: Optional[str] = None
    asset_id: UUID

    @model_validator(mode="after")
    def check_url_or_local_path(cls, model):
        if (model.url and model.local_path) or (not model.url and not model.local_path):
            raise ValueError("Provide either 'url' or 'local_path', but not both.")
        return model


# Output schema for returning data
class Repository(CreateRepository):
    id: UUID

    class Config:
        from_attributes = True
