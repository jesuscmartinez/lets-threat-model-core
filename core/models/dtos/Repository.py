from typing import Optional
from pydantic import BaseModel, Field, model_validator
from uuid import UUID, uuid4


# Output schema for returning data
class Repository(BaseModel):
    uuid: UUID = Field(
        default_factory=uuid4, description="Unique identifier for the repository"
    )
    name: str = Field(default="", description="Name of the repository")
    description: str | None = Field(
        default=None, description="Detailed description of the repository"
    )
    url: Optional[str] = Field(default=None, description="Remote URL of the repository")
    local_path: Optional[str] = Field(
        default=None, description="Local filesystem path of the repository"
    )
    asset_uuid: UUID = Field(..., description="Identifier of the associated asset")

    @model_validator(mode="after")
    def check_url_or_local_path(cls, model):
        if (model.url and model.local_path) or (not model.url and not model.local_path):
            raise ValueError("Provide either 'url' or 'local_path', but not both.")
        return model

    class Config:
        from_attributes = True
