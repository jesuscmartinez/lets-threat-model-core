from pydantic import BaseModel
from uuid import UUID
from core.models.enums import AuthnType, DataClassification


# Input schema for creating an Asset
class CreateAsset(BaseModel):
    name: str
    description: str | None = None
    internet_facing: bool
    authn_type: AuthnType
    data_classification: DataClassification


# Output schema for returning Asset data
class Asset(CreateAsset):
    id: UUID

    class Config:
        from_attributes = True
