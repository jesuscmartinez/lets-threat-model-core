from pydantic import BaseModel, Field
from uuid import UUID, uuid4
from core.models.enums import AuthnType, DataClassification


class Asset(BaseModel):
    uuid: UUID = Field(
        default_factory=uuid4, description="Unique identifier for the asset"
    )
    name: str = Field(default="", description="Name of the asset")
    description: str | None = Field(
        default=None, description="Detailed description of the asset"
    )
    internet_facing: bool = Field(
        default=False, description="Whether the asset is internet-facing"
    )
    authn_type: AuthnType = Field(
        default=AuthnType.NONE, description="Type of authentication used by the asset"
    )
    data_classification: DataClassification = Field(
        default=DataClassification.PUBLIC,
        description="Data classification level of the asset",
    )

    class Config:
        from_attributes = True
