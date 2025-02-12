from pydantic import BaseModel, Field


class File(BaseModel):
    file_path: str = Field(..., description="Path to the file.")
    justification: str = Field(..., description="Brief reason for the categorization.")

    def __hash__(self):
        return hash(self.file_path)  # Hash based on file path

    def __eq__(self, other):
        return isinstance(other, File) and self.file_path == other.file_path
