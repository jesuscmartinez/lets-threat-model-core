from typing import List
from pydantic import BaseModel, Field


class RepoDataFlowAgentConfig(BaseModel):
    """
    Configuration class to store runtime settings.
    Uses Pydantic for validation, default values, and serialization.
    """

    context_window: int = Field(
        default=128000, description="Maximum context window size"
    )
    max_output_tokens: int = Field(
        default=16384, description="Maximum number of output tokens"
    )

    # Review settings
    review_max_file_in_batch: int = Field(
        default=3, description="Max files per batch in review"
    )
    review_token_buffer: float = Field(
        default=0.5, description="Buffer percentage for review tokens"
    )

    # File patterns
    exclude_patterns: List[str] = Field(
        default_factory=lambda: [
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
            "*.gitmodules",
            "*.gitattributes",
            "*.gitkeep",
            "venv/**",
            ".venv/**",
            ".vscode/**",
            ".idea/**",
        ],
        description="Patterns to exclude from processing",
    )
    include_patterns: List[str] = Field(
        default_factory=lambda: [
            "README.md",
            "docker-compose.yml",
            "swagger.yml",
            "Dockerfile",
        ],
        description="Patterns to include in processing",
    )

    # Categorization settings
    categorize_max_file_in_batch: int = Field(
        default=30, description="Max files per batch for categorization"
    )
    categorize_token_buffer: float = Field(
        default=0.5, description="Buffer percentage for categorization tokens"
    )
    categorize_only: bool = Field(
        default=False, description="If True, only categorization is performed"
    )

    # Completion threshold
    completion_threshold: float = Field(
        default=0.8, description="Threshold to determine review completion"
    )

    def add_exclude_patterns(self, patterns: List[str]):
        """Appends new patterns to the exclude list, avoiding duplicates."""
        self.exclude_patterns.extend(
            p for p in patterns if p not in self.exclude_patterns
        )

    def to_dict(self) -> dict:
        """Returns the configuration as a dictionary."""
        return self.model_dump()

    def show_config(self):
        """Prints the configuration settings for debugging purposes."""
        print(self.model_dump_json(indent=2))
