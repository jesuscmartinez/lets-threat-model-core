# Use a minimal base image
FROM python:3.11-slim AS base

# Set up environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/app \
    HF_HOME=/tmp/cache

WORKDIR /app

# Install system dependencies (including Git)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Create a non-root user with limited permissions
RUN groupadd -r cli_user && useradd -r -g cli_user -d /app -s /sbin/nologin cli_user

# Copy only requirements file to leverage Docker's layer caching
COPY --chown=cli_user:cli_user requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy core code to the base image
COPY core /app/core

COPY main.py /app/

# Ensure Python can locate the core module
ENV PYTHONPATH="/app/core"

USER cli_user

# Final stage to reduce image size
FROM base AS final

WORKDIR /app

COPY --from=base /app /app

USER cli_user

ENTRYPOINT ["python", "main.py"]
CMD ["-o", "threat_model_report.md"]