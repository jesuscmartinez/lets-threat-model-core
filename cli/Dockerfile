# Use a minimal base image
FROM python:3.11-slim AS base

# Set up environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/app

WORKDIR /app

# Create a non-root user with limited permissions
RUN groupadd -r cli_user && useradd -r -g cli_user -d /app -s /sbin/nologin cli_user

# Copy only requirements file to leverage Docker's layer caching
COPY --chown=cli_user:cli_user cli/requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy shared code to the base image
COPY core /app/core

COPY cli/. /app/

# Ensure Python can locate the shared module
ENV PYTHONPATH="/app/core"

USER cli_user

# Final stage to reduce image size
FROM base AS final

WORKDIR /app

COPY --from=base /app /app

USER cli_user