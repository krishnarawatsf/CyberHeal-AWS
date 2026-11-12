FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CYBERHEAL_OPA_EXE=/usr/local/bin/opa \
    PYTHONPATH=/app/src

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install official OPA binary matching system architecture (arm64 or amd64)
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        curl -fsSL https://openpolicyagent.org/downloads/v1.22.2/opa_linux_arm64_static -o /usr/local/bin/opa; \
    else \
        curl -fsSL https://openpolicyagent.org/downloads/v1.22.2/opa_linux_amd64_static -o /usr/local/bin/opa; \
    fi && \
    chmod 0755 /usr/local/bin/opa && \
    opa version

# Install Python requirements
COPY requirements.txt requirements-member-b.txt requirements-member-c.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-member-b.txt -r requirements-member-c.txt

# Copy project files
COPY pyproject.toml ./
COPY src ./src
COPY tests ./tests
COPY respond ./respond
COPY config ./config
COPY observability ./observability
COPY scripts ./scripts

# Ensure scripts are executable
RUN chmod +x scripts/*.sh scripts/*.py

# Create work directory with write permissions
RUN mkdir -p /app/work && chmod -R 777 /app/work

EXPOSE 8080 8000

# Default command: launch the interactive dashboard
CMD ["python", "scripts/run_dashboard.py", "--host", "0.0.0.0", "--port", "8080"]
