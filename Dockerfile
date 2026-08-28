FROM python:3.12-slim AS base

# Install patched runtime dependencies for Scapy + libpcap
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libpcap0.8t64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first (layer cache)
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p logs data models

# Expose dashboard port
EXPOSE 5000

# Default: run dashboard
CMD ["python", "dashboard.py"]
