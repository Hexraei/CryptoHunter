# CryptoHunter - Complete Production Dockerfile
# Full Analysis Pipeline with all tools
#
# Build: docker build -t cryptohunter .
# Run:   docker-compose up

FROM python:3.11-slim

LABEL maintainer="Team IRIZ"
LABEL version="2.0.0"
LABEL description="AI/ML Cryptographic Primitive Detection - Full Pipeline"

WORKDIR /app

# ================================================================
# System Dependencies
# ================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Java for Ghidra
    openjdk-17-jdk-headless \
    # Build tools
    build-essential \
    git \
    wget \
    curl \
    unzip \
    cmake \
    # binwalk dependencies
    mtd-utils \
    gzip \
    bzip2 \
    tar \
    arj \
    lhasa \
    p7zip \
    p7zip-full \
    cabextract \
    squashfs-tools \
    sleuthkit \
    lzop \
    srecord \
    zstd \
    lz4 \
    # unblob dependencies
    e2fsprogs \
    # File analysis
    file \
    # PostgreSQL client
    libpq-dev \
    # For angr/Z3
    libffi-dev \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# ================================================================
# Install binwalk from source (latest with all plugins)
# ================================================================
RUN git clone https://github.com/ReFirmLabs/binwalk.git /tmp/binwalk \
    && cd /tmp/binwalk \
    && pip install . \
    && cd / && rm -rf /tmp/binwalk

# Install sasquatch for SquashFS variants
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && ./build.sh || true \
    && cd / && rm -rf /tmp/sasquatch

# ================================================================
# Install unblob (advanced firmware extractor)
# ================================================================
RUN pip install --no-cache-dir unblob

# ================================================================
# Download and Install Ghidra
# ================================================================
ENV GHIDRA_VERSION=11.0
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && chmod +x /opt/ghidra/support/analyzeHeadless

ENV GHIDRA_PATH=/opt/ghidra
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# ================================================================
# Python Dependencies - Core
# ================================================================
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ================================================================
# Python Dependencies - Analysis Tools
# ================================================================
RUN pip install --no-cache-dir \
    # Graph Neural Networks
    torch --index-url https://download.pytorch.org/whl/cpu \
    torch-geometric \
    # Machine Learning
    xgboost \
    scikit-learn \
    numpy \
    # Graph Analysis
    networkx \
    # Symbolic Execution
    angr \
    # Celery for distributed tasks
    celery[redis] \
    # Database
    sqlalchemy \
    asyncpg \
    psycopg2-binary \
    # Redis client
    redis \
    # Export formats
    openpyxl \
    reportlab \
    # Utilities
    requests \
    tqdm \
    aiofiles \
    python-multipart

# ================================================================
# Copy Application Code
# ================================================================
COPY src/ ./src/
COPY models/ ./models/
COPY scripts/ ./scripts/

# Create directories
RUN mkdir -p uploads results ghidra_projects /tmp/crypto_analysis

# ================================================================
# Environment Variables
# ================================================================
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/src
ENV GHIDRA_PATH=/opt/ghidra
ENV MODEL_PATH=/app/models/sota_crypto_model.pt
ENV UPLOAD_DIR=/app/uploads
ENV RESULTS_DIR=/app/results

# Celery settings
ENV CELERY_BROKER_URL=amqp://guest:guest@rabbitmq:5672//
ENV CELERY_RESULT_BACKEND=redis://redis:6379/1

# Database
ENV DATABASE_URL=postgresql://crypto:crypto123@postgres:5432/cryptohunter

# ================================================================
# Expose Port
# ================================================================
EXPOSE 8000

# ================================================================
# Health Check
# ================================================================
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# ================================================================
# Run Application
# ================================================================
CMD ["python", "src/standalone.py"]
