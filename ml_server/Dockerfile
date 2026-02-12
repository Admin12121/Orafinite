# Orafinite ML Sidecar Dockerfile (GPU-ONLY / NVIDIA CUDA 12.1 + Python 3.11)
#
# This sidecar REQUIRES an NVIDIA CUDA-capable GPU.
# It will refuse to start if no GPU is detected.
#
# Prerequisites:
#   - NVIDIA GPU with CUDA support (tested on RTX 4060)
#   - Docker Desktop with WSL2 backend (Windows) or native Docker (Linux)
#   - NVIDIA Container Toolkit installed
#   - Verify: docker run --rm --gpus all nvidia/cuda:12.1.1-base-ubuntu22.04 nvidia-smi

FROM nvidia/cuda:12.1.1-runtime-ubuntu22.04

# Prevent interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

WORKDIR /app

# Install Python 3.11 and system dependencies
RUN apt-get update && apt-get install -y \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    build-essential \
    protobuf-compiler \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1 \
    && rm -rf /var/lib/apt/lists/*

# Ensure pip uses python 3.11
RUN python3.11 -m pip install --upgrade pip

# Copy requirements first for caching
COPY ml_server/requirements.txt .

# Install Python dependencies (CUDA-enabled PyTorch)
RUN python3.11 -m pip install --no-cache-dir -r requirements.txt

# Copy proto files and generate
COPY proto /proto
RUN python3.11 -m grpc_tools.protoc \
    -I/proto \
    --python_out=/app \
    --grpc_python_out=/app \
    /proto/ml_service.proto

# Copy application code
COPY ml_server/ .

# Set environment — GPU-ONLY, no CPU fallback
ENV PYTHONUNBUFFERED=1
ENV GRPC_PORT=50051
ENV LLM_GUARD_DEVICE=cuda

EXPOSE 50051

CMD ["python3.11", "server.py"]
