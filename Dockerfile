# Use the Ubuntu base image
FROM --platform=linux/amd64 ubuntu:latest

# Install necessary dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    clang \
    llvm \
    make \
    cmake \
    gcc \
    g++ \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libclang-dev \
    libcurl4-openssl-dev \
    libboost-all-dev \
    pkg-config

# Set the working directory to /src
WORKDIR /src

# Copy your current directory to /src in the container
COPY . /src

# Set up any additional build or setup commands as needed (if any)

# Example: Install Rust (if you're using it)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain stable -y

# Default command to run when starting the container
CMD ["bash"]
