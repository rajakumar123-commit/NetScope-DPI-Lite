# ============================================================================
# Dockerfile — Multi-stage build for NetScope DPI Lite
# Stage 1: Build with GCC 12 on Debian
# Stage 2: Minimal Ubuntu 22.04 runtime
# ============================================================================

# ---- Stage 1: Build --------------------------------------------------------
FROM gcc:12 AS builder

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy project files
COPY include/   ./include/
COPY src/        ./src/
COPY CMakeLists.txt ./
COPY rules.conf  ./

# Build
RUN mkdir -p build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make -j$(nproc)

# ---- Stage 2: Runtime ------------------------------------------------------
FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary + config
COPY --from=builder /build/build/netscope_dpi ./
COPY --from=builder /build/rules.conf          ./

# Create expected directories
RUN mkdir -p pcaps output logs reports

# Expose Prometheus metrics port
EXPOSE 9100

# Default entrypoint — expects PCAP mounted at /app/pcaps/input.pcap
ENTRYPOINT ["./netscope_dpi"]
CMD ["--pcap", "pcaps/input.pcap", "--rules", "rules.conf", \
     "--out",  "output/output.pcap", "--workers", "4", "--daemon"]
