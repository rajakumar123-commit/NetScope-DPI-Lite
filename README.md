# NetScope DPI Lite

> **A multithreaded Deep Packet Inspection (DPI) engine written in C++17.**  
> Classifies network flows by application (YouTube, TikTok, Netflix, etc.) using TLS SNI, HTTP Host, and DNS analysis. Enforces IP/app/domain/port-level blocking rules, exports real-time metrics to Prometheus/Grafana, and writes filtered PCAP output.

---

## What This Project Is

NetScope DPI Lite is a **from-scratch systems programming project** that demonstrates how professional network inspection engines work internally — the same class of software used inside ISP routers, enterprise firewalls, and CDN WAFs.

It does not wrap `libpcap` or any third-party DPI library. Every layer — packet parsing, TLS ClientHello traversal, flow tracking, multithreaded queue routing, and HTTP metrics export — is implemented directly in C++17 using standard library primitives.

**This project is educational in intent** and is tested against PCAP files, not live traffic.

---

## Key Features

| Feature | Detail |
|---|---|
| **Layer-7 Classification** | TLS SNI, HTTP `Host:` header, DNS label decoding |
| **21 Application Types** | YouTube, Netflix, TikTok, Discord, Zoom, GitHub, and more |
| **Multithreaded Pipeline** | Reader → Load Balancer → N Workers → Writer |
| **Flow Affinity** | Hash-routed; zero mutex on flow-table hot path |
| **Blocking Rules Engine** | Block by IP, app, domain pattern (`*.tiktok.com`), or port |
| **Prometheus Metrics** | Lock-free atomic counters; histogram latency tracking |
| **Grafana Dashboard** | Pre-provisioned via docker-compose |
| **PCAP I/O** | Reads any `.pcap` file; writes filtered output PCAP |
| **Portable** | GCC on Linux/Docker, MinGW on Windows (MSYS2 UCRT64) |
| **No External Dependencies** | Only C++17 stdlib + POSIX sockets |

---

## Architecture at a Glance

```
Input .pcap file
        │
        ▼
 ┌─────────────┐
 │ Main Thread │  Reader — reads raw packets, builds PacketJob
 │  (Reader)   │  parses Ethernet/IP/TCP/UDP, moves data into queue
 └──────┬──────┘
        │  ThreadSafeQueue<PacketJob>  (capacity 50,000)
        ▼
 ┌──────────────┐
 │ LoadBalancer │  Hashes FiveTuple → worker_idx = hash(5-tuple) % N
 │   Thread     │  Guarantees flow affinity (all pkts of a flow → same worker)
 └──────┬───────┘
   ┌────┴──────────────────────────────────┐
   │          (per-worker queues, cap 10k) │
   ▼      ▼      ▼      ▼                 
 ┌────┐ ┌────┐ ┌────┐ ┌────┐             
 │ W0 │ │ W1 │ │ W2 │ │ W3 │  FastPathWorkers (N, default 4)
 └─┬──┘ └─┬──┘ └─┬──┘ └─┬──┘  Each owns private ConnectionTracker
   │      │      │      │      SNI/HTTP/DNS classify, rule check, metrics
   └──────┴──────┴──────┴──────────────────┐
                                           │ FORWARD packets only
                                           ▼
                                  ┌─────────────────┐
                                  │  Output Queue   │  (cap 20,000)
                                  └────────┬────────┘
                                           ▼
                                  ┌─────────────────┐
                                  │  Writer Thread  │  → output/output.pcap
                                  └─────────────────┘

MetricsServer (background thread) ← Prometheus scrapes :9100/metrics every 5s
```

---

## Project Structure

```
NetScope DPI Lite/
├── src/                    # Implementation files
│   ├── main.cpp            # Engine orchestrator, CLI, shutdown sequencing
│   ├── types.cpp           # AppType strings, sniToAppType() CDN alias map
│   ├── pcap_reader.cpp     # PCAP global header + per-packet read/write
│   ├── packet_parser.cpp   # Ethernet/IPv4/TCP/UDP header parsing
│   ├── sni_extractor.cpp   # TLS ClientHello walker, HTTP Host, DNS decoder
│   ├── connection_tracker.cpp  # Per-worker unordered_map flow table
│   ├── load_balancer.cpp   # FiveTuple hasher → worker queue router
│   ├── fast_path.cpp       # Per-worker DPI loop: classify → block → route
│   ├── rule_manager.cpp    # IP/app/domain/port blacklists + shouldBlock()
│   ├── metrics.cpp         # POSIX HTTP server, Prometheus text format
│   └── logger.cpp          # Thread-safe RAII stream logger (singleton)
├── include/                # Header files (one per class)
├── tests/
│   ├── generate_test_pcap.py   # Python script: generates test_dpi.pcap
│   ├── test_parser.cpp         # Unit test: packet parser
│   └── test_sni.cpp            # Unit test: SNI/HTTP/DNS extractors
├── docker/
│   ├── Dockerfile          # Multi-stage build (gcc:12 builder → ubuntu:22.04)
│   └── docker-compose.yml  # netscope + prometheus + grafana services
├── prometheus/prometheus.yml   # Scrape config: netscope:9100 every 5s
├── grafana/provisioning/       # Auto-provisioned datasource + dashboard
├── rules.conf              # Blocking rules (IP, app, domain, port)
├── CMakeLists.txt          # C++17 build, test targets
└── docs/                   # Full engineering documentation (this folder)
```

---

## Quick Start

### Native Build (Linux / MSYS2 UCRT64 on Windows)

```bash
# Generate test PCAP
python3 tests/generate_test_pcap.py

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run
./netscope_dpi --pcap ../pcaps/test_dpi.pcap --workers 4
```

### Docker (Recommended — includes Prometheus + Grafana)

```bash
# Copy a PCAP to pcaps/input.pcap, then:
cd docker
docker-compose up --build

# Open Grafana:  http://localhost:3000  (admin/admin)
# Open Prometheus: http://localhost:9090
# Raw metrics:  http://localhost:9100/metrics
```

---

## CLI Reference

```
Usage: netscope_dpi --pcap <input.pcap> [options]

  --pcap     <file>    Input PCAP file (required)
  --out      <file>    Output PCAP file [default: output/output.pcap]
  --rules    <file>    Blocking rules file [default: rules.conf]
  --workers  <N>       Number of worker threads [default: 4]
  --log      <file>    Log file [default: logs/engine.log]
  --metrics  <port>    Prometheus port [default: 9100]
  --no-metrics         Disable Prometheus endpoint
  --daemon             Keep metrics server alive after processing completes
```

---

## Rules File Format (`rules.conf`)

```conf
# Block a specific source IP
block_ip     192.168.1.50

# Block all traffic classified as these apps (via SNI/Host)
block_app    YouTube
block_app    TikTok

# Block by domain substring or wildcard
block_domain tiktok.com
block_domain *.betting-site.com

# Block by destination port
block_port   4444
block_port   1337
```

---

## Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `netscope_packets_processed_total` | Counter | Total packets through the engine |
| `netscope_bytes_processed_total` | Counter | Total bytes processed |
| `netscope_packets_forwarded_total` | Counter | Packets passed to output PCAP |
| `netscope_packets_dropped_total` | Counter | Packets blocked by rules |
| `netscope_tcp_packets_total` | Counter | TCP flow count |
| `netscope_udp_packets_total` | Counter | UDP flow count |
| `netscope_active_flows` | Gauge | Current flow table size |
| `netscope_app_packets_total{app="..."}` | Counter | Per-application classification |
| `netscope_worker_queue_size{worker="N"}` | Gauge | Current queue depth per worker |
| `netscope_processing_latency_ms` | Histogram | Per-packet processing time |

---

## Documentation

Full engineering documentation lives in [`docs/`](docs/). Start with:

1. [`architecture.md`](docs/architecture.md) — System overview and design reasoning
2. [`packet-flow.md`](docs/packet-flow.md) — Packet lifecycle from bytes to classification
3. [`threading-model.md`](docs/threading-model.md) — All threads, queues, and interactions
4. [`tls-sni-explained.md`](docs/tls-sni-explained.md) — Byte-level TLS parsing walkthrough
5. [`interview-preparation.md`](docs/interview-preparation.md) — Deep Q&A on every subsystem
6. [`cross-questions.md`](docs/cross-questions.md) — Difficult follow-up questions with answers

---

## What This Project Demonstrates

| Skill Area | Evidence |
|---|---|
| **Systems Programming** | Manual packet parsing with `reinterpret_cast`, byte-order handling |
| **Multithreading (C++17)** | `std::thread`, `std::atomic`, `std::condition_variable`, `std::shared_mutex` |
| **Networking / DPI** | TLS RFC 5246/8446 parsing, DNS label decoding, HTTP header scanning |
| **Producer-Consumer Design** | Bounded `ThreadSafeQueue<T>` with backpressure |
| **Flow Affinity Architecture** | Hash-based routing to eliminate shared-state contention |
| **Observability** | Custom Prometheus HTTP endpoint, Grafana dashboard |
| **Docker / Containerisation** | Multi-stage build, docker-compose service orchestration |
| **Modern C++** | Move semantics, `std::optional`, RAII, templates, lambdas |

---

## Limitations (Honest Disclosure)

- **PCAP-only input** — does not capture live traffic (no `AF_PACKET`, `libpcap`, or `eBPF`)
- **IPv4 only** — IPv6, VLAN-tagged frames, and GRE tunnels are skipped
- **No TCP reassembly** — SNI must arrive in a single TCP segment (standard for TLS handshakes)
- **TLS 1.3 ECH** — Encrypted ClientHello (RFC 9001+) hides the SNI; engine cannot extract it
- **QUIC/HTTP3** — Not supported; QUIC traffic will remain UNKNOWN or UDP-classified
- **No hot-reload** — Rule changes require engine restart
- **Single metrics server thread** — Handles one Prometheus scrape at a time (sufficient for 5s intervals)
- **In-memory flow table only** — No persistence; flow state is lost on restart

---

## License

MIT — Educational use.
