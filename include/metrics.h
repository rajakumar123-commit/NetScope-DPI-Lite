#pragma once
// ============================================================================
// metrics.h — Prometheus metrics server
// NetScope DPI Lite (NEW — not in original repo)
//
// Runs a minimal POSIX HTTP server on :9100.
// Prometheus scrapes GET /metrics → returns text format.
// All counters are atomic — zero mutex overhead on hot path.
// ============================================================================

#include "types.h"
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <functional>
#include <cstdint>

namespace NetScope {

class MetricsServer {
public:
    explicit MetricsServer(uint16_t port = 9100);
    ~MetricsServer();

    // Start the HTTP server thread
    void start();

    // Stop gracefully
    void stop();

    // ---------- Called by workers on hot path (lock-free) ----------
    void recordPacket(uint64_t bytes);
    void recordForwarded();
    void recordDropped();
    void recordTCP();
    void recordUDP();
    void recordApp(AppType app);
    void recordLatencyMs(double ms);

    // ---------- Called by ConnectionTracker on cleanup ----------
    void setActiveFlows(size_t count);
    void setQueueSize(int worker_id, size_t size);

    // ---------- Generate Prometheus text format ----------
    std::string renderMetrics() const;

private:
    uint16_t    port_;
    std::thread server_thread_;
    std::atomic<bool> running_{false};
    int listen_fd_ = -1;

    void serverLoop();
    void handleClient(int client_fd);

    // ---------- Counters (all atomic) ----------
    std::atomic<uint64_t> packets_total_{0};
    std::atomic<uint64_t> bytes_total_{0};
    std::atomic<uint64_t> forwarded_total_{0};
    std::atomic<uint64_t> dropped_total_{0};
    std::atomic<uint64_t> tcp_total_{0};
    std::atomic<uint64_t> udp_total_{0};
    std::atomic<uint64_t> active_flows_{0};

    // Per-app counters
    std::atomic<uint64_t> app_counts_[static_cast<int>(AppType::APP_COUNT)];

    // Per-worker queue sizes (gauge)
    static constexpr int MAX_WORKERS = 16;
    std::atomic<uint64_t> queue_sizes_[MAX_WORKERS];

    // Processing latency histogram (buckets: 0.1, 1, 5, 10, +Inf ms)
    std::atomic<uint64_t> lat_bucket_01_{0};
    std::atomic<uint64_t> lat_bucket_1_{0};
    std::atomic<uint64_t> lat_bucket_5_{0};
    std::atomic<uint64_t> lat_bucket_10_{0};
    std::atomic<uint64_t> lat_bucket_inf_{0};
    std::atomic<uint64_t> lat_count_{0};
    // sum stored as integer microseconds to avoid floating-point atomics
    std::atomic<uint64_t> lat_sum_us_{0};
};

} // namespace NetScope
