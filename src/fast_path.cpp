// ============================================================================
// fast_path.cpp — DPI worker thread implementation
// NetScope DPI Lite
// ============================================================================

#include "fast_path.h"
#include <chrono>
#include <sstream>
#include <string>

namespace NetScope {

FastPathWorker::FastPathWorker(int                         worker_id,
                               RuleManager*                rules,
                               MetricsServer*              metrics,
                               DPIStats*                   stats,
                               ThreadSafeQueue<PacketJob>* output_queue)
    : worker_id_(worker_id),
      rules_(rules),
      metrics_(metrics),
      stats_(stats),
      output_queue_(output_queue),
      input_queue_(10000),
      tracker_(worker_id) {}

FastPathWorker::~FastPathWorker() { stop(); }

void FastPathWorker::start() {
    running_ = true;
    thread_  = std::thread(&FastPathWorker::run, this);
    LOG_INFO << "[Worker " << worker_id_ << "] Started";
}

void FastPathWorker::stop() {
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable()) thread_.join();
    LOG_INFO << "[Worker " << worker_id_ << "] Stopped."
             << " Processed: " << processed_.load()
             << " Forwarded: " << forwarded_.load()
             << " Dropped: "   << dropped_.load()
             << " Flows: "     << tracker_.flowCount();
}

// ============================================================================
// run — worker event loop
// ============================================================================
void FastPathWorker::run() {
    while (running_) {
        auto job = input_queue_.popWithTimeout(std::chrono::milliseconds(50));
        if (!job) continue;

        auto t_start = std::chrono::steady_clock::now();
        processPacket(*job);
        auto t_end  = std::chrono::steady_clock::now();

        double ms = std::chrono::duration<double, std::milli>(
                        t_end - t_start).count();
        if (metrics_) metrics_->recordLatencyMs(ms);

        processed_.fetch_add(1, std::memory_order_relaxed);

        // Periodic stale flow cleanup
        if (processed_.load() % CLEANUP_INTERVAL == 0) {
            size_t removed = tracker_.cleanupStale(std::chrono::seconds(120));
            if (removed > 0)
                LOG_DEBUG << "[Worker " << worker_id_ << "] Cleaned "
                          << removed << " stale flows";
            if (metrics_)
                metrics_->setQueueSize(worker_id_, input_queue_.size());
        }
    }
}

// ============================================================================
// processPacket — full DPI pipeline for one packet
// ============================================================================
void FastPathWorker::processPacket(PacketJob& pkt) {
    // 1. Get or create flow state (O(1), no locking — flow affinity)
    Connection& conn = tracker_.getOrCreate(pkt.tuple);

    conn.last_seen = std::chrono::steady_clock::now();
    conn.packets_in++;
    conn.bytes_in += pkt.data.size();

    // 2. Classify flow (try SNI/HTTP — runs only until classified)
    if (!conn.classified) {
        classifyFlow(pkt, conn);
    }

    // 3. Blocking decision
    if (conn.action == FlowAction::FORWARD) {
        conn.action = rules_->shouldBlock(
            pkt.tuple.src_ip, pkt.tuple.dst_port,
            conn.app_type, conn.sni);
    }

    // 4. Record metrics (lock-free atomics)
    if (metrics_) {
        metrics_->recordPacket(pkt.data.size());
        metrics_->recordApp(conn.app_type);
        if (pkt.tuple.protocol == 6)  metrics_->recordTCP();
        else                          metrics_->recordUDP();
    }

    stats_->total_packets.fetch_add(1, std::memory_order_relaxed);
    stats_->total_bytes.fetch_add(pkt.data.size(), std::memory_order_relaxed);

    int app_idx = static_cast<int>(conn.app_type);
    stats_->app_packets[app_idx].fetch_add(1, std::memory_order_relaxed);

    // 5. Forward or drop
    if (conn.action == FlowAction::DROP) {
        stats_->dropped_packets.fetch_add(1, std::memory_order_relaxed);
        if (metrics_) metrics_->recordDropped();
        dropped_.fetch_add(1, std::memory_order_relaxed);

        // Log first block per flow
        if (conn.state != ConnectionState::BLOCKED) {
            conn.state = ConnectionState::BLOCKED;
            LOG_INFO << "[BLOCKED] " << pkt.tuple.toString()
                     << " app=" << appTypeToString(conn.app_type)
                     << (conn.sni.empty() ? "" : " sni=" + conn.sni);
        }
    } else {
        stats_->forwarded_packets.fetch_add(1, std::memory_order_relaxed);
        if (metrics_) metrics_->recordForwarded();
        forwarded_.fetch_add(1, std::memory_order_relaxed);
        output_queue_->push(std::move(pkt));
    }
}

// ============================================================================
// classifyFlow — extract SNI / HTTP Host / DNS, set app_type
// ============================================================================
void FastPathWorker::classifyFlow(PacketJob& pkt, Connection& conn) {
    const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
    const size_t   plen    = pkt.payload_length;

    // --- TLS SNI (HTTPS port 443) ---
    if (pkt.tuple.dst_port == 443 && plen > 5) {
        auto sni = SNIExtractor::extract(payload, plen);
        if (sni) {
            conn.sni        = *sni;
            conn.app_type   = sniToAppType(*sni);
            conn.state      = ConnectionState::CLASSIFIED;
            conn.classified = true;
            return;
        }
    }

    // --- HTTP Host header (port 80) ---
    if (pkt.tuple.dst_port == 80 && plen > 10) {
        auto host = HTTPHostExtractor::extract(payload, plen);
        if (host) {
            conn.sni        = *host;
            conn.app_type   = sniToAppType(*host);
            conn.state      = ConnectionState::CLASSIFIED;
            conn.classified = true;
            return;
        }
    }

    // --- DNS (port 53 UDP) ---
    if ((pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) && plen >= 12) {
        auto domain = DNSExtractor::extractQuery(payload, plen);
        if (domain) {
            conn.sni        = *domain;
            conn.app_type   = AppType::DNS;
            conn.state      = ConnectionState::CLASSIFIED;
            conn.classified = true;
            return;
        }
    }

    // --- Port-based fallback (don't mark as classified — SNI may come later) ---
    if (pkt.tuple.dst_port == 443 && conn.app_type == AppType::UNKNOWN)
        conn.app_type = AppType::HTTPS;
    else if (pkt.tuple.dst_port == 80 && conn.app_type == AppType::UNKNOWN)
        conn.app_type = AppType::HTTP;
}

} // namespace NetScope
