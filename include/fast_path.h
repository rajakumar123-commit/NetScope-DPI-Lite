#pragma once
// ============================================================================
// fast_path.h — DPI worker thread (one per logical CPU core by default)
// NetScope DPI Lite
//
// Each FastPathWorker:
//   - Owns its own ConnectionTracker (zero-lock hot path)
//   - Pops PacketJobs from its dedicated queue
//   - Runs SNI / HTTP / DNS classification
//   - Calls RuleManager::shouldBlock()
//   - Records metrics atomically
//   - Pushes FORWARD packets to shared output_queue
// ============================================================================

#include "types.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "sni_extractor.h"
#include "metrics.h"
#include "logger.h"
#include <thread>
#include <atomic>
#include <memory>

namespace NetScope {

class FastPathWorker {
public:
    FastPathWorker(int                          worker_id,
                  RuleManager*                 rules,
                  MetricsServer*               metrics,
                  DPIStats*                    stats,
                  ThreadSafeQueue<PacketJob>*  output_queue);

    ~FastPathWorker();

    ThreadSafeQueue<PacketJob>& inputQueue() { return input_queue_; }

    void start();
    void stop();

    // Per-worker statistics
    uint64_t processed()  const { return processed_.load(); }
    uint64_t forwarded()  const { return forwarded_.load(); }
    uint64_t dropped()    const { return dropped_.load(); }
    size_t   flowCount()  const { return tracker_.flowCount(); }
    int      id()         const { return worker_id_; }

    // For Reporter: get all tracked flows at shutdown
    const ConnectionTracker& tracker() const { return tracker_; }

private:
    void run();
    void processPacket(PacketJob& pkt);
    void classifyFlow(PacketJob& pkt, Connection& conn);

    int                         worker_id_;
    RuleManager*                rules_;
    MetricsServer*              metrics_;
    DPIStats*                   stats_;
    ThreadSafeQueue<PacketJob>* output_queue_;
    ThreadSafeQueue<PacketJob>  input_queue_;
    ConnectionTracker           tracker_;

    std::thread          thread_;
    std::atomic<bool>    running_{false};
    std::atomic<uint64_t> processed_{0};
    std::atomic<uint64_t> forwarded_{0};
    std::atomic<uint64_t> dropped_{0};

    // Cleanup stale flows every 10,000 packets
    static constexpr uint64_t CLEANUP_INTERVAL = 10000;
};

} // namespace NetScope
