#pragma once
// ============================================================================
// load_balancer.h — Flow-affine packet dispatcher
// NetScope DPI Lite
//
// Single LB thread (simplified from original's 2-LB model).
// Pops ParsedPackets from raw_queue, hashes the five-tuple, routes
// to the correct worker queue — ensuring all packets of a flow hit
// the SAME worker thread (zero locking on flow table hot path).
// ============================================================================

#include "types.h"
#include "packet_parser.h"
#include "thread_safe_queue.h"
#include <vector>
#include <thread>
#include <atomic>
#include <memory>

namespace NetScope {

class LoadBalancer {
public:
    // worker_queues: one per FastPathWorker (owned by DPIEngine)
    explicit LoadBalancer(
        std::vector<ThreadSafeQueue<PacketJob>*> worker_queues);

    ~LoadBalancer();

    // raw_queue fed by Reader thread
    ThreadSafeQueue<PacketJob>& inputQueue() { return input_queue_; }

    void start();
    void stop();

    uint64_t dispatched() const { return dispatched_.load(); }
    uint64_t dropped()    const { return lb_dropped_.load(); }

private:
    void run();

    std::vector<ThreadSafeQueue<PacketJob>*> worker_queues_;
    ThreadSafeQueue<PacketJob>               input_queue_;
    std::thread                              thread_;
    std::atomic<bool>                        running_{false};
    std::atomic<uint64_t>                    dispatched_{0};
    std::atomic<uint64_t>                    lb_dropped_{0};  // parse failures

    FiveTupleHash hasher_;
};

} // namespace NetScope
