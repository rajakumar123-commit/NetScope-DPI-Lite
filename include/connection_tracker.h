#pragma once
// ============================================================================
// connection_tracker.h — Per-worker flow state table
// NetScope DPI Lite
//
// Design: each FastPathWorker has its OWN ConnectionTracker.
// Flow affinity (hash % N_workers) ensures one flow always hits one worker.
// → Zero locking on the hot path. No shared state between workers.
//
// Improvement over original: removed GlobalConnectionTable
// (aggregation done by Reporter at shutdown instead).
// ============================================================================

#include "types.h"
#include <unordered_map>
#include <chrono>

namespace NetScope {

class ConnectionTracker {
public:
    explicit ConnectionTracker(int worker_id);

    // Get existing connection or create a new one for this five-tuple
    Connection& getOrCreate(const FiveTuple& tuple);

    // Check if a connection exists (bidirectional)
    Connection* find(const FiveTuple& tuple);

    // Remove stale connections (last_seen older than timeout)
    size_t cleanupStale(std::chrono::seconds timeout =
                            std::chrono::seconds(120));

    // Accessors
    size_t             flowCount() const { return table_.size(); }
    int                workerId()  const { return worker_id_; }

    // Iterator access for Reporter aggregation at shutdown
    using FlowTable = std::unordered_map<FiveTuple, Connection, FiveTupleHash>;
    const FlowTable& flows() const { return table_; }

private:
    int        worker_id_;
    FlowTable  table_;
};

} // namespace NetScope
