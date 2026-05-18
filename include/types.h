#pragma once
// ============================================================================
// types.h — Core shared types for NetScope DPI Lite
// ============================================================================
//
// Upgrade from original:
//  - Unified namespace NetScope (original split PacketAnalyzer + DPI)
//  - Added FlowAction enum (replaces scattered bool blocked checks)
//  - Added per_app_packets atomic array in DPIStats
//  - Added APP_COUNT sentinel for array sizing
// ============================================================================

#include <cstdint>
#include <string>
#include <atomic>
#include <chrono>
#include <vector>

namespace NetScope {

// ============================================================================
// Application Types — detected via TLS SNI or HTTP Host header
// ============================================================================
enum class AppType : int {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT   // ← sentinel: keep last, used for array sizing
};

std::string appTypeToString(AppType type);
AppType     sniToAppType(const std::string& sni);

// ============================================================================
// Flow Action — what the engine does with a packet
// ============================================================================
enum class FlowAction {
    FORWARD,    // Pass through to output PCAP
    DROP        // Block — do not write to output
};

// ============================================================================
// Connection State — lifecycle of a tracked flow
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,  // SNI/Host extracted, app known
    BLOCKED,
    CLOSED
};

// ============================================================================
// Five-Tuple — uniquely identifies a network flow
// ============================================================================
struct FiveTuple {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  protocol = 0;  // 6=TCP, 17=UDP

    bool operator==(const FiveTuple& o) const {
        return src_ip   == o.src_ip  &&
               dst_ip   == o.dst_ip  &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               protocol == o.protocol;
    }

    // Bidirectional match: normalise so (A→B) == (B→A)
    FiveTuple normalised() const {
        if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port))
            return *this;
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }

    std::string toString() const;
};

// Boost-style hash combining — avoids collisions better than XOR
struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = 0;
        auto combine = [&](size_t v) {
            h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
        };
        combine(std::hash<uint32_t>{}(t.src_ip));
        combine(std::hash<uint32_t>{}(t.dst_ip));
        combine(std::hash<uint16_t>{}(t.src_port));
        combine(std::hash<uint16_t>{}(t.dst_port));
        combine(std::hash<uint8_t> {}(t.protocol));
        return h;
    }
};

// ============================================================================
// Connection — per-flow state tracked by each FastPathWorker
// ============================================================================
struct Connection {
    FiveTuple       tuple;
    ConnectionState state     = ConnectionState::NEW;
    AppType         app_type  = AppType::UNKNOWN;
    FlowAction      action    = FlowAction::FORWARD;
    std::string     sni;          // SNI hostname or HTTP Host

    uint64_t packets_in  = 0;
    uint64_t packets_out = 0;
    uint64_t bytes_in    = 0;
    uint64_t bytes_out   = 0;

    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;

    // TCP state helpers
    bool syn_seen     = false;
    bool syn_ack_seen = false;
    bool fin_seen     = false;
    bool classified   = false;  // true once SNI/Host successfully extracted
};

// ============================================================================
// PacketJob — self-contained packet passed between threads via queues
// Owns its data buffer — no dangling pointers after move
// ============================================================================
struct PacketJob {
    uint32_t             packet_id    = 0;
    uint32_t             ts_sec       = 0;
    uint32_t             ts_usec      = 0;
    FiveTuple            tuple;
    std::vector<uint8_t> data;         // full raw packet bytes
    uint8_t              tcp_flags    = 0;
    size_t               payload_offset = 0;
    size_t               payload_length = 0;
};

// ============================================================================
// DPIStats — global engine statistics (all atomics, no mutex needed)
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> active_connections{0};

    // Per-app packet counts — indexed by AppType enum value
    std::atomic<uint64_t> app_packets[static_cast<int>(AppType::APP_COUNT)];

    DPIStats() {
        for (auto& a : app_packets) a.store(0);
    }

    // Non-copyable (atomics are not copyable)
    DPIStats(const DPIStats&)            = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace NetScope
