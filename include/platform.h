#pragma once
// ============================================================================
// platform.h — Portable byte-order conversion
// NetScope DPI Lite
//
// Replaces <arpa/inet.h> ntohs/ntohl with inline functions that work
// identically on Linux (Docker), macOS, and Windows WSL2.
// ============================================================================

#include <cstdint>

namespace NetScope {

inline uint16_t swapBytes16(uint16_t v) {
    return static_cast<uint16_t>(((v & 0xFF00u) >> 8) | ((v & 0x00FFu) << 8));
}

inline uint32_t swapBytes32(uint32_t v) {
    return ((v & 0xFF000000u) >> 24) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x000000FFu) << 24);
}

// Runtime endianness check — evaluated once, branch predicted away
inline bool isLittleEndian() {
    constexpr uint16_t test = 0x0001;
    return *reinterpret_cast<const uint8_t*>(&test) == 0x01;
}

// Network (big-endian) → host byte order
inline uint16_t netToHost16(uint16_t v) { return isLittleEndian() ? swapBytes16(v) : v; }
inline uint32_t netToHost32(uint32_t v) { return isLittleEndian() ? swapBytes32(v) : v; }

// Host → network byte order (same operation: symmetric)
inline uint16_t hostToNet16(uint16_t v) { return netToHost16(v); }
inline uint32_t hostToNet32(uint32_t v) { return netToHost32(v); }

} // namespace NetScope
