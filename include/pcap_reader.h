#pragma once
// ============================================================================
// pcap_reader.h — PCAP file reader + writer
// NetScope DPI Lite
//
// Upgrade from original:
//  - Added PcapWriter class (original wrote packets inline in main())
//  - Unified into namespace NetScope
//  - Added is_done() flag so reader thread knows when to stop
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace NetScope {

// ============================================================================
// PCAP File Format Structures
// ============================================================================

// 24-byte global header — appears once at start of every .pcap file
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 (little-endian) or 0xd4c3b2a1 (big-endian)
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset (usually 0)
    uint32_t sigfigs;        // timestamp accuracy (usually 0)
    uint32_t snaplen;        // max capture length (65535)
    uint32_t network;        // data link type: 1 = Ethernet
};

// 16-byte per-packet header — precedes every packet record
struct PcapPacketHeader {
    uint32_t ts_sec;    // timestamp: seconds
    uint32_t ts_usec;   // timestamp: microseconds
    uint32_t incl_len;  // bytes actually saved in file
    uint32_t orig_len;  // original packet length on wire
};

// One captured packet (header + raw bytes)
struct RawPacket {
    PcapPacketHeader     header;
    std::vector<uint8_t> data;
};

// ============================================================================
// PcapReader — sequential read from a .pcap file
// ============================================================================
class PcapReader {
public:
    PcapReader() = default;
    ~PcapReader() { close(); }

    // Open a pcap file. Returns false on failure.
    bool open(const std::string& filename);

    // Close the file
    void close();

    // Read the next packet into `packet`. Returns false when file exhausted.
    bool readNextPacket(RawPacket& packet);

    const PcapGlobalHeader& getGlobalHeader() const { return global_header_; }
    bool isOpen()  const { return file_.is_open(); }
    bool isDone()  const { return done_; }
    bool needsByteSwap() const { return needs_byte_swap_; }

private:
    std::ifstream    file_;
    PcapGlobalHeader global_header_{};
    bool             needs_byte_swap_ = false;
    bool             done_            = false;

    uint16_t maybeSwap16(uint16_t v) const;
    uint32_t maybeSwap32(uint32_t v) const;
};

// ============================================================================
// PcapWriter — write forwarded packets to an output .pcap file
// (original repo did this inline in main — we encapsulate it)
// ============================================================================
class PcapWriter {
public:
    PcapWriter() = default;
    ~PcapWriter() { close(); }

    // Open output file and write the global header from source capture
    bool open(const std::string& filename, const PcapGlobalHeader& global_header);

    // Write a single packet record
    void writePacket(const RawPacket& pkt);
    void writePacket(uint32_t ts_sec, uint32_t ts_usec,
                     const uint8_t* data, uint32_t length);

    void close();
    bool isOpen() const { return file_.is_open(); }

private:
    std::ofstream file_;
};

} // namespace NetScope
