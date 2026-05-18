// ============================================================================
// pcap_reader.cpp — PCAP file reader + writer implementation
// NetScope DPI Lite
// ============================================================================

#include "pcap_reader.h"
#include "platform.h"
#include <iostream>
#include <cstring>

namespace NetScope {

// ============================================================================
// PcapReader
// ============================================================================

bool PcapReader::open(const std::string& filename) {
    file_.open(filename, std::ios::binary);
    if (!file_.is_open()) {
        std::cerr << "[PcapReader] Cannot open: " << filename << '\n';
        return false;
    }

    // Read 24-byte global header
    file_.read(reinterpret_cast<char*>(&global_header_), sizeof(global_header_));
    if (file_.gcount() != sizeof(global_header_)) {
        std::cerr << "[PcapReader] Truncated global header\n";
        return false;
    }

    // Detect byte order from magic number
    if (global_header_.magic_number == 0xa1b2c3d4) {
        needs_byte_swap_ = false;
    } else if (global_header_.magic_number == 0xd4c3b2a1) {
        needs_byte_swap_ = true;
    } else {
        std::cerr << "[PcapReader] Bad magic number: 0x"
                  << std::hex << global_header_.magic_number << '\n';
        return false;
    }

    done_ = false;
    return true;
}

void PcapReader::close() {
    if (file_.is_open()) file_.close();
    done_ = true;
}

bool PcapReader::readNextPacket(RawPacket& packet) {
    if (!file_.is_open() || file_.eof()) {
        done_ = true;
        return false;
    }

    // Read 16-byte per-packet header
    file_.read(reinterpret_cast<char*>(&packet.header), sizeof(PcapPacketHeader));
    if (file_.gcount() != sizeof(PcapPacketHeader)) {
        done_ = true;
        return false;
    }

    // Byte-swap if needed
    if (needs_byte_swap_) {
        packet.header.ts_sec   = maybeSwap32(packet.header.ts_sec);
        packet.header.ts_usec  = maybeSwap32(packet.header.ts_usec);
        packet.header.incl_len = maybeSwap32(packet.header.incl_len);
        packet.header.orig_len = maybeSwap32(packet.header.orig_len);
    }

    // Sanity check capture length
    constexpr uint32_t MAX_PACKET = 65536;
    if (packet.header.incl_len == 0 || packet.header.incl_len > MAX_PACKET) {
        done_ = true;
        return false;
    }

    // Read packet bytes
    packet.data.resize(packet.header.incl_len);
    file_.read(reinterpret_cast<char*>(packet.data.data()), packet.header.incl_len);
    if (static_cast<uint32_t>(file_.gcount()) != packet.header.incl_len) {
        done_ = true;
        return false;
    }

    return true;
}

uint16_t PcapReader::maybeSwap16(uint16_t v) const {
    return needs_byte_swap_ ? swapBytes16(v) : v;
}

uint32_t PcapReader::maybeSwap32(uint32_t v) const {
    return needs_byte_swap_ ? swapBytes32(v) : v;
}

// ============================================================================
// PcapWriter
// ============================================================================

bool PcapWriter::open(const std::string& filename,
                      const PcapGlobalHeader& global_header) {
    file_.open(filename, std::ios::binary | std::ios::trunc);
    if (!file_.is_open()) {
        std::cerr << "[PcapWriter] Cannot open: " << filename << '\n';
        return false;
    }
    // Write global header (same as source file)
    file_.write(reinterpret_cast<const char*>(&global_header),
                sizeof(global_header));
    return true;
}

void PcapWriter::writePacket(const RawPacket& pkt) {
    writePacket(pkt.header.ts_sec, pkt.header.ts_usec,
                pkt.data.data(), static_cast<uint32_t>(pkt.data.size()));
}

void PcapWriter::writePacket(uint32_t ts_sec, uint32_t ts_usec,
                              const uint8_t* data, uint32_t length) {
    if (!file_.is_open()) return;

    PcapPacketHeader hdr;
    hdr.ts_sec   = ts_sec;
    hdr.ts_usec  = ts_usec;
    hdr.incl_len = length;
    hdr.orig_len = length;

    file_.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    file_.write(reinterpret_cast<const char*>(data), length);
}

void PcapWriter::close() {
    if (file_.is_open()) {
        file_.flush();
        file_.close();
    }
}

} // namespace NetScope
