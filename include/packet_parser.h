#pragma once
// ============================================================================
// packet_parser.h — Ethernet / IPv4 / TCP / UDP header parsing
// NetScope DPI Lite
//
// Upgrade from original:
//  - Added payload_offset calculation (was inline in main_working.cpp)
//  - Protocol/flag constants in inline namespaces
//  - Unified namespace NetScope
// ============================================================================

#include "pcap_reader.h"
#include <cstdint>
#include <string>
#include <array>
#include <cstring>

namespace NetScope {

// ============================================================================
// Protocol header structs — byte-accurate, packed layout
// ============================================================================

// Ethernet II header — 14 bytes
struct EthernetHeader {
    std::array<uint8_t, 6> dst_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;   // network byte order
};

// IPv4 header — 20 bytes minimum (options extend it)
struct IPv4Header {
    uint8_t  version_ihl;    // [7:4]=version(4), [3:0]=IHL (header len / 4)
    uint8_t  tos;
    uint16_t total_length;   // network byte order
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;       // 6=TCP, 17=UDP, 1=ICMP
    uint16_t checksum;
    uint32_t src_ip;         // network byte order
    uint32_t dst_ip;         // network byte order
};

// TCP header — 20 bytes minimum
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t  data_offset;   // [7:4] = data offset (header len / 4)
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// UDP header — 8 bytes (fixed)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

// ============================================================================
// TCP Flag constants
// ============================================================================
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// EtherType values
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
}

// IP Protocol numbers
namespace Protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP  = 6;
    constexpr uint8_t UDP  = 17;
}

// ============================================================================
// ParsedPacket — result of parsing one raw packet
// ============================================================================
struct ParsedPacket {
    // Timestamps (copied from PCAP packet header)
    uint32_t ts_sec  = 0;
    uint32_t ts_usec = 0;

    // Ethernet layer
    bool        has_eth   = false;
    std::string src_mac;
    std::string dst_mac;
    uint16_t    ether_type = 0;

    // IP layer
    bool     has_ip     = false;
    uint8_t  ip_version = 0;
    uint8_t  ttl        = 0;
    uint8_t  protocol   = 0;   // 6=TCP, 17=UDP
    uint32_t src_ip     = 0;   // host byte order
    uint32_t dst_ip     = 0;   // host byte order
    std::string src_ip_str;
    std::string dst_ip_str;

    // Transport layer
    bool     has_tcp   = false;
    bool     has_udp   = false;
    uint16_t src_port  = 0;
    uint16_t dst_port  = 0;
    uint8_t  tcp_flags = 0;
    uint32_t seq_num   = 0;
    uint32_t ack_num   = 0;

    // Payload (points into original RawPacket data — valid only during processing)
    size_t         payload_offset = 0;  // byte offset from start of RawPacket::data
    size_t         payload_length = 0;
    const uint8_t* payload_data   = nullptr;
};

// ============================================================================
// PacketParser — stateless static parser
// ============================================================================
class PacketParser {
public:
    // Parse raw → parsed. Returns false if packet is malformed / unsupported.
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

    // Helpers
    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip_host_order);
    static std::string tcpFlagsToString(uint8_t flags);

private:
    static bool parseEthernet(const uint8_t* data, size_t len,
                               ParsedPacket& p, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len,
                           ParsedPacket& p, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len,
                          ParsedPacket& p, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len,
                          ParsedPacket& p, size_t& offset);
};

} // namespace NetScope
