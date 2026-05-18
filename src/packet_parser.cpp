// ============================================================================
// packet_parser.cpp — Ethernet/IPv4/TCP/UDP parser implementation
// NetScope DPI Lite
//
// Key improvement over original: payload_offset is calculated here
// (original computed it inline in main_working.cpp, making it easy to miss).
// ============================================================================

#include "packet_parser.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace NetScope {

// ============================================================================
// Public entry point
// ============================================================================
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parsed = ParsedPacket{};  // reset
    parsed.ts_sec  = raw.header.ts_sec;
    parsed.ts_usec = raw.header.ts_usec;

    const uint8_t* data = raw.data.data();
    const size_t   len  = raw.data.size();

    if (len < 14) return false;  // too short for Ethernet

    size_t offset = 0;

    if (!parseEthernet(data, len, parsed, offset)) return false;
    if (!parsed.has_ip) return true;  // ARP etc. — skip

    if (!parseIPv4(data, len, parsed, offset)) return false;

    if (parsed.has_tcp) {
        if (!parseTCP(data, len, parsed, offset)) return false;
    } else if (parsed.has_udp) {
        if (!parseUDP(data, len, parsed, offset)) return false;
    }

    // Payload
    parsed.payload_offset = offset;
    if (offset < len) {
        parsed.payload_length = len - offset;
        parsed.payload_data   = data + offset;
    }

    return true;
}

// ============================================================================
// Ethernet (14 bytes)
// ============================================================================
bool PacketParser::parseEthernet(const uint8_t* data, size_t len,
                                  ParsedPacket& p, size_t& offset) {
    if (offset + 14 > len) return false;

    p.dst_mac    = macToString(data + offset);     offset += 6;
    p.src_mac    = macToString(data + offset);     offset += 6;
    p.ether_type = netToHost16(*reinterpret_cast<const uint16_t*>(data + offset));
    offset += 2;

    p.has_eth = true;
    p.has_ip  = (p.ether_type == EtherType::IPv4);
    return true;
}

// ============================================================================
// IPv4 (20+ bytes)
// ============================================================================
bool PacketParser::parseIPv4(const uint8_t* data, size_t len,
                              ParsedPacket& p, size_t& offset) {
    if (offset + 20 > len) return false;

    const auto* ip = reinterpret_cast<const IPv4Header*>(data + offset);

    p.ip_version = (ip->version_ihl >> 4) & 0x0F;
    if (p.ip_version != 4) return false;

    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;  // header length in bytes
    if (ihl < 20 || offset + ihl > len) return false;

    p.ttl      = ip->ttl;
    p.protocol = ip->protocol;
    p.src_ip   = netToHost32(ip->src_ip);
    p.dst_ip   = netToHost32(ip->dst_ip);
    p.src_ip_str = ipToString(p.src_ip);
    p.dst_ip_str = ipToString(p.dst_ip);
    p.has_ip   = true;

    offset += ihl;  // skip past IP header (including any options)

    p.has_tcp = (p.protocol == Protocol::TCP);
    p.has_udp = (p.protocol == Protocol::UDP);
    return true;
}

// ============================================================================
// TCP (20+ bytes)
// ============================================================================
bool PacketParser::parseTCP(const uint8_t* data, size_t len,
                             ParsedPacket& p, size_t& offset) {
    if (offset + 20 > len) return false;

    const auto* tcp = reinterpret_cast<const TCPHeader*>(data + offset);

    p.src_port  = netToHost16(tcp->src_port);
    p.dst_port  = netToHost16(tcp->dst_port);
    p.seq_num   = netToHost32(tcp->seq_number);
    p.ack_num   = netToHost32(tcp->ack_number);
    p.tcp_flags = tcp->flags;

    uint8_t data_offset = (tcp->data_offset >> 4) * 4;  // in bytes
    if (data_offset < 20 || offset + data_offset > len) return false;

    offset += data_offset;
    return true;
}

// ============================================================================
// UDP (8 bytes, fixed)
// ============================================================================
bool PacketParser::parseUDP(const uint8_t* data, size_t len,
                             ParsedPacket& p, size_t& offset) {
    if (offset + 8 > len) return false;

    const auto* udp = reinterpret_cast<const UDPHeader*>(data + offset);
    p.src_port = netToHost16(udp->src_port);
    p.dst_port = netToHost16(udp->dst_port);

    offset += 8;
    return true;
}

// ============================================================================
// Helpers
// ============================================================================
std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ':';
        ss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return ss.str();
}

std::string PacketParser::ipToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 24) & 0xFF) << '.'
       << ((ip >> 16) & 0xFF) << '.'
       << ((ip >>  8) & 0xFF) << '.'
       << ((ip >>  0) & 0xFF);
    return ss.str();
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string s;
    if (flags & TCPFlags::SYN) s += "SYN ";
    if (flags & TCPFlags::ACK) s += "ACK ";
    if (flags & TCPFlags::FIN) s += "FIN ";
    if (flags & TCPFlags::RST) s += "RST ";
    if (flags & TCPFlags::PSH) s += "PSH ";
    if (flags & TCPFlags::URG) s += "URG ";
    if (!s.empty()) s.pop_back();
    return s;
}

} // namespace NetScope
