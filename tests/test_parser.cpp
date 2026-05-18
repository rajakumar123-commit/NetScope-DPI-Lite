#include "../include/packet_parser.h"
#include <iostream>
#include <vector>
#include <cassert>

using namespace NetScope;

int main() {
    std::cout << "[Test] Running PacketParser tests..." << std::endl;

    // Construct a synthetic TCP IPv4 packet
    // Ethernet: 14 bytes
    // IPv4: 20 bytes
    // TCP: 20 bytes
    // Payload: 4 bytes ("TEST")
    
    std::vector<uint8_t> pkt_data = {
        // --- Ethernet II ---
        // Dst MAC: 00:11:22:33:44:55
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        // Src MAC: 66:77:88:99:aa:bb
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        // EtherType: IPv4 (0x0800)
        0x08, 0x00,

        // --- IPv4 ---
        // Version 4, IHL 5 (0x45), TOS 0
        0x45, 0x00,
        // Total Length: 44 (0x002c)
        0x00, 0x2c,
        // ID: 1234 (0x04d2), Flags/Frag: 0
        0x04, 0xd2, 0x00, 0x00,
        // TTL: 64, Protocol: TCP (6)
        0x40, 0x06,
        // Checksum: 0x0000
        0x00, 0x00,
        // Src IP: 192.168.1.100 (0xc0a80164)
        0xc0, 0xa8, 0x01, 0x64,
        // Dst IP: 10.0.0.1 (0x0a000001)
        0x0a, 0x00, 0x00, 0x01,

        // --- TCP ---
        // Src Port: 12345 (0x3039)
        0x30, 0x39,
        // Dst Port: 80 (0x0050)
        0x00, 0x50,
        // Seq Number: 1000
        0x00, 0x00, 0x03, 0xe8,
        // Ack Number: 2000
        0x00, 0x00, 0x07, 0xd0,
        // Data Offset: 5 (20 bytes), Flags: PSH | ACK (0x18)
        0x50, 0x18,
        // Window
        0x00, 0x00,
        // Checksum
        0x00, 0x00,
        // Urgent Ptr
        0x00, 0x00,

        // --- Payload ---
        'T', 'E', 'S', 'T'
    };

    RawPacket raw;
    raw.data = pkt_data;
    raw.header.incl_len = pkt_data.size();
    raw.header.orig_len = pkt_data.size();

    ParsedPacket parsed;
    bool success = PacketParser::parse(raw, parsed);

    assert(success);
    assert(parsed.has_eth);
    assert(parsed.has_ip);
    assert(parsed.has_tcp);
    assert(!parsed.has_udp);

    assert(parsed.src_ip_str == "192.168.1.100");
    assert(parsed.dst_ip_str == "10.0.0.1");
    assert(parsed.src_port == 12345);
    assert(parsed.dst_port == 80);
    assert(parsed.tcp_flags == (TCPFlags::PSH | TCPFlags::ACK));

    assert(parsed.payload_length == 4);
    assert(parsed.payload_offset == 54); // 14 + 20 + 20
    assert(std::string(reinterpret_cast<const char*>(parsed.payload_data), parsed.payload_length) == "TEST");

    std::cout << "[Test] PacketParser tests passed!" << std::endl;
    return 0;
}
