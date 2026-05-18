#include "../include/sni_extractor.h"
#include <iostream>
#include <vector>
#include <cassert>

using namespace NetScope;

int main() {
    std::cout << "[Test] Running SNIExtractor tests..." << std::endl;

    // --- 1. Test HTTP Host Extractor ---
    std::string http_req = "GET /index.html HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: curl\r\n\r\n";
    std::vector<uint8_t> http_data(http_req.begin(), http_req.end());

    assert(HTTPHostExtractor::isHTTPRequest(http_data.data(), http_data.size()));
    auto host = HTTPHostExtractor::extract(http_data.data(), http_data.size());
    assert(host.has_value());
    assert(host.value() == "example.com");

    // --- 2. Test DNS Extractor ---
    std::vector<uint8_t> dns_query = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Query: www.google.com
        0x03, 'w', 'w', 'w', 0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, // Type: A
        0x00, 0x01  // Class: IN
    };
    
    assert(DNSExtractor::isDNSQuery(dns_query.data(), dns_query.size()));
    auto dns = DNSExtractor::extractQuery(dns_query.data(), dns_query.size());
    assert(dns.has_value());
    assert(dns.value() == "www.google.com");

    // --- 3. Test TLS SNI Extractor ---
    // Minimal valid ClientHello with SNI "test.com"
    std::vector<uint8_t> tls_client_hello = {
        // Record layer
        0x16, 0x03, 0x01, 0x00, 0x3d, // Handshake, TLS 1.0, length 61
        // Handshake layer
        0x01, 0x00, 0x00, 0x39, // ClientHello, length 57
        0x03, 0x03, // Client Version TLS 1.2
        // Random (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // Session ID length (0)
        0x00, 0x02, 0x13, 0x01, // Cipher Suites length (2), TLS_AES_128_GCM_SHA256
        0x01, 0x00, // Compression methods length (1), null
        0x00, 0x11, // Extensions total length (17)
        // SNI Extension
        0x00, 0x00, // Extension type: SNI
        0x00, 0x0d, // Extension length: 13
        0x00, 0x0b, // SNI list length: 11
        0x00,       // SNI type: hostname
        0x00, 0x08, // Hostname length: 8
        't', 'e', 's', 't', '.', 'c', 'o', 'm'
    };

    assert(SNIExtractor::isTLSClientHello(tls_client_hello.data(), tls_client_hello.size()));
    auto sni = SNIExtractor::extract(tls_client_hello.data(), tls_client_hello.size());
    assert(sni.has_value());
    assert(sni.value() == "test.com");

    std::cout << "[Test] SNIExtractor tests passed!" << std::endl;
    return 0;
}
