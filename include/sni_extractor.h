#pragma once
// ============================================================================
// sni_extractor.h — TLS SNI, HTTP Host, DNS query extraction
// NetScope DPI Lite
//
// Reused from original repository (most complete component).
// The TLS ClientHello parser is production-quality with full extension loop.
// QUIC extractor intentionally omitted (out of scope).
// ============================================================================

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace NetScope {

// ============================================================================
// SNIExtractor — parses TLS ClientHello to extract the SNI hostname
//
// TLS ClientHello structure (simplified):
//
//  [Record Layer - 5 bytes]
//    Byte 0:    Content Type = 0x16 (Handshake)
//    Bytes 1-2: TLS Version  (0x0301–0x0304)
//    Bytes 3-4: Record Length
//
//  [Handshake Layer]
//    Byte 0:    Handshake Type = 0x01 (ClientHello)
//    Bytes 1-3: Handshake Length (3-byte big-endian)
//    Bytes 4-5: Client Version
//    Bytes 6-37: Random (32 bytes)
//    Byte 38:   Session ID Length
//    ...variable: Session ID
//    2 bytes:   Cipher Suites Length
//    ...variable: Cipher Suites
//    1 byte:    Compression Methods Length
//    ...variable: Compression Methods
//    2 bytes:   Extensions Total Length
//    [Extension loop]
//      2 bytes: Extension Type
//      2 bytes: Extension Length
//      N bytes: Extension Data
//    [SNI Extension (type 0x0000)]
//      2 bytes: SNI List Length
//      1 byte:  SNI Type = 0x00 (hostname)
//      2 bytes: Hostname Length
//      N bytes: Hostname  <- EXTRACTED HERE
// ============================================================================
class SNIExtractor {
public:
    // Extract SNI from TLS ClientHello payload (after TCP header).
    // Returns nullopt if not a ClientHello or SNI not present.
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);

    // Quick check: is this a TLS ClientHello?
    static bool isTLSClientHello(const uint8_t* payload, size_t length);

private:
    static constexpr uint8_t  CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t  HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint16_t EXTENSION_SNI          = 0x0000;
    static constexpr uint8_t  SNI_TYPE_HOSTNAME      = 0x00;

    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

// ============================================================================
// HTTPHostExtractor — extracts Host: header from plaintext HTTP requests
// ============================================================================
class HTTPHostExtractor {
public:
    // Extract the Host header value from an HTTP request payload.
    // Strips port if present (e.g., "example.com:8080" -> "example.com").
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);

    // Check if payload starts with an HTTP method (GET, POST, etc.)
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

// ============================================================================
// DNSExtractor — extracts queried domain name from DNS query
// ============================================================================
class DNSExtractor {
public:
    // Extract the question domain from a DNS query.
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);

    // Returns true if this looks like a DNS query (QR bit = 0)
    static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace NetScope
