// ============================================================================
// sni_extractor.cpp — TLS SNI / HTTP Host / DNS query extraction
// NetScope DPI Lite
//
// Core TLS parser reused from original repository — most complete component.
// All byte offsets validated against RFC 5246 (TLS 1.2) and RFC 8446 (TLS 1.3).
// ============================================================================

#include "sni_extractor.h"
#include <cstring>

namespace NetScope {

// ============================================================================
// Helpers
// ============================================================================
uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) <<  8) |
            static_cast<uint32_t>(data[2]);
}

// ============================================================================
// SNIExtractor::isTLSClientHello
// ============================================================================
bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;

    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;

    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;

    uint16_t record_len = readUint16BE(payload + 3);
    if (record_len > length - 5) return false;

    if (payload[5] != HANDSHAKE_CLIENT_HELLO) return false;
    return true;
}

// ============================================================================
// SNIExtractor::extract — full TLS ClientHello extension walker
// ============================================================================
std::optional<std::string> SNIExtractor::extract(const uint8_t* payload,
                                                   size_t length) {
    if (!isTLSClientHello(payload, length)) return std::nullopt;

    size_t offset = 5;  // skip TLS record header
    offset += 1;        // handshake type (already verified)
    offset += 3;        // 3-byte handshake length

    if (offset + 2 > length) return std::nullopt;
    offset += 2;  // client version

    if (offset + 32 > length) return std::nullopt;
    offset += 32; // random

    if (offset >= length) return std::nullopt;
    uint8_t session_id_len = payload[offset++];
    if (offset + session_id_len > length) return std::nullopt;
    offset += session_id_len;

    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;
    if (offset > length) return std::nullopt;

    if (offset >= length) return std::nullopt;
    uint8_t comp_len = payload[offset++];
    if (offset + comp_len > length) return std::nullopt;
    offset += comp_len;

    if (offset + 2 > length) return std::nullopt;
    uint16_t ext_total = readUint16BE(payload + offset);
    offset += 2;

    size_t ext_end = offset + ext_total;
    if (ext_end > length) ext_end = length;

    // Walk extensions
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_len  = readUint16BE(payload + offset + 2);
        offset += 4;

        if (offset + ext_len > ext_end) break;

        if (ext_type == EXTENSION_SNI) {
            if (ext_len < 5) break;

            uint16_t list_len = readUint16BE(payload + offset);
            if (list_len < 3) break;

            uint8_t  sni_type = payload[offset + 2];
            uint16_t sni_len  = readUint16BE(payload + offset + 3);

            if (sni_type != SNI_TYPE_HOSTNAME) break;
            if (sni_len > ext_len - 5)         break;

            return std::string(
                reinterpret_cast<const char*>(payload + offset + 5),
                sni_len);
        }

        offset += ext_len;
    }

    return std::nullopt;
}

// ============================================================================
// HTTPHostExtractor
// ============================================================================
bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    for (const char* m : methods) {
        if (std::memcmp(payload, m, 4) == 0) return true;
    }
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload,
                                                       size_t length) {
    if (!isHTTPRequest(payload, length)) return std::nullopt;

    for (size_t i = 0; i + 6 < length; ++i) {
        if ((payload[i]   == 'H' || payload[i]   == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
             payload[i+4] == ':') {

            size_t start = i + 5;
            while (start < length &&
                   (payload[start] == ' ' || payload[start] == '\t'))
                ++start;

            size_t end = start;
            while (end < length &&
                   payload[end] != '\r' && payload[end] != '\n')
                ++end;

            if (end > start) {
                std::string host(
                    reinterpret_cast<const char*>(payload + start),
                    end - start);
                // Strip port (e.g., "example.com:8080" -> "example.com")
                auto colon = host.find(':');
                if (colon != std::string::npos)
                    host = host.substr(0, colon);
                return host;
            }
        }
    }

    return std::nullopt;
}

// ============================================================================
// DNSExtractor
// ============================================================================
bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    if (payload[2] & 0x80) return false;
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    return qdcount > 0;
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload,
                                                       size_t length) {
    if (!isDNSQuery(payload, length)) return std::nullopt;

    size_t offset = 12;
    std::string domain;

    while (offset < length) {
        uint8_t label_len = payload[offset++];
        if (label_len == 0) break;
        if (label_len > 63) break;
        if (offset + label_len > length) break;

        if (!domain.empty()) domain += '.';
        domain.append(reinterpret_cast<const char*>(payload + offset), label_len);
        offset += label_len;
    }

    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

} // namespace NetScope
