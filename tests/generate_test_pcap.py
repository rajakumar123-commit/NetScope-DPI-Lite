"""
generate_test_pcap.py — NetScope DPI Lite test PCAP generator
Ported from original Packet_analyzer repo + extended with more blocking targets.

Generates test_dpi.pcap with:
  - 16 TLS connections with real SNI hostnames (YouTube, Facebook, etc.)
  - 2 HTTP connections with Host headers
  - 4 DNS queries
  - 5 packets from blocked IP 192.168.1.50
  - Extra YouTube + Facebook flows to trigger default rules.conf blocks

Usage:
  python3 tests/generate_test_pcap.py
  → pcaps/test_dpi.pcap
"""

import struct
import random
import os

# ============================================================================
# PCAP writer
# ============================================================================
class PCAPWriter:
    def __init__(self, filename):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        self.file = open(filename, 'wb')
        self._write_global_header()
        self.timestamp = 1700000000

    def _write_global_header(self):
        # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, linktype=Ethernet
        self.file.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write_packet(self, data):
        ts_sec  = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        self.file.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
        self.file.write(data)

    def close(self):
        self.file.close()

# ============================================================================
# Packet construction helpers
# ============================================================================
def eth(src_mac='00:11:22:33:44:55', dst_mac='aa:bb:cc:dd:ee:ff', etype=0x0800):
    s = bytes.fromhex(src_mac.replace(':', ''))
    d = bytes.fromhex(dst_mac.replace(':', ''))
    return d + s + struct.pack('>H', etype)

def ip_hdr(src, dst, proto, payload_len):
    total = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH',
                      0x45, 0, total,
                      random.randint(1, 65535), 0x4000,
                      64, proto, 0)
    hdr += bytes(int(x) for x in src.split('.'))
    hdr += bytes(int(x) for x in dst.split('.'))
    return hdr

def tcp_hdr(sport, dport, seq, ack, flags):
    return struct.pack('>HHIIBHHHH' if False else '>HHIIBBHHH',
                       sport, dport, seq, ack,
                       0x50, flags, 65535, 0, 0)

def udp_hdr(sport, dport, payload_len):
    return struct.pack('>HHHH', sport, dport, 8 + payload_len, 0)

def tls_client_hello(sni: str) -> bytes:
    """Construct a minimal but valid TLS 1.2 ClientHello with SNI extension."""
    sni_b    = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_b)) + sni_b
    sni_list  = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext   = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list

    # Supported versions extension (TLS 1.3 support)
    sv_ext = struct.pack('>HHBH', 0x002b, 3, 2, 0x0304)

    extensions    = sni_ext + sv_ext
    ext_block     = struct.pack('>H', len(extensions)) + extensions

    client_hello = (
        struct.pack('>H', 0x0303) +               # client_version
        bytes(random.randint(0, 255) for _ in range(32)) +  # random
        struct.pack('B', 0) +                      # session_id_length
        struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302) +  # cipher_suites
        struct.pack('BB', 1, 0) +                  # compression_methods
        ext_block
    )

    hs = struct.pack('B', 0x01) + struct.pack('>I', len(client_hello))[1:] + client_hello
    record = struct.pack('B', 0x16) + struct.pack('>H', 0x0301) + struct.pack('>H', len(hs)) + hs
    return record

def http_request(host: str, path='/') -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: NetScope-Test/1.0\r\nAccept: */*\r\n\r\n").encode()

def dns_query(domain: str) -> bytes:
    txid  = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    qname = b''
    for label in domain.split('.'):
        qname += struct.pack('B', len(label)) + label.encode()
    qname += b'\x00'
    qtype  = struct.pack('>HH', 1, 1)  # A record, IN class
    return txid + flags + counts + qname + qtype

# ============================================================================
# Main generator
# ============================================================================
def main():
    out = 'pcaps/test_dpi.pcap'
    w   = PCAPWriter(out)

    USER_IP    = '192.168.1.100'
    USER_MAC   = '00:11:22:33:44:55'
    GW_MAC     = 'aa:bb:cc:dd:ee:ff'
    BLOCKED_IP = '192.168.1.50'
    DNS_SERVER = '8.8.8.8'

    seq = 1000

    # ---- TLS connections with real SNI (16 flows) ----------------------------
    tls_flows = [
        ('142.250.185.206', 'www.google.com',     443),
        ('142.250.185.110', 'www.youtube.com',    443),  # → BLOCKED by default rules
        ('157.240.1.35',    'www.facebook.com',   443),
        ('157.240.1.174',   'www.instagram.com',  443),
        ('104.244.42.65',   'twitter.com',        443),
        ('52.94.236.248',   'www.amazon.com',     443),
        ('23.52.167.61',    'www.netflix.com',    443),
        ('140.82.114.4',    'github.com',         443),
        ('104.16.85.20',    'discord.com',        443),
        ('35.186.224.25',   'zoom.us',            443),
        ('35.186.227.140',  'web.telegram.org',   443),
        ('99.86.0.100',     'www.tiktok.com',     443),  # → BLOCKED by domain rule
        ('35.186.224.47',   'open.spotify.com',   443),
        ('192.0.78.24',     'www.cloudflare.com', 443),
        ('13.107.42.14',    'www.microsoft.com',  443),
        ('17.253.144.10',   'www.apple.com',      443),
        # Extra YouTube flows to exercise app blocking
        ('142.250.0.46',    'youtu.be',           443),
        ('142.250.0.100',   'ytimg.com',          443),
        # Extra Facebook
        ('157.240.1.200',   'fbcdn.net',          443),
    ]

    for dst_ip, sni, dport in tls_flows:
        sport = random.randint(49152, 65535)
        e     = eth(USER_MAC, GW_MAC)

        # SYN
        t = tcp_hdr(sport, dport, seq, 0, 0x02)
        w.write_packet(e + ip_hdr(USER_IP, dst_ip, 6, len(t)) + t)

        # SYN-ACK (server)
        e2 = eth(GW_MAC, USER_MAC)
        t  = tcp_hdr(dport, sport, seq+1000, seq+1, 0x12)
        w.write_packet(e2 + ip_hdr(dst_ip, USER_IP, 6, len(t)) + t)

        # ACK
        t = tcp_hdr(sport, dport, seq+1, seq+1001, 0x10)
        w.write_packet(e + ip_hdr(USER_IP, dst_ip, 6, len(t)) + t)

        # TLS ClientHello with SNI
        payload = tls_client_hello(sni)
        t = tcp_hdr(sport, dport, seq+1, seq+1001, 0x18)
        w.write_packet(e + ip_hdr(USER_IP, dst_ip, 6, len(t)+len(payload)) + t + payload)

        seq += 10000

    # ---- HTTP connections (2 flows) ------------------------------------------
    http_flows = [
        ('93.184.216.34',   'example.com',  80),
        ('185.199.108.153', 'httpbin.org',  80),
    ]
    for dst_ip, host, dport in http_flows:
        sport   = random.randint(49152, 65535)
        e       = eth(USER_MAC, GW_MAC)

        t = tcp_hdr(sport, dport, seq, 0, 0x02)
        w.write_packet(e + ip_hdr(USER_IP, dst_ip, 6, len(t)) + t)

        payload = http_request(host)
        t = tcp_hdr(sport, dport, seq+1, 1, 0x18)
        w.write_packet(e + ip_hdr(USER_IP, dst_ip, 6, len(t)+len(payload)) + t + payload)
        seq += 10000

    # ---- DNS queries (4 flows) -----------------------------------------------
    dns_domains = ['www.google.com', 'www.youtube.com', 'www.facebook.com', 'api.twitter.com']
    for domain in dns_domains:
        sport   = random.randint(49152, 65535)
        e       = eth(USER_MAC, GW_MAC)
        payload = dns_query(domain)
        u       = udp_hdr(sport, 53, len(payload))
        w.write_packet(e + ip_hdr(USER_IP, DNS_SERVER, 17, len(u)+len(payload)) + u + payload)

    # ---- Blocked source IP (5 packets) ----------------------------------------
    blocked_mac = '00:11:22:33:44:56'
    for _ in range(5):
        sport = random.randint(49152, 65535)
        e     = eth(blocked_mac, GW_MAC)
        t     = tcp_hdr(sport, 443, seq, 0, 0x02)
        w.write_packet(e + ip_hdr(BLOCKED_IP, '172.217.0.100', 6, len(t)) + t)
        seq += 1000

    w.close()

    total = len(tls_flows) + len(http_flows) + len(dns_domains) + 5
    print(f"Generated {out}")
    print(f"  TLS flows:     {len(tls_flows)} (with real SNI hostnames)")
    print(f"  HTTP flows:    {len(http_flows)}")
    print(f"  DNS queries:   {len(dns_domains)}")
    print(f"  Blocked-IP:    5 packets from {BLOCKED_IP}")
    print(f"  Total flows:   {total}")
    print(f"\nTo run:")
    print(f"  ./build/netscope_dpi --pcap pcaps/test_dpi.pcap --rules rules.conf")

if __name__ == '__main__':
    main()
