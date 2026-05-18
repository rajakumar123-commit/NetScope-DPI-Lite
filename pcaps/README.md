# pcaps/ — Input PCAP Files

Place your `.pcap` capture files here.

## Generate a Test PCAP (No Wireshark Needed)

```bash
python3 tests/generate_test_pcap.py
```

This creates `pcaps/test_dpi.pcap` with:
- 19 TLS connections (real SNI: YouTube, Facebook, GitHub, Discord, Zoom…)
- 2 HTTP connections with `Host:` headers
- 4 DNS queries
- 5 packets from blocked IP `192.168.1.50`

## Run the Engine

```bash
./build/netscope_dpi \
    --pcap pcaps/test_dpi.pcap \
    --rules rules.conf \
    --out output/filtered.pcap \
    --workers 4
```

## Using Real Captures

Capture with Wireshark or tcpdump:
```bash
tcpdump -i eth0 -w pcaps/capture.pcap
```

Then run:
```bash
./build/netscope_dpi --pcap pcaps/capture.pcap
```

> **Note**: `pcaps/` is git-ignored. Do not commit PCAP files containing real traffic.
