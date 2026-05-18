# NetScope DPI Lite — Packet Flow Walkthrough

This document traces the exact lifecycle of a single packet—from the moment it is read from disk to its final classification and egress—highlighting the memory management and parsing logic along the way.

---

## Example Packet

Imagine a user initiates a connection to YouTube. We are tracking the 4th packet of the flow: the **TLS ClientHello**.

- **Src:** `192.168.1.100:54321`
- **Dst:** `142.250.185.110:443`
- **Payload:** TLS handshake data containing the SNI extension `"www.youtube.com"`.

---

## Step 1: PCAP Read & Allocation

The `PcapReader` (running on the main thread) reads the 16-byte PCAP packet header to determine the frame's length on the wire (e.g., 512 bytes).

```cpp
RawPacket raw;
raw.data.resize(incl_len);  // Allocates 512 bytes on the heap
file_.read(reinterpret_cast<char*>(raw.data.data()), incl_len);
```

## Step 2: Zero-Copy Parsing

The `PacketParser` processes the raw bytes. It does **not** copy the L2/L3/L4 headers into new structs. Instead, it advances an `offset` cursor and uses `reinterpret_cast` to overlay C++ structs directly onto the raw byte array.

1. **Ethernet (14 bytes):** Verifies EtherType is `0x0800` (IPv4). Advances `offset` to 14.
2. **IPv4 (20+ bytes):** Reads the IP header length (IHL) and extracts `src_ip` and `dst_ip`. Uses `netToHost32` to correct for network byte order (Big Endian). Advances `offset` past the IP header.
3. **TCP (20+ bytes):** Extracts `src_port` and `dst_port`. Reads the TCP data offset to calculate where the TCP header ends.

```cpp
parsed.payload_offset = offset; // Let's say offset is 54
parsed.payload_length = total_len - offset; // 512 - 54 = 458 bytes of TLS data
```

## Step 3: Queue Transfer (Ownership & `std::move`)

The main thread bundles the metadata and the raw data into a `PacketJob` object. 

```cpp
PacketJob job;
job.tuple = makeTuple(parsed);          // {192.168.1.100, 142.250.185.110, 54321, 443, 6}
job.data  = std::move(raw.data);        // Transfers ownership! Zero memory is copied.
job.payload_offset = parsed.payload_offset;
```

By using `std::move()`, the heap pointer of the `std::vector` is transferred to `job.data`. The original `raw.data` vector is left empty. The `job` is then pushed into the LoadBalancer queue.

## Step 4: Load Balancing (Hashing)

The `LoadBalancer` thread pops the `PacketJob`.
It normalizes the 5-tuple (ensuring `src_ip < dst_ip`) so that packets flowing in the reverse direction result in the exact same hash.

```cpp
size_t worker_idx = hasher_(job->tuple.normalised()) % 4; // Suppose this yields 2.
worker_queues_[2]->push(std::move(*job)); // Moved again!
```
The packet is handed off to Worker 2.

## Step 5: Worker Processing & Flow State

Worker 2 pops the packet. Because of flow affinity, Worker 2 is the *only* thread that will ever see packets for this specific YouTube connection.

```cpp
Connection& conn = tracker_.getOrCreate(job.tuple);
conn.bytes_in += job.data.size();
```
Worker 2 looks up the flow in its local `std::unordered_map`. Since this is the 4th packet, the flow exists, but its state is currently `UNKNOWN` because the first 3 packets (TCP 3-way handshake) contained no payload.

## Step 6: L7 SNI Extraction

Because `conn.classified == false`, the engine attempts to classify the payload.
It sees `dst_port == 443` and calls the `SNIExtractor`.

The extractor performs byte-level traversal of the payload buffer starting at `job.payload_offset` (byte 54):
1. Verifies byte 0 is `0x16` (TLS Handshake).
2. Verifies byte 5 is `0x01` (ClientHello).
3. Skips the 32-byte random seed, variable-length session ID, and cipher suites.
4. Iterates over the TLS extensions until it finds extension type `0x0000` (SNI).
5. Parses the length markers and extracts the raw ASCII string: `"www.youtube.com"`.

The engine then maps the string to an application type:
```cpp
AppType app = sniToAppType("www.youtube.com"); // Returns AppType::YOUTUBE
conn.app_type = app;
conn.classified = true;
```
For packets 5 through 10,000 of this flow, the engine will see `conn.classified == true` and skip the expensive extraction phase entirely.

## Step 7: Rule Enforcement

Worker 2 now checks the `RuleManager` to determine the packet's fate.

```cpp
FlowAction action = rules_->shouldBlock(src_ip, dst_port, app, sni);
```
The `RuleManager` acquires a `std::shared_lock` (allowing other workers to read simultaneously) and checks the HashSets.
If the administrator added `block_app YouTube` to `rules.conf`, `shouldBlock` returns `FlowAction::DROP`.
If not, it returns `FlowAction::FORWARD`.

## Step 8: Metrics and Egress

**If FORWARD:**
- The worker atomic counters increment: `total_packets++`, `app_packets[YOUTUBE]++`.
- The `PacketJob` is moved to the `output_queue`: `output_queue_->push(std::move(*job))`.
- The Writer thread pops it and writes the raw bytes to `output.pcap`.

**If DROP:**
- The worker increments the `dropped_packets` atomic counter.
- The `PacketJob` is *not* pushed anywhere.
- As the loop iteration ends, the `PacketJob` object goes out of scope. Its destructor is called, which invokes the `std::vector` destructor, instantly freeing the 512 bytes of heap memory. No memory leaks, no explicit `delete` required.
