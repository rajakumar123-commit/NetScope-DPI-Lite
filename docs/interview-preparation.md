# NetScope DPI Lite — Interview Preparation Guide

This guide is designed to help you confidently explain your project in a software engineering or networking interview. The answers are kept clear, practical, and beginner-friendly.

---

## 1. Explaining the Project

**Q: Can you tell me about your NetScope DPI project? What does it do?**
> **A:** NetScope DPI Lite is a network traffic inspector built in C++. Standard firewalls only block traffic based on IP addresses, but modern apps use shared IP addresses (like CDNs). My project reads the actual application data (Layer 7) inside the packet. Even though HTTPS is encrypted, the very first message a client sends contains the website name in plain text (called the SNI). NetScope extracts this name, identifies if it's YouTube, TikTok, or Netflix, and enforces blocking rules. It also uses multiple threads to process packets quickly.

**Q: Why didn't you just use existing libraries like `libpcap`?**
> **A:** My main goal was to learn how things work under the hood. By building the parser, the thread queues, and the logic from scratch using just standard C++, I learned a lot about memory management, how to safely share data between threads, and how network packets are structured byte-by-byte.

---

## 2. Multithreading Questions

**Q: How did you use multithreading in this project?**
> **A:** I used a Producer-Consumer pattern. One thread (the Reader) reads packets from a file and puts them into a queue. Multiple "Worker" threads take packets from the queue and do the heavy lifting of inspecting the payload and checking rules. This allows the program to process multiple packets at the same time.

**Q: If multiple threads are working at the same time, how do you prevent them from messing up each other's data?**
> **A:** To track a connection, you need a Hash Map. If all threads shared one Hash Map, they would need a Mutex lock, which slows everything down because they wait in line. 
> I solved this using a Load Balancer. It looks at the packet's IPs and generates a Hash number. Based on that number, it sends the packet to a specific Worker. Because the math is consistent, packets from the same connection always go to the same Worker. This means each Worker can have its own private Hash Map, and I didn't need to use a Mutex lock at all!

**Q: What happens if the Reader thread reads packets faster than the Workers can process them?**
> **A:** I implemented a concept called "Backpressure." The queues between the threads have a maximum size limit. If a queue gets full, the thread trying to put a packet into it will automatically go to sleep until there is space. This prevents the program from using up all the computer's RAM and crashing.

---

## 3. Networking and C++ Questions

**Q: How do you extract the website name from an HTTPS connection?**
> **A:** HTTPS is encrypted, but the very first packet the client sends is called the TLS ClientHello, and it's in plain text. My code loops through the raw bytes of that packet, skipping things like random numbers, until it finds the "Server Name Indication" (SNI) extension. Then it simply reads the string, like "www.youtube.com".

**Q: When moving big packets between threads, doesn't copying the data slow down the program?**
> **A:** Yes, copying data is very slow. To fix this, I used a C++11 feature called Move Semantics (`std::move`). Instead of copying the 1500 bytes of packet data into the queue, `std::move` just transfers the pointer to the data. The actual data in memory stays exactly where it is. This makes moving packets between threads incredibly fast.

**Q: How do you track statistics without slowing down the threads?**
> **A:** If I used a lock (mutex) every time a packet was processed just to update the `total_packets` counter, it would cause a huge traffic jam. Instead, I used C++ `std::atomic` variables. These are special variables that the CPU can safely update across multiple threads without needing a lock. A background thread reads these atomic variables and sends them to a Grafana dashboard.
