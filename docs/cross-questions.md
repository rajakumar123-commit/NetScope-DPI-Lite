# NetScope DPI Lite — Follow-Up Questions

Interviewers like to ask "What if" questions to see if you understand the limits of your design. Here are some likely follow-up questions and simple ways to answer them.

---

## 1. Limits of the Design

**Q: Your Load Balancer uses math (hashing) to send packets to Workers. What happens if a user downloads a massive 10GB file?**
> **A:** This is a known issue called the "Hot Flow Problem." Because the hashing math is consistent, all the packets for that massive 10GB download will go to just one Worker thread. That single Worker will be working at 100% capacity, while the other Workers might sit idle. In a real-world enterprise firewall, they use more complex dynamic balancing to handle massive "elephant flows," but for this project, simple hashing was the best tradeoff for speed.

**Q: Your queues use a `std::mutex` (lock) so threads can safely add or remove items. Isn't there a lock-free way to do this?**
> **A:** Yes, there are "lock-free" queues (like Ring Buffers). They are much faster, but the tradeoff is that the threads have to constantly spin in a loop checking if the queue has data, which uses 100% of the CPU even when the program is doing nothing. I chose to use locks and condition variables because it allows the threads to actually go to sleep when there's no work, which is much better for a normal computer.

---

## 2. Networking "What Ifs"

**Q: Your code expects to find the website name in the very first packet. What if the network is bad and splits the packet into two pieces?**
> **A:** That's a great point. My current code processes each packet individually. If the data is split across two separate packets (fragmentation), my code won't be able to read the website name. Professional enterprise systems have a feature called "TCP Reassembly" that waits and stitches the packets back together before reading them. That is a very complex feature and would be the next big improvement for my project.

**Q: What if someone fakes (spoofs) their IP address to get past your blocking rules?**
> **A:** For a website connection (TCP/HTTPS), IP spoofing doesn't really work. To start a connection, the server has to send a reply back to the client. If the client faked their IP, the reply goes to the fake IP, and the connection fails before it even starts. So, the fake traffic would naturally be dropped. However, for things like DNS (UDP), spoofing works easily, which is why DNS attacks are so common on the internet.

**Q: Have you heard of Encrypted ClientHello (ECH)? How does your project handle it?**
> **A:** Yes, ECH is a new internet standard that actually encrypts the website name (the SNI) so middleboxes can't read it. If a website uses ECH, my DPI engine will not be able to see the real website name, and passive blocking won't work. To block ECH traffic, big companies have to use "SSL Decryption," where they essentially act as a Man-in-the-Middle to decrypt all employee traffic. Passive inspection like mine is slowly becoming harder as the internet gets more secure.

---

## 3. C++ Details

**Q: If a bad packet causes a bug in Worker 2 and it crashes, what happens to your whole program?**
> **A:** In C++, if one thread crashes (like a segmentation fault), the entire program crashes. In a real production environment, a firewall should never crash just because it saw a bad packet. To fix this, I would need to wrap my parsing logic in `try/catch` blocks and make sure that if a packet is broken, the worker just logs an error, drops the packet, and moves on to the next one safely.
