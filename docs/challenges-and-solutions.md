# NetScope DPI Lite — Challenges & Solutions

Building a multithreaded C++ project from scratch was tough. A lot of my first ideas completely failed, and I had to learn how things actually work to fix them. Here are the biggest challenges I faced and the "aha!" moments that solved them.

---

## 1. Multithreading Made My Code Slower!

**The Challenge:**
When I first added Worker threads, I used one big `std::unordered_map` (Hash Map) in the middle of the code to keep track of network connections. Because multiple threads were using it, I had to use a `std::mutex` lock so they wouldn't corrupt the data. 
But when I tested it, running 4 threads was actually *slower* than running 1 thread! I realized the threads were spending all their time just waiting in line for the lock. The CPU was busy, but no actual work was getting done.

**The Solution:**
I had an "aha!" moment: what if the threads didn't share data at all? 
I created a Load Balancer thread that uses a math formula (a Hash) based on the IPs. This guarantees that all packets for a specific connection always go to the *exact same Worker*. Because the Worker is the only one touching its data, I deleted the Mutex lock entirely. Suddenly, the speed multiplied perfectly with the number of threads!

---

## 2. Running Out of RAM (OOM Crashes)

**The Challenge:**
Reading a file from an SSD is super fast, but deep packet inspection (searching for text in the payload) takes a bit more time. 
In my first version, the Reader thread just pushed packets into a standard queue as fast as it could. The poor Worker threads couldn't keep up. The queue grew to millions of packets, eating up all my computer's RAM in seconds, and the operating system crashed the program.

**The Solution:**
I learned about a concept called "Backpressure." I wrote a custom Queue class that has a maximum limit (like 10,000 items). If the queue is full, the thread trying to add to it automatically goes to sleep. This naturally slows down the fast Reader thread so it matches the speed of the Worker threads. My RAM usage stayed perfectly flat after that.

---

## 3. The Hidden Cost of Copying Data

**The Challenge:**
Even after fixing the locks, I felt the code should be faster. I did some reading and realized a major mistake: every time a packet moved from the Reader -> Load Balancer -> Worker, C++ was making a complete copy of the 1500-byte data buffer. Millions of copies were happening every second, destroying my performance.

**The Solution:**
I had to learn how C++11 "Move Semantics" work. By wrapping my packets in `std::move()`, I told C++ to just hand over the *pointer* to the data, rather than copying the data itself. It was amazing to realize that the physical data in RAM stayed in the exact same spot from the moment it was read to the moment it was destroyed. It drastically reduced CPU usage.

---

## 4. Endianness: Why was Port 443 showing up as 47105?

**The Challenge:**
I wanted to parse the packets really fast, so I casted the raw memory bytes directly into a C++ Struct. 
But when I tried to print out the Destination Port, a web packet that should have been port `443` was printing out as `47105`. I thought my code was broken.

**The Solution:**
I learned that network traffic is sent in "Big-Endian" format, but my computer's CPU reads memory in "Little-Endian" format. The bytes were literally backward! 
I wrote simple, portable helper functions (`netToHost16`) that swap the bytes back to normal. It was a great lesson in how hardware architecture affects low-level programming.

---

## 5. The "Hanging" Program Deadlock

**The Challenge:**
When the Reader thread finished reading all the packets in the file, it would close successfully. But the program itself just stayed open and hung forever! I had to press `Ctrl+C` to force it to close.

**The Solution:**
I realized the Worker threads were stuck asleep. They were waiting on the queues for new packets, but since the file was done, no new packets were ever going to arrive. 
I fixed this by adding a `shutdown()` method to my queues. When the main thread finishes, it sets a flag and calls `notify_all()`. This acts like an alarm clock, forcefully waking up all the sleeping threads so they can see the flag, realize it's time to go home, and cleanly exit the program.
