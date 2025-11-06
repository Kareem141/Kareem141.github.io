---
title: Network Attacks:DOS Attacks
date: 2025-10-30 03:30:34 +0200
categories: [SOC Investigation]
tags: [soc, investigation, network, ddos]
---
# Overview of DoS Attacks
***
A Denial-of-Service (DoS) attack is a cyber threat where an attacker disrupts the availability of a service, system, or network by flooding it with excessive traffic or exploiting vulnerabilities to consume resources. This makes it unavailable to legitimate users. DoS attacks can target hardware (e.g., CPU, memory), software, or network bandwidth. They differ from DDoS attacks, which involve multiple sources (e.g., botnets) for greater scale, but the principles overlap.

DoS attacks are broadly categorized into two main types based on your notes: **Local DoS** (internal resource exhaustion) and **Network DoS** (external traffic-based disruption). Network DoS further divides into malformed packet attacks and volume-based attacks.

# 1. Local DoS Attacks
***
Local DoS attacks occur when an attacker has physical or logical access to the target machine or network (e.g., as an insider or via initial compromise). The goal is to exhaust local resources like CPU, memory, or disk space, rendering the system unresponsive to normal operations. These are less common in public discussions compared to network-based DoS but are effective in targeted environments like corporate servers.

### Key Characteristics and Methods

- **Target**: Primarily servers or workstations where the attacker can gain elevated access.
- **Mechanism**: The attacker deploys malicious tools or processes that run with high priority, monopolizing system resources and preventing other services from functioning. For example:
    - Tools like "CPU Hog" or custom scripts can be uploaded and executed to consume CPU cycles.
    - On Windows systems, these tools can be set to run at priority level 15 (the highest real-time priority), which starves lower-priority processes like user applications or system services. This can cause the OS to become unstable or crash.
- **Common Scenarios**: Often seen in server environments, such as enterprise networks where an attacker has compromised credentials. It can also involve fork bombs (e.g., in Unix-like systems) that recursively spawn processes to exhaust memory.
- **Additional Clarification**: Unlike network DoS, local DoS doesn't rely on external traffic; it's more like a "resource starvation" attack from within. Mitigation includes access controls (e.g., least privilege principles), process monitoring tools (e.g., Windows Task Manager or Linux's `top` command), and endpoint detection software to identify anomalous high-priority processes.

### Detection and Investigation

- Monitor for sudden spikes in CPU or memory usage from unknown processes.
- Use tools like antivirus software or intrusion detection systems (IDS) to scan for injected malware.

![DOS Attacks](assets/img/soc/dos/do1.png)

# 2. Network DoS Attacks
***
Network DoS attacks originate from external sources and target the network infrastructure or connectivity. They aim to overwhelm bandwidth, processing power, or protocol handling capabilities. These are divided into two subtypes: Malformed Packet Attacks (exploiting protocol flaws) and Volume-Based Attacks (flooding with legitimate-looking traffic). Attackers often spoof IP addresses to hide their origin and amplify impact, especially in volumetric variants.

## 2.1 Malformed Packet Attacks
***
These attacks send specially crafted (malformed) packets that exploit vulnerabilities in network protocols or software, causing the target to crash, reboot, or become unresponsive while processing them. The volume is typically low, but the impact is high due to the packets' design.

- **Mechanism**: Packets are altered to be invalid or oversized, triggering errors in the target's parsing logic. Examples include:
    - **Ping of Death**: Oversized ICMP packets that exceed the maximum IP packet size (65,535 bytes), causing buffer overflows.
    - **Teardrop Attack**: Fragmented packets with overlapping offsets that the target can't reassemble properly, leading to crashes.
- **Additional Clarification**: Modern systems are patched against many classic malformed attacks (e.g., via updated OS kernels), but new variants emerge. These are protocol-specific, often targeting TCP/IP stack weaknesses.
- **Detection and Mitigation**: Use firewalls or intrusion prevention systems (IPS) to inspect and drop malformed packets. Tools like Wireshark can analyze packet structures for anomalies.

## 2.2 Volume-Based Attacks (Flood Attacks)
***
These involve sending a massive volume of traffic to saturate the target's bandwidth or resources, making it unable to handle legitimate requests. Measured in bits per second (bps) or packets per second (pps), they can be amplified using reflection techniques. Attackers spoof IPs to distribute the flood and evade tracing, often from unexpected geographic locations (e.g., connections from countries unrelated to your business). Key metrics for investigation include sent/received bytes and packets.

### Examples of Volume-Based Attacks

- **SYN Flood**:
    - **Mechanism**: Targets the TCP handshake process. The attacker sends SYN packets to initiate connections, the server responds with SYN-ACK, but the attacker never sends the final ACK, leaving half-open connections that exhaust the server's connection table (backlog queue). This is a classic volumetric DoS when spoofed from multiple IPs.
    - **Additional Clarification**: Common on web servers; can lead to thousands of incomplete connections. Variants include ACK floods or RST floods.
    - **Detection and Investigation**:
        - Use perimeter firewalls to monitor SYN packets without corresponding ACKs.
        - Look for sequential patterns in logs, e.g., connection IDs like 1051, 1052, 1053... indicating automated flooding.
        - Analyze sent bytes/packets for spikes; unexpected source countries or spoofed IPs are red flags.
        - Tools: NetFlow analysis or SYN cookies (a mitigation technique where the server doesn't allocate resources until ACK is received).
- **DNS Amplification**:
    - **Mechanism**: A reflection/amplification attack where the attacker spoofs the victim's IP in DNS queries to open resolvers (public DNS servers). The resolvers respond with much larger answers (e.g., full DNS zone transfers) to the victim, multiplying traffic volume (amplification factor up to 50x or more).
    - **Additional Clarification**: Exploits DNS protocol's request-response asymmetry. Often combined with botnets for DDoS scale.
    - **Detection and Investigation**:
        - Monitor incoming packets at the firewall for high-volume UDP traffic on port 53 (DNS) from various source ports.
        - Check received bytes: Bursts >1MB/s are suspicious, especially if queries are small but responses are large.
        - Look for patterns like repeated queries from diverse IPs spoofing the victim. Mitigation: Rate-limit DNS responses or use DNSSEC.
- **HTTP Flood**:
    - **Mechanism**: An application-layer (Layer 7) attack where the attacker (often via botnets) sends a flood of HTTP GET/POST requests to a specific URL or resource on the web server, exhausting server resources like CPU for processing dynamic content (e.g., database queries). Unlike lower-layer floods, it mimics legitimate traffic.
    - **Additional Clarification**: Targets web applications; slow HTTP attacks (e.g., Slowloris) keep connections open longer to tie up threads. Normal user behavior involves varied URLs, but attackers focus on resource-intensive ones.
    - **Detection and Investigation**:
        - Analyze web server logs for IPs from the same subnet, ASN (Autonomous System Number), or country repeatedly accessing the same URL.
        - Monitor received bytes for unusual spikes tied to HTTP traffic.
        - Tools: Web Application Firewalls (WAF) with behavioral analysis; look for high request rates without corresponding user agents or sessions. Mitigation: CAPTCHA challenges or rate limiting per IP.

![DOS Attacks](assets/img/soc/dos/do2.png)

> To investigate any DoS, focus on traffic anomalies:
> - **Metrics**: Sent/received bytes, packets per second, connection rates.
> - **Tools**: Firewalls (e.g., perimeter firewalls), SIEM systems, or traffic analyzers like tcpdump.
> - **Best Practices**: Implement rate limiting, traffic scrubbing services (e.g., Cloudflare), and redundancy (e.g., load balancers). Always patch systems to prevent malformed packet exploits.
{: .prompt-tip }