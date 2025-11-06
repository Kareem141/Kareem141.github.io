---
title: IPS/IDS Alerts Investigation
date: 2025-10-31 03:30:30 +0200
categories: [SOC Investigation]
tags: [soc, investigation, ips, ids]
---
Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) are critical security tools that monitor network traffic for suspicious or malicious activities. An IDS detects potential threats by analyzing traffic patterns and signatures, generating alerts for further investigation, while an IPS goes a step further by actively blocking or preventing the detected threats. Investigating alerts involves systematically analyzing key fields in the alert logs (often via a Security Information and Event Management (SIEM) tool) to determine if the activity is benign, a false positive, or an actual attack. This includes correlating logs from IPS/IDS, firewalls, and network traffic to build a timeline of events, test hypotheses (e.g., command injection or exploitation attempts), and check for patterns like repeated attempts or evasion techniques.

# 1. Source IP Address
***
The Source IP field identifies the origin of the network connection or traffic that triggered the alert. This is crucial for tracing the initiator of the activity and assessing risk based on the direction of traffic.

- **Typical Scenarios**:
    - **Server as Source**: If the source is an internal server (e.g., sending traffic to a client or another server), this is often normal for legitimate operations like updates or services. Server-to-client or server-to-server traffic is common in enterprise environments and less likely to indicate an attack unless accompanied by unusual payloads.
    - **Client as Source**: This raises higher suspicion, especially if it's client-to-server traffic. An attacker (e.g., from an external or compromised client) may be attempting to exploit a vulnerability in the target server, triggering an IPS/IDS signature. Investigate for signs of reconnaissance, exploitation, or lateral movement.
- **Investigation Steps**:
    - Filter logs by source IP (e.g., `data.srcip` in SIEM) and count distinct sources to identify patterns, such as multiple IPs attempting the same attack.
    - Check if the IP is internal (e.g., via subnet analysis) or external (e.g., geolocation or WHOIS lookup). For external sources, query threat intelligence platforms (e.g., AlienVault OTX or VirusTotal) to see if it's associated with known attackers or APT groups.
    - Correlate with firewall logs for prior connections from this IP. If it's a repeated source for alerts, it could indicate a persistent threat actor testing defenses.
    - **More Clarity**: Always verify if the source IP belongs to a legitimate user or device (e.g., via asset inventory). If it's a compromised internal host, look for signs like unusual user agents or command execution in endpoint logs.

> **Risk Indicator**: High risk if client-to-server with a matching exploit signature, as it suggests active targeting of vulnerabilities.
{: .prompt-danger }

# 2. Source Port
***
The Source Port field specifies the port number from which the connection originates on the source device. Ports are ephemeral (dynamically assigned) for clients but fixed for servers.

- **Explanation and Investigation**:
    - This port helps identify the application or service initiating the traffic. For example, a source port in the high range (e.g., >1024) is typical for client-side connections, while low ports (e.g., 80 for HTTP) might indicate server responses.
    - **Investigation Steps**: Cross-reference with known port assignments (e.g., using IANA port lists). If the port is unusual for the source IP (e.g., a client using a privileged port like 22 for SSH), it could indicate spoofing or evasion. Analyze the protocol (TCP/UDP) alongside the port to understand the traffic type.
    - **More Clarity**: Ports alone rarely trigger alerts but provide context for the full 5-tuple (source IP/port, destination IP/port, protocol). In attacks, attackers may use non-standard source ports to blend with normal traffic or evade port-based filtering.

# 3. Destination IP Address
***
The Destination IP field indicates the target of the traffic, helping pinpoint what (or who) is being attacked.

- **Typical Scenarios**:
    - **Server as Destination**: Common for inbound attacks, where external traffic targets a server hosting services like web apps or databases.
    - **Client-to-Client or Server-to-Server**: These are often internal and legitimate but warrant scrutiny if unexpected. Client-to-client traffic is abnormal in segmented networks and could indicate lateral movement (e.g., worm propagation).
    - **Web Application or Other Targets**: If the destination is a web server or application, check for HTTP/HTTPS-specific exploits.
- **Investigation Steps**:
    - Filter by destination IP (e.g., `data.dstip`) to count distinct targets and review if the attack was blocked (`data.action: block`) or allowed (`data.action: alert`).
    - Map the IP to assets (e.g., is it a critical server?). For internal destinations, check access controls (e.g., was this connection authorized?).
    - Correlate with endpoint logs on the destination for signs of compromise, such as unusual processes or file changes.
    - **More Clarity**: Use network diagrams to visualize flows. If the destination is a high-value asset (e.g., top management workstation), prioritize investigation, as it may indicate targeted phishing or privilege escalation.

> **Risk Indicator**: Elevated if the destination is an unusual or sensitive system, especially with a signature match.
{: .prompt-danger }

# 4. Destination Port
***
The Destination Port field reveals the specific service or application the traffic is targeting, providing insight into the attacker's intent.

- **Explanation and Investigation**:
    - Ports map to services (e.g., 80/443 for web, 3389 for RDP). Attackers often probe common ports for vulnerabilities (e.g., port 445 for SMB exploits like EternalBlue).
    - **Investigation Steps**: Identify the service via port number and check if it's running on the destination IP (e.g., using Nmap scans in a controlled environment). Review if the port aligns with expected traffic—e.g., inbound to port 22 (SSH) from an unknown source is suspicious.
    - **More Clarity**: Attackers may scan multiple ports to fingerprint services (e.g., testing if a vulnerable version of Apache is present). Always verify the service's vulnerability status using tools like CVE databases before dismissing an alert. Modern IPS/IPS can detect port-knocking or tunneling attempts on non-standard ports.

> **Risk Indicator**: High if targeting a known vulnerable service (e.g., outdated software on that port).
{: .prompt-danger }

# 5. Signature Name
***
The Signature Name field describes the specific rule or pattern that triggered the alert, based on known attack signatures (e.g., "SQL Injection Attempt" or "OS.Command.Injection.Attempt").

- **Key Considerations**:
    - **External Traffic (Out-to-In)**: Check for repeated signatures from the same source IP, indicating persistent scanning or exploitation attempts. Attackers may use the same code to test if your environment runs a specific product/service (e.g., probing for Microsoft IIS vulnerabilities).
    - **Internal Traffic**: If multiple signatures trigger from one machine to another, it strongly suggests an internal attack, such as malware spreading or lateral movement.
    - **General Advice**: Before querying if the target is vulnerable, confirm the service/product in use (e.g., via asset management). Update signature databases regularly to catch variants.
- **Investigation Steps**:
    - Filter logs by signature (e.g., `data.attack: [signature name]`) to count events and check for unblocked instances (`data.action: alert`).
    - Correlate with vulnerability scanners (e.g., Nessus) to see if the target service matches known CVEs associated with the signature.
    - Look for evasion (e.g., obfuscated payloads) or zero-day indicators if the signature doesn't fully match.
    - **More Clarity**: Signatures are pattern-based (e.g., matching packet headers like IPs/ports) but can be bypassed; combine with anomaly detection for better coverage. If repeated, it may be reconnaissance—e.g., testing for a specific product before a full exploit.

> **Risk Indicator**: Repeated or multi-signature alerts from internal sources indicate a likely compromise.
{: .prompt-danger }

# 6. Fragmentation
***
Fragmentation refers to splitting IP packets into smaller pieces to traverse networks with varying MTU sizes, but attackers exploit it to evade detection.

- **Explanation**:
    - **Evasion Technique**: By fragmenting malicious payloads (e.g., overlapping or out-of-order fragments), attackers make it harder for older IDS/IPS to reassemble and inspect the full packet, potentially bypassing signatures. This is common in DDoS or exploit attempts.
    - **Modern Detection**: Current IPS/IDS systems are "smart" enough to perform reassembly and detect fragmentation-based evasion, often triggering dedicated alerts (e.g., "IP Fragmentation Attack").
- **Investigation Steps**:
    - If an alert mentions fragmentation (e.g., in packet details), review the full session for malicious content post-reassembly. Check for abnormal fragment counts or sizes.
    - Correlate with traffic volume—if high fragmentation coincides with spikes, it could be a DDoS variant.
    - **More Clarity**: Not all fragmentation is malicious (e.g., legitimate large file transfers), but combined with a signature, it's a red flag. Use tools like Wireshark for deep packet inspection to verify.

> **Risk Indicator**: An alert for fragmentation attempts suggests an active evasion effort, warranting immediate blocking of the source.
{: .prompt-danger }

# 7. Abnormal Connections and Patterns
***
Beyond individual fields, look for deviations from baseline network behavior, as these often signal attacks even without a perfect signature match.

- **Key Scenarios**:
    - **Client-to-Client Connections**: These are abnormal in well-segmented networks (e.g., via VLANs or firewalls) and could indicate peer-to-peer malware, unauthorized sharing, or internal scanning.
    - **Normal Client to Sensitive Targets (e.g., Top Management)**: Traffic from a standard user/client to a high-privilege system (e.g., executive laptop) is a strong attack indicator, possibly privilege escalation or data theft.
    - **Connection + Signature**: Any anomalous connection paired with a triggered signature (e.g., unusual port + exploit attempt) points to malice.
    - **Other Patterns**: Off-hours spikes, unexpected protocols, or high-volume traffic from new sources.
- **Investigation Steps**:
    - Establish baselines (e.g., normal traffic flows via historical logs) and filter for deviations (e.g., `data.action: accept` for allowed abnormals).
    - **Correlate across logs**: Check firewall for blocks, endpoint for processes, and SIEM for timelines. Use anomaly detection to flag outliers like sudden external connections.
    - **More Clarity**: Abnormalities often stem from compromised hosts (e.g., backdoors). In internal attacks, look for multiple signatures or chained events (e.g., reconnaissance followed by exploitation). Prioritize based on impact—e.g., to critical assets.

> **Risk Indicator**: Client-to-client or to sensitive targets, especially with signatures, demands urgent response like isolation.
{: .prompt-danger }