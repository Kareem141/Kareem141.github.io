---
title: Web Server & WAF Logs
date: 2025-10-30 03:30:36 +0200
categories: [SOC Investigation]
tags: [soc, investigation, network, waf, web server, logs]
---
Web Application Firewalls (WAFs) and web servers generate logs that are crucial for monitoring, detecting, and responding to traffic. WAF logs focus on security events, distinguishing between **legal requests** (normal, benign traffic like standard HTTP methods such as GET or POST) and **illegal requests** (malicious attempts like SQL injection, Cross-Site Scripting (XSS), or other exploits). Web server logs, on the other hand, record all incoming traffic without inherent security filtering—they treat everything as potentially legal and require additional analysis (e.g., via threat intelligence or response code patterns) to identify anomalies.

# 1. WAF Logs: Overview and Analysis
***
WAFs act as a protective layer in front of web applications, inspecting traffic for threats using rules, signatures (predefined patterns for known attacks), and policies. Logs capture events where traffic is evaluated—legal requests are typically allowed, while illegal ones may trigger blocks, alerts, or logging for review. The **Event Name** is often the entry point: it flags the request type (e.g., "GET" for legal or "SQL Injection Attempt" for illegal). If it's generic (e.g., "Illegal Request"), drill down into sub-fields like **Violation Type** for specifics.

WAF logs help in:

- Identifying attack patterns (e.g., brute-force attempts or injection probes).
- Geofencing suspicious traffic.
- Auditing policy exceptions (e.g., why a known violation was allowed).

Key fields are summarized in the table below:

<table>
    <thead>
        <tr>
            <th style="text-align: left">Field</th>
            <th style="text-align: left">Description</th>
            <th style="text-align: left">Why It Matters / Analysis Tips</th>
            <th style="text-align: left">Examples / Common Values</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">Event Name</td>
            <td style="text-align: left">Indicates the overall nature of the request (legal or illegal).</td>
            <td style="text-align: left">Serves as the high-level alert; generic names like "Illegal Request" require further investigation via sub-fields. Legal events confirm normal operations; illegal ones signal potential threats.</td>
            <td style="text-align: left">Legal: "HTTP GET", "HTTP POST". Illegal: "SQL Injection", "XSS Attempt", "Illegal Request" (generic).</td>
        </tr>
        <tr>
            <td style="text-align: left">Violation Type</td>
            <td style="text-align: left">Specifies the exact type of security violation if detected.</td>
            <td style="text-align: left">Pinpoints the threat category, allowing targeted responses (e.g., updating rules for that type). Not present or empty for legal requests.</td>
            <td style="text-align: left">"SQL Injection", "XSS (Cross-Site Scripting)", "Command Injection", "Path Traversal".</td>
        </tr>
        <tr>
            <td style="text-align: left">Signature Name</td>
            <td style="text-align: left">The name of the predefined rule or pattern (signature) that matched the violation.</td>
            <td style="text-align: left">Helps trace how the WAF detected the threat; useful for tuning rules or false positive reduction. Only populated if a signature-based detection occurred.</td>
            <td style="text-align: left">"SQLi-1-1", "XSS-Filter-Generic", "ModSecurity CRS Rule 942100".</td>
        </tr>
        <tr>
            <td style="text-align: left">Source IP</td>
            <td style="text-align: left">The IP address of the originating client.</td>
            <td style="text-align: left">Detects suspicious sources; compare against expected traffic patterns (e.g., flag IPs from unexpected countries via threat intel feeds like IP reputation databases).</td>
            <td style="text-align: left">"192.0.2.1" (IPv4) or "2001:db8::1" (IPv6). Suspicious if from high-risk regions like known botnet sources.</td>
        </tr>
        <tr>
            <td style="text-align: left">Source Geolocation</td>
            <td style="text-align: left">Geographic origin of the Source IP (e.g., country, city).</td>
            <td style="text-align: left">Enables geoblocking; unexpected locations (e.g., traffic from a sanctioned country when expecting only US/EU) raise red flags for attacks or compromised users. Derived from IP geolocation databases like MaxMind.</td>
            <td style="text-align: left">"United States, New York" or "Russia, Moscow". Use with Source IP for correlation.</td>
        </tr>
        <tr>
            <td style="text-align: left">Source Port</td>
            <td style="text-align: left">The port number used by the source for the connection.</td>
            <td style="text-align: left">Less commonly analyzed but useful for protocol-specific attacks (e.g., non-standard ports indicating tunneling).</td>
            <td style="text-align: left">"54321" (ephemeral port for client-side connections).</td>
        </tr>
        <tr>
            <td style="text-align: left">Method</td>
            <td style="text-align: left">The HTTP method used in the request.</td>
            <td style="text-align: left">Legal methods are standard; unusual ones (e.g., TRACE or OPTIONS in excess) can indicate reconnaissance. Attack tools often default to GET for simplicity.</td>
            <td style="text-align: left">"GET", "POST", "PUT", "DELETE".</td>
        </tr>
        <tr>
            <td style="text-align: left">Response</td>
            <td style="text-align: left">The HTTP status code returned by the WAF or server.</td>
            <td style="text-align: left">Focus on errors for anomalies: 4xx/5xx codes may indicate probes for vulnerabilities. Legal requests often get 200 (OK).</td>
            <td style="text-align: left">200 (Allowed/Success), 400 (Bad Request—attacker requesting non-existent resources), 403/407 (Forbidden/Proxy Authentication Required—insufficient privileges), 500 (Internal Server Error—server-side issue, possibly exploited).</td>
        </tr>
        <tr>
            <td style="text-align: left">Destination IP</td>
            <td style="text-align: left">The IP address of the target server or application.</td>
            <td style="text-align: left">Identifies which backend service was targeted; useful for segmenting logs by asset (e.g., web app vs. API).</td>
            <td style="text-align: left">"203.0.113.1" (your server's IP).</td>
        </tr>
        <tr>
            <td style="text-align: left">Destination Port</td>
            <td style="text-align: left">The port on the destination used for the request.</td>
            <td style="text-align: left">Helps map to services (e.g., port 80/443 for HTTP/HTTPS); unusual ports may signal port-scanning attacks.</td>
            <td style="text-align: left">"443" (HTTPS), "80" (HTTP).</td>
        </tr>
        <tr>
            <td style="text-align: left">Device Action</td>
            <td style="text-align: left">The action taken by the WAF (e.g., block, allow, or log).</td>
            <td style="text-align: left">Shows enforcement: blocks prevent attacks, but "allow" on violations might indicate an exception (check Policy or logs for reasons like whitelisting). Admins may permit certain violations for legitimate testing.</td>
            <td style="text-align: left">"Blocked", "Allowed", "Logged Only".</td>
        </tr>
        <tr>
            <td style="text-align: left">Requested URL</td>
            <td style="text-align: left">The full URL path and query string of the request (includes potential violation payload).</td>
            <td style="text-align: left">Core field for violation details: inspect for encoded attacks (e.g., in query params for GET or body for POST). Tools like SQLMap often use GET requests with payloads in URLs; POST violations hide in request bodies.</td>
            <td style="text-align: left">"/login.php?id=1' OR '1'='1" (SQL injection attempt). Use URL decoding tools for analysis.</td>
        </tr>
        <tr>
            <td style="text-align: left">Referrer</td>
            <td style="text-align: left">The URL of the page that linked to the requested URL (HTTP Referer header).</td>
            <td style="text-align: left">Detects phishing or referral-based attacks; empty or suspicious referrers (e.g., from malware sites) are red flags.</td>
            <td style="text-align: left">"https://evil.com/phish" or empty (direct access, common in automated attacks).</td>
        </tr>
        <tr>
            <td style="text-align: left">URL</td>
            <td style="text-align: left">Similar to Requested URL; may refer to the normalized or canonical URL.</td>
            <td style="text-align: left">Consolidated with Requested URL for redundancy; use for pattern matching across events.</td>
            <td style="text-align: left">Same as Requested URL, but without query params (e.g., "/login.php").</td>
        </tr>
        <tr>
            <td style="text-align: left">Policy</td>
            <td style="text-align: left">The WAF policy or rule set applied to the request (e.g., grouped by protected asset).</td>
            <td style="text-align: left">WAFs use modular policies for different environments; helps contextualize events (e.g., stricter rules for banking vs. public sites). Check for policy mismatches.</td>
            <td style="text-align: left">"Website Protection Policy", "Internet Banking Policy", "API Security Policy". Policies often include sub-rules for specific threats.</td>
        </tr>
        <tr>
            <td style="text-align: left">User Name</td>
            <td style="text-align: left">The authenticated username (if applicable, from headers like Authorization).</td>
            <td style="text-align: left">Critical for access control: suspicious activity from a valid user may indicate credential theft (e.g., via phishing emails). Cross-check with normal behavior or multi-factor logs.</td>
            <td style="text-align: left">"john.doe@company.com". Flag if mismatched with Source IP/Geolocation.</td>
        </tr>
        <tr>
            <td style="text-align: left">IP Geolocation</td>
            <td style="text-align: left">Geographic details tied to the IP (overlaps with Source Geolocation).</td>
            <td style="text-align: left">Redundant with Source Geolocation; use for broader threat hunting (e.g., correlating with global attack trends).</td>
            <td style="text-align: left">Same as Source Geolocation; tools like WHOIS can enrich this.</td>
        </tr>
        <tr>
            <td style="text-align: left">User Agent</td>
            <td style="text-align: left">The client software identifier (browser, tool, or bot).</td>
            <td style="text-align: left">Reveals attack vectors: legitimate browsers vs. automated tools. Suspicious agents indicate bots or scanners.</td>
            <td style="text-align: left">"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" (Chrome browser) or "sqlmap/1.7" (attack tool).</td>
        </tr>
    </tbody>
</table>

**Additional Tips for WAF Log Analysis:**

- **Correlating Fields:** Always cross-reference Source IP with User Name and Geolocation to detect account takeovers. For illegal requests, examine Requested URL and Violation Type together to reconstruct the attack (e.g., SQL injection via POST body).
- **Common Tools and Patterns:** Attackers use tools like SQLMap (for database exploits) or Burp Suite (for web vuln scanning), often generating high-volume GET requests. Monitor for rate-limiting violations.
- **Exceptions and Tuning:** If Device Action is "Allowed" on a violation, review policy exceptions—perhaps for legitimate API testing. Use SIEM tools (e.g., Splunk) to aggregate logs.
- **Enhancements:** Integrate with threat intelligence (e.g., via APIs from AlienVault OTX) to flag known malicious IPs.

# 2. Web Server Logs: Overview and Analysis
***
Web servers (e.g., Apache, Nginx, IIS) log all traffic without built-in threat detection—they assume all requests are legal unless explicitly configured otherwise (e.g., via mod_security modules). Unlike WAFs, they can't natively identify illegal requests like SQL injection; instead, rely on indirect indicators such as unusual response codes, high error rates, or external threat intel (e.g., checking Source IP against blocklists). Logs are essential for performance monitoring, debugging, and forensic analysis post-breach.

Key fields are summarized in the table below:

<table>
    <thead>
        <tr>
            <th style="text-align: left">Field</th>
            <th style="text-align: left">Description</th>
            <th style="text-align: left">Why It Matters / Analysis Tips</th>
            <th style="text-align: left">Examples / Common Values</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">Source IP</td>
            <td style="text-align: left">IP address of the client.</td>
            <td style="text-align: left">Baseline for traffic patterns; use threat intel to flag malicious IPs (e.g., via services like AbuseIPDB).</td>
            <td style="text-align: left">"192.0.2.1".</td>
        </tr>
        <tr>
            <td style="text-align: left">Destination IP</td>
            <td style="text-align: left">IP address of the server.</td>
            <td style="text-align: left">Identifies the targeted host in multi-server setups.</td>
            <td style="text-align: left">"203.0.113.1".</td>
        </tr>
        <tr>
            <td style="text-align: left">User Agent</td>
            <td style="text-align: left">Client software identifier.</td>
            <td style="text-align: left">Detects bots or unusual clients; cross-check with expected user behaviors.</td>
            <td style="text-align: left">"Mozilla/5.0..." (browser) or "curl/7.68.0" (scripted tool).</td>
        </tr>
        <tr>
            <td style="text-align: left">URL / Requested URL</td>
            <td style="text-align: left">The requested resource path/query.</td>
            <td style="text-align: left">Spot patterns like excessive requests to sensitive paths (e.g., /admin). Consolidated for duplicates.</td>
            <td style="text-align: left">"/index.html" or "/api/v1/users?id=1".</td>
        </tr>
        <tr>
            <td style="text-align: left">Response</td>
            <td style="text-align: left">HTTP status code returned.</td>
            <td style="text-align: left">Key for anomaly detection: high 4xx/5xx rates suggest attacks (e.g., 404 for scanning, 500 for exploits). Web servers log this without WAF context.</td>
            <td style="text-align: left">200 (OK), 404 (Not Found—probe for hidden files), 500 (Server Error).</td>
        </tr>
        <tr>
            <td style="text-align: left">Source Port</td>
            <td style="text-align: left">Client's outgoing port.</td>
            <td style="text-align: left">Rarely anomalous but useful for connection tracking.</td>
            <td style="text-align: left">"54321".</td>
        </tr>
        <tr>
            <td style="text-align: left">Destination Port</td>
            <td style="text-align: left">Server's listening port.</td>
            <td style="text-align: left">Confirms service (e.g., 80 for HTTP).</td>
            <td style="text-align: left">"80" or "443".</td>
        </tr>
        <tr>
            <td style="text-align: left">User Name</td>
            <td style="text-align: left">Authenticated user (if logged, e.g., via access logs).</td>
            <td style="text-align: left">Similar to WAF: check for abused credentials. Not always present in anonymous traffic.</td>
            <td style="text-align: left">"john.doe".</td>
        </tr>
    </tbody>
</table>

**Additional Tips for Web Server Log Analysis:**

- **Limitations and Enhancements:** Since web servers don't detect illegality, integrate with WAF logs or tools like Fail2Ban for automated banning. Use threat intelligence platforms (e.g., IBM X-Force) to enrich Source IP data.
- **Common Patterns:** Look for error spikes (e.g., 400+ responses from one IP) or unusual User Agents. For illegal detection, parse Requested URL for signs of injection (manual or via scripts).
- **Comparison to WAF:** Web server logs provide raw volume data; pair with WAF for security context. Enable extended logging (e.g., Apache's %h %l %u %t "%r" %>s %b) for fuller details.
- **Best Practices:** Rotate logs regularly to manage size; use tools like ELK Stack (Elasticsearch, Logstash, Kibana) for visualization and alerting on thresholds (e.g., >100 requests/min from one IP).