---
title: Microsoft Events Log Analysis:Logon And Logoff Events Analysis
date: 2025-10-29 03:30:31 +0200
categories: [SOC Investigation]
tags: [soc, investigation, logs, event, microsoft, id]
---
# Key Event IDs for Logon and Logoff Analysis
***
Event IDs are the primary way to identify logon success, failure, or logoff. Here's a summary table of the most relevant ones:
<table>
    <thead>
        <tr>
            <th style="text-align: left">Event ID</th>
            <th style="text-align: left">Description</th>
            <th style="text-align: left">When It Occurs</th>
            <th style="text-align: left">Key Use in Analysis</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">4624</td>
            <td style="text-align: left">An account was successfully logged on</td>
            <td style="text-align: left">Successful authentication (e.g., login to a machine or network resource)</td>
            <td style="text-align: left">Track successful sessions; correlate with logoff for duration.</td>
        </tr>
        <tr>
            <td style="text-align: left">4625</td>
            <td style="text-align: left">An account failed to log on</td>
            <td style="text-align: left">Failed authentication attempt</td>
            <td style="text-align: left">Identify reasons for failure (e.g., brute force attacks); monitor for patterns.</td>
        </tr>
        <tr>
            <td style="text-align: left">4634</td>
            <td style="text-align: left">An account was logged off</td>
            <td style="text-align: left">User or system initiates logoff sequence (may not always complete)</td>
            <td style="text-align: left">Match with 4624's Logon ID to calculate session duration; note if paired with 4647.</td>
        </tr>
        <tr>
            <td style="text-align: left">4647</td>
            <td style="text-align: left">User initiated logoff</td>
            <td style="text-align: left">Logon session is fully terminated (complements 4634)</td>
            <td style="text-align: left">Confirms complete logoff; useful for tracking full session lifecycle.</td>
        </tr>
    </tbody>
</table>

# Common Fields in Logon and Logoff Events
***
- **Event ID**: It distinguishes success (4624) from failure (4625) or logoff (4634/4647). Always filter logs by these IDs for targeted analysis.
- **Account Name**: The username attempting to log on. In a domain environment (e.g., Active Directory), it's often in the format `username` (e.g., `kim.john` for user Kim John in domain `abc.com`). The full account might appear as `abc\kim`.john or `kim.john@abc.com`. This field helps identify who is logging in; monitor for suspicious names (e.g., non-existent or external accounts).
- **Account Domain**: Often paired with Account Name; specifies the domain (e.g., abc.com). If blank or "NT AUTHORITY," it indicates a local system account.
- **Logon Type**: Indicates how the user logged in, which is crucial for understanding the context (e.g., local vs. remote access). Common types include:
  - Type 2:Interactive (e.g., at the console or via Ctrl+Alt+Del).
  - Type 3:Network (e.g., accessing a shared folder via SMB; no password prompt if trusted).
  - Type 7:Unlock (after screen lock).
  - Type 10:RemoteInteractive (e.g., RDP/Terminal Services).
  - Type 9:NewCredentials (explicit credentials, like "run as administrator" for elevated privileges). High volumes of Type 3 events can indicate normal network activity but also potential lateral movement in attacks.3 Logon types are listed in the event details for 4624 and 4625.
- **Caller Process ID (or Subject Process ID)**: The process ID (PID) and name of the process that initiated the logon attempt.For example:
  - `winlogon.exe` for console logins.
  - `lsass.exe` for service or network logons.
  - `svchost.exe` for system processes. This helps trace what software or service triggered the logon. In failures (4625), a suspicious PID might indicate malware.
- **Process ID (Logon Process)**: Related to Caller Process ID; this is the authentication package used (e.g., `NtLmSsp` for NTLM, `Kerberos` for domain auth, `Winsta` for workstation). It specifies the technical method of authentication. For instance, `Kerberos` is typical in domain environments like `abc.com example`.
- **Workstation Name**: The DNS or NetBIOS name of the source computer (e.g., fully qualified domain name like `myworkstation.abc.com` for the machine from which `kim.john` is logging in). This is especially useful for remote logons; it helps geolocate or verify the device (e.g., is it a company laptop?). In event details, it's under "Workstation name" or "Computer Name."
- **Source Network Address**: The IP address of the machine or network source initiating the logon (e.g., `192.168.1.100` for `kim.john`'s workstation). For local logons, it might be empty or ::1 (localhost). This is critical for detecting external threats (e.g., logons from unknown IPs). Pair it with Workstation Name for full context.
- **Logon ID**: A unique hexadecimal identifier for the session (e.g., `0x12345678`). Search for this ID in a successful 4624 event, then match it in the corresponding 4634/4647 logoff event to calculate session duration (e.g., subtract timestamps). This is invaluable for tracking user activity timelines. If durations are unusually short, it might indicate automated scripts or attacks.
- **Explicit Credentials (or RunAs/NewCredentials)**: Refers to scenarios where a user provides elevated credentials, often tied to Logon Type 9. For example "run as administrator"—this occurs when a program needs higher privileges (e.g., via `runas` command or UAC prompt). In the event, look for "Authentication Package" as `Negotiate` or similar. Monitor for abuse, as attackers might use this for privilege escalation.
- **Status and Sub-Status (for Failures Only)**: Exclusive to 4625 events; these codes explain why the logon failed. reasons like "password expired" or "incorrect password". Here's a table of common codes for clarity:

<table>
    <thead>
        <tr>
            <th style="text-align: left">Status Code</th>
            <th style="text-align: left">Sub-Status Code</th>
            <th style="text-align: left">Failure Reason</th>
            <th style="text-align: left">Possible Causes/Analysis Tips</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">0xC000006D</td>
            <td style="text-align: left">0xC000006A</td>
            <td style="text-align: left">Incorrect password</td>
            <td style="text-align: left">User mistyped; or brute-force attack (check for rapid repeats from same IP).</td>
        </tr>
        <tr>
            <td style="text-align: left">0xC0000064</td>
            <td style="text-align: left">N/A</td>
            <td style="text-align: left">User does not exist</td>
            <td style="text-align: left">could be a typo or attacker probing non-existent usernames (brute force). High volume suggests scanning attacks.</td>
        </tr>
        <tr>
            <td style="text-align: left">0xC0000072</td>
            <td style="text-align: left">N/A</td>
            <td style="text-align: left">Account disabled</td>
            <td style="text-align: left">Account locked due to policy, vacation, or compromise (e.g., attacker sold credentials on dark web). Investigate recent changes or external access attempts.</td>
        </tr>
        <tr>
            <td style="text-align: left">0xC0000071</td>
            <td style="text-align: left">N/A</td>
            <td style="text-align: left">Password expired</td>
            <td style="text-align: left">Routine policy enforcement; remind user to change password.</td>
        </tr>
        <tr>
            <td style="text-align: left">0xC000015B</td>
            <td style="text-align: left">N/A</td>
            <td style="text-align: left">Logon time restriction</td>
            <td style="text-align: left">Attempt outside allowed hours; could be legitimate off-hours work or insider threat.</td>
        </tr>
        <tr>
            <td style="text-align: left">0xC0000193</td>
            <td style="text-align: left">N/A</td>
            <td style="text-align: left">Account locked out</td>
            <td style="text-align: left">Multiple failures; often from brute force. Review preceding 4625 events.</td>
        </tr>
    </tbody>
</table>

These codes are in hexadecimal in the event XML/details. A surge in 4625 events (e.g., hundreds from one IP) often signals brute-force attacks. Always cross-reference with Source Network Address.

![Microsoft Events Log](assets/img/soc/ms/ms1.png)

# Analyzing Logon Success (Event ID 4624)
***
Focus on verifying legitimate access:
- Use Account Name, Workstation Name, and Source Network Address to confirm the user's device and location (e.g., `kim.john` from `myworkstation.abc.com` at `192.168.1.100`).
- Note Logon Type for context (e.g., Type 3 for SMB shared folder access).
- Record Logon ID for later duration tracking.
- Anomalies: Unusual Logon Types (e.g., Type 10 RDP from external IP) or high volumes could indicate lateral movement in an attack.

# Analyzing Logon Failure (Event ID 4625)
***
This is where security threats often show up:
- Prioritize Status/Sub-Status to pinpoint the reason (as in the table above).
- For non-existent usernames: Check frequency—if sporadic, likely user error; if patterned (e.g., sequential guesses), suspect brute force.
- For disabled accounts: investigate if the account was recently disabled (e.g., via AD logs) or if there's evidence of compromise (e.g., prior successful logons from odd locations).
- Trace Source Network Address and Workstation Name to the origin—e.g., failures from unknown IPs suggest external attacks.

> Tip: Filter for repeats from the same Source Network Address to detect automated attempts.
{: .prompt-tip }

# Analyzing Logoff Events (Event IDs 4634 and 4647)
***
These confirm session closure:
- Match Logon ID from 4624 to calculate duration (e.g., via timestamp difference: `Logoff Time - Logon Time`).
- Logon Type and Source details should match the original logon for consistency.
- If a 4634 appears without a 4647, the session might have been interrupted (e.g., crash or forced logoff).
- In logoff events, revisit the paired 4624/4625 to trace the session's origin (Workstation Name/IP). This helps if a failure led to a short/aborted session—e.g., a brute-force attempt that partially succeeded then failed.
- Anomalies: Unexpected short sessions or logoffs from different locations than logon could indicate session hijacking.

# Additional Tips
***
- **Session Duration Calculation: Use PowerShell**: `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4634} | Where-Object {$_.Message -match 'Logon ID: 0x[0-9A-F]+'}` then correlate IDs. Short durations (<1 minute) might be probes; long ones could be persistent access.
- **Common Pitfalls**: High volumes of 4624/4634 (e.g., Type 3) are normal on file servers but monitor for spikes. RDP-related events (Type 10) are key for remote access investigations.
- **Security Best Practices**: Enable detailed auditing, use baselines to spot anomalies (e.g., via Microsoft Defender or Splunk), and correlate with other logs (e.g., 4672 for privilege use). For attacks, look for 4625 clusters followed by successful 4624 (e.g., password spraying).
- **Tools for Deeper Dive**: Event Viewer for basics; for advanced, use wevtutil or third-party parsers. If analyzing large logs, export to CSV and use Excel/Power BI for timelines.