---
title: Microsoft Events Log Analysis:Windows Account & Group Management Events
date: 2025-10-29 03:30:33 +0200
categories: [SOC Investigation]
tags: [soc, investigation, logs, event, microsoft, id]
---
# User Account Management
***
User account management events track changes to user accounts in Active Directory (AD) or local systems, such as creation, modification, enabling/disabling, password changes, and deletions. These are vital for monitoring insider threats, unauthorized access attempts, or compliance with policies like least privilege.
### Common Event IDs
Here are the most relevant Event IDs for user account management (from the Security log):
<table>
    <thead>
        <tr>
            <th style="text-align: left">Event ID</th>
            <th style="text-align: left">Description</th>
            <th style="text-align: left">When It Occurs</th>
            <th style="text-align: left">Auditing Category</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">4720</td>
            <td style="text-align: left">A user account was created</td>
            <td style="text-align: left">New user account added (e.g., via Active Directory Users and Computers)</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4722</td>
            <td style="text-align: left">A user account was enabled</td>
            <td style="text-align: left">Disabled account reactivated</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4723</td>
            <td style="text-align: left">An attempt was made to change an account's password</td>
            <td style="text-align: left">Password change by the user or admin</td>
            <td style="text-align: left">User Account Management (Success/Failure)</td>
        </tr>
        <tr>
            <td style="text-align: left">4724</td>
            <td style="text-align: left">An attempt was made to reset an account's password</td>
            <td style="text-align: left">Admin resets a user's password</td>
            <td style="text-align: left">User Account Management (Success/Failure)</td>
        </tr>
        <tr>
            <td style="text-align: left">4725</td>
            <td style="text-align: left">A user account was disabled</td>
            <td style="text-align: left">Account deactivated (e.g., for security reasons)</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4726</td>
            <td style="text-align: left">A user account was deleted</td>
            <td style="text-align: left">User account removed</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4738</td>
            <td style="text-align: left">A user account was changed</td>
            <td style="text-align: left">Modifications to account properties (e.g., name, expiration)</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4740</td>
            <td style="text-align: left">A user account was locked out</td>
            <td style="text-align: left">Account locked due to failed logons</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
        <tr>
            <td style="text-align: left">4767</td>
            <td style="text-align: left">A user account was unlocked</td>
            <td style="text-align: left">Locked account unlocked</td>
            <td style="text-align: left">User Account Management (Success)</td>
        </tr>
    </tbody>
</table>

## Key Fields in User Account Events
***
Most user account events include sections like Subject (who performed the action), Target Account (the affected account), and Attributes (details of changes). These fields help trace accountability and assess impact. Below is a breakdown, with explanations:
- **Subject Section**: Identifies the actor (e.g., the administrator or service account that initiated the change).
    - **Security ID**: A unique SID (Security Identifier) for the subject account. SIDs are used internally by Windows for authentication and authorization.
    - **Account Name**: The username of the subject (e.g., "administrator").
    - **Account Domain**: The domain or machine name (e.g., "ACME-FR" for a domain-joined system).
    - **Logon ID**: A hexadecimal value (e.g., "0x20f9d") representing the session ID of the logon session. This links related events from the same session for correlation.
- **Target Account / New Account Section**: Details the affected user account.
    - **Security ID**: The SID of the new or changed account.
    - **Account Name**: The username (e.g., "John.Locke").
    - **Account Domain**: The domain of the target account.
- **Attributes Section**: Properties of the account, which vary by event but often include changes or new values. These are key for auditing compliance (e.g., password policies).
    - **SAM Account Name**: The logon name in the Security Accounts Manager (SAM) database (e.g., "John.Locke"). This is the pre-Windows 2000 logon name.
    - **Display Name**: A user-friendly name (e.g., "John Locke") shown in tools like ADUC.
    - **User Principal Name (UPN)**: The full email-like name for logon (e.g., "John.Locke@acme-fr.local"). It's the modern equivalent of "Full Name" in your notes and is used for Kerberos authentication.
    - **Home Directory**: Path to the user's network home folder (e.g., "\\server\users\John.Locke"). Often set to "-" if not configured.
    - **Home Drive**: Mapped drive letter for the home directory (e.g., "H:").
    - **Script Path**: Path to a logon script (e.g., batch file run at login).
    - **Profile Path**: Roaming profile location (e.g., "\\server\profiles\John.Locke").
    - **User Workstations**: Allowed workstations for logon (comma-separated list); "*" means all.
    - **Password Last Set**: Timestamp of the last password change (e.g., "never" for new accounts). Critical for detecting stale passwords.
    - **Account Expires**: Expiration date (e.g., "never"). Helps enforce temporary accounts.
    - **Primary Group ID**: Default group (e.g., 513 for Domain Users).
    - **Allowed To Delegate To**: Services the account can delegate to (rarely used).
    - **Old UAC Value / New UAC Value**: User Account Control flags (hexadecimal, e.g., "0x0" to "0x15"). Flags include "Account Disabled," "Password Not Required," "Normal Account," etc. Changes here indicate policy shifts.
    - **User Account Control**: Human-readable breakdown of UAC flags (e.g., "'Password Not Required' - Enabled" flags weak security).
    - **User Parameters**: Custom parameters (usually "-").
    - **SID History**: List of previous SIDs (for migrations; usually "-").
    - **Logon Hours**: Allowed logon times (bitmask; "value not set" means unrestricted).

![Microsoft Events Log](assets/img/soc/ms/ms5.png)

# Security Group Management
***
Security groups manage permissions in Windows (e.g., assigning rights to folders or resources). Events track creation, deletion, and membership changes for security-enabled groups (local, global, or universal). These are essential for monitoring privilege escalations, like adding users to admin groups.

### Common Event IDs
Focus on security-enabled groups (not distribution groups for email). Events are similar for local/global/universal scopes.
<table>
    <thead>
        <tr>
            <th style="text-align: left">Event ID</th>
            <th style="text-align: left">Description</th>
            <th style="text-align: left">When It Occurs</th>
            <th style="text-align: left">Auditing Category</th>
            <th style="text-align: left">Group Type</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td style="text-align: left">4727</td>
            <td style="text-align: left">A security-enabled global group was created</td>
            <td style="text-align: left">New global group added</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Global</td>
        </tr>
        <tr>
            <td style="text-align: left">4728</td>
            <td style="text-align: left">A member was added to a security-enabled global group</td>
            <td style="text-align: left">User/computer added to group</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Global</td>
        </tr>
        <tr>
            <td style="text-align: left">4729</td>
            <td style="text-align: left">A member was removed from a security-enabled global group</td>
            <td style="text-align: left">Member removed</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Global</td>
        </tr>
        <tr>
            <td style="text-align: left">4730</td>
            <td style="text-align: left">A security-enabled global group was deleted</td>
            <td style="text-align: left">Group removed</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Global</td>
        </tr>
        <tr>
            <td style="text-align: left">4731</td>
            <td style="text-align: left">A security-enabled local group was created</td>
            <td style="text-align: left">New local group (similar for universal: 4737)</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Local/Universal</td>
        </tr>
        <tr>
            <td style="text-align: left">4732</td>
            <td style="text-align: left">A member was added to a security-enabled local group</td>
            <td style="text-align: left">Member added (universal: 4737 variant)</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Local/Universal</td>
        </tr>
        <tr>
            <td style="text-align: left">4733</td>
            <td style="text-align: left">A member was removed from a security-enabled local group</td>
            <td style="text-align: left">Member removed</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Local/Universal</td>
        </tr>
        <tr>
            <td style="text-align: left">4734</td>
            <td style="text-align: left">A security-enabled local group was deleted</td>
            <td style="text-align: left">Group removed (universal: 4741)</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Local/Universal</td>
        </tr>
        <tr>
            <td style="text-align: left">4735</td>
            <td style="text-align: left">A security-enabled local group was changed</td>
            <td style="text-align: left">Group attributes modified</td>
            <td style="text-align: left">Security Group Management (Success)</td>
            <td style="text-align: left">Local/Universal</td>
        </tr>
        
    </tbody>
</table>

## Key Fields in Security Group Events
***
Similar structure to user events, but focused on groups:

- **Subject Section**: Same as user events (who made the change).
- **Group Section**: Details the affected group.
    - **Security ID**: SID of the group.
    - **Group Name**: Name (e.g., "Domain Admins").
    - **Group Domain**: Domain or local machine.
    - **Attributes**: Group SAM name, description, etc. (e.g., "Group Scope: Global and security").
- **Member Section** (for add/remove events): SID, name, and domain of the added/removed member (user or group).
- **Additional Attributes**: Similar to user events, but group-specific (e.g., no password fields; instead, group type like "Security" vs. "Distribution").

> Analysis Tips: Watch for additions to privileged groups (e.g., Event 4728 for "Administrators"). The "Target Group" and "Member" sections help trace who gained elevated rights. Correlate with user events for full context.
{: .prompt-tip }