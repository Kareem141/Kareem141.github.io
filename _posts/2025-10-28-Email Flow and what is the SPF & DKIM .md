---
title: Email Flow and what is the SPF & DKIM 
date: 2025-10-28 03:30:32 +0200
categories: [SOC Investigation]
tags: [soc, investigation, logs, email, mail, spf, dkim]
---
# Email Flow
***
- **Mail User Agent (MUA)**: computer application that allows you to send and retrieve email (Outlook, FireFox).
- **Mail Submission Agent (MSA)**: the server that receive the message from the MUA and send it to MTA.
- **Mail Transfer Agent (MTA)**: Accept the message from the MSA, route it and forwards outgoing e-mail for delivery.
- **Mail Delivery Agent (MDA)**: Server that Provide the mail message to the recipient after successful authentication.

![Email Flow](assets/img/soc/email/e1.png)

# SPF & DKIM
***
- **SPF**: helps servers verify that messages appearing to come from a particular domain are sent from servers authorized by the domain owner.
- **DKIM**: adds a digital signature to every message. This lets receiving servers verify that messages
aren't forged, and weren't changed during transit. it encrypt message body (asemetric encrypt) and generate hash then publish its public key then when the message reach MDA, it  decrypt the message and generate hash and compare the two hashes. if they are the same, then the message weren’t changed during transit.

![Email Flow](assets/img/soc/email/e2.png)