---
layout: post
title: "MaaS Infrastructure Profiling"
date: 2026-09-24
pid: "0401"
category: "Research"
description: "Tracking a modern Malware-as-a-Service panel operating from a bulletproof host by mapping its Telegram Dead Drop Resolver, fingerprinting its Python backend, and documenting its OPSEC failures."
tags: [Malware, OSINT, Infrastructure]
featured: true
---
### Intro
While hunting for fresh malware payloads on MalwareBazaar, I found a newly uploaded 64-bit Windows executable flagged as a `v20-stealer`. Dynamic analysis in ANY.RUN revealed that the malware does not rely on hardcoded Command and Control (C2) IP addresses. Instead, it uses a Dead Drop Resolver (DDR) hosted on a Telegram channel to dynamically fetch its backend infrastructure.

By manually decoding the exfiltration mechanisms and fingerprinting the exposed backend server, I mapped an active, completely uncategorized Malware-as-a-Service (MaaS) panel operating out of a bulletproof hosting provider in the Netherlands. Rather than connecting to a known commodity botnet, this infrastructure appears custom and highly targeted.

## Phase 1: Initial Triage and the Dead Drop Resolver (DDR)
The investigation started with a fresh sample uploaded to MalwareBazaar by threat researcher `devmihaylov`.

<div class="image-container">
    <img src="{{ '/assets/img/0401/Bazaar_Listing.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

To safely see its network behavior without risking local execution, I ran the binary through the ANY.RUN sandbox. Almost immediately, the HTTP requests made it very clear what was happening.

<div class="image-container">
    <img src="{{ '/assets/img/0401/AnyRun-HTTPReqs.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

Instead of immediately beaconing to a malicious server, the malware first reaches out to a legitimate Telegram channel URL: `https://t.me/kahagqhkakneh`. This technique, known as a Dead Drop Resolver (MITRE ATT&CK T1102.001), allows the attacker to update their C2 infrastructure instantly just by editing a social media bio, entirely bypassing static IP blocklists.

Navigating to the Telegram channel via a safe web preview revealed a seemingly nonsensical string in the bio:

<div class="image-container">
    <img src="{{ '/assets/img/0401/TelegramChannel_MemberCount_9-24-26-12-31.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

The payload reads: `[gsc]MTAzLjEwMS44NS4yNg==[/gsc]`

The `[gsc]` tags act as markers, telling the malware exactly where to parse the string. The core payload is standard Base64. Decoding it directly in the terminal reveals the hidden C2 IP address:
```
$ echo "MTAzLjEwMS44NS4yNg==" | base64 -d
103.101.85.26
```

The ANY.RUN network stream also showed subsequent `POST` requests reaching out to `103.101.85.26/gate?mode=beacon`, consistently returning `HTTP 200 OK`. The C2 was live and accepting victim logs.

## Phase 2: Infrastructure Profiling & OPSEC Failures
Since I had the live C2 IP, I shifted to passive recon using Shodan to profile the backend architecture.

<div class="image-container">
    <img src="{{ '/assets/img/0401/Shodan_Part1.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

<div class="image-container">
    <img src="{{ '/assets/img/0401/Shodan_Part2.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

The server (`103.101.85.26`) is hosted in the Netherlands by **Internalhost (AS214408)**, a known bulletproof hosting provider often used by cybercriminals to avoid abuse complaints and DMCA takedowns.

Despite running a modern MaaS panel, the attacker's server security seems incredibly bad. The host is an unpatched Windows machine bleeding critical vulnerabilities, including:

- **CVE-2020-0796 (SMBGhost):** A critical Remote Code Execution vulnerability in Windows SMBv3.
- **CVE-2023-44487:** HTTP/2 Rapid Reset Denial of Service.
- **CVE-2025-23419:** An Nginx TLS session bypass.

### Active Service Enumeration
Probing the exposed ports directly from a Kali terminal gave a better picture of their setup:

- **Port 3389 (RDP):** Scans returned a `filtered` state, indicating the attacker implemented an IP whitelist to restrict remote desktop access to a specific IP.
- **Port 6379 (Redis):** The Redis cache was exposed to the public internet. While an Nmap script scan confirmed it was reachable, querying it directly via `redis-cli` returned `NOAUTH Authentication required`. The attacker secured the database with a password, but failed to bind it to the local loopback interface.

> Note: Half way through the profiling, a re-check of the Telegram dead drop showed the member count had increased from 2 to 3, indicating active monitoring or bot rotation by the operators.

<div class="image-container">
    <img src="{{ '/assets/img/0401/TelegramChannel_MemberCount_9-24-26-17-12.png' | relative_url }}" alt="MalwareBazaar Listing">
</div>

## Phase 3: Cryptographic Forensics & The Web Backend
Analyzing the SSL/TLS certificate on port 443 revealed another low-effort OPSEC choice. Rather than registering a domain name to blend in with legitimate HTTPS traffic, the attacker generated a self-signed certificate:
```
Issuer: CN=localhost
Not Before: Aug 10 07:24:29 2026 GMT
Serial Number: 6c:1b:01:6e:a4:d9:b7:9e:1d:d6:20:f5:d8:39:70:dd:c6:91:c1:2f
```

The August 10 creation date pinpoints when this specific infrastructure node was spun up.

Querying the web server's HTTP headers exposed a dual-stack architecture:
```
HTTP/1.1 405 Method Not Allowed
Server: uvicorn
Server: nginx/1.24.0
```

While legacy commodity stealers (like RedLine and StealC) are reliant on PHP, the presence of **Uvicorn** indicates a modern, asynchronous Python backend (likely FastAPI or Starlette), hidden behind an Nginx reverse proxy.

## Phase 4: Client-Side Reverse Engineering
Sending standard `GET` requests to the root directory, or attempting to brute-force typical API documentation endpoints (`/docs`, `/openapi.json`), consistently returned the exact same HTML skeleton: `<div id="root"></div>`.

This confirmed the front end is a **Single Page Application (SPA)**, likely built in React or Vue. Nginx was configured with a catch-all routing rule to serve the compiled client-side JavaScript bundle to any incoming request.

By downloading the compiled Vite artifact (`panel.js`) directly from the server, I extracted the hardcoded API routes the attacker neglected to hide:
```
$ grep -oP '(?<=")/[a-zA-Z0-9_/-]+(?=")' panel.js | sort -u
/admin
/billing
/builder
/cookies
/exports
/logs
/steam
```

These endpoints are the definitive fingerprints of an active MaaS affiliate dashboard. The presence of `/builder` allows affiliates to generate custom stealer stubs, while `/cookies` and `/steam` handle the parsing of high-value session tokens stolen from victims.

## Conclusion
What began as a routine malware sample triage uncovered a complete, end-to-end view of a modern infostealer operation. By chasing the execution chain through a Telegram Dead Drop Resolver, we unmasked an active Python-based MaaS backend. Despite utilizing simple but effective evasion tactics like social media dead drops to bypass static IP blocklists, the threat actor's infrastructure security seemed to remain fundamentally flawed.

### Indicators of Compromise (IOCs)

| **Type**        | **Indicator**                                                 | **Context**                                  |
| --------------- | ------------------------------------------------------------- | -------------------------------------------- |
| **IPv4**        | `103.101.85.26`                                               | Active C2 Panel (Internalhost AS214408)      |
| **URL**         | `[https://t.me/kahagqhkakneh](https://t.me/kahagqhkakneh)`    | Telegram Dead Drop Resolver                  |
| **URI**         | `/gate?mode=beacon`                                           | Stealer Log Ingestion Endpoint               |
| **Certificate** | `6c:1b:01:6e:a4:d9:b7:9e:1d:d6:20:f5:d8:39:70:dd:c6:91:c1:2f` | Serial number for self-signed `CN=localhost` |