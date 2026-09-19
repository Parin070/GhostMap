# 
```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝████╗ ████║██╔══██╗██╔══██╗
██║  ███╗███████║██║   ██║███████╗   ██║   ██╔████╔██║███████║██████╔╝
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/OSINT-Tool-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/CLI-Typer-blueviolet?style=for-the-badge"/>
</p>

<p align="center">
  <b>Multi-module OSINT reconnaissance CLI. IP intel. Domain recon. Email breach check. People search. AI-powered threat summary.</b>
</p>

---

## What is GhostMap?

GhostMap is a terminal-based OSINT tool built for cybersecurity analysts, bug bounty hunters, and researchers. Feed it a target — IP, domain, email, or name — and it pulls intelligence from multiple sources, scores the risk, and gives you an AI-generated threat assessment. All from one CLI.

---

## Modules

```
osint/
├── main.py               # Interactive menu + ASCII banner
├── ai.py                 # OpenRouter AI threat summary
├── modules/
│   ├── base.py           # Recon base class
│   ├── ip.py             # IP recon (async)
│   ├── domain.py         # Domain recon
│   ├── email.py          # Email breach check
│   └── people.py         # People / username search
└── output/
    ├── terminal.py       # Rich table display
    └── pdf.py            # PDF export (coming soon)
```

---

## Features

| Module | Sources | Output |
|--------|---------|--------|
| **IP Recon** | AbuseIPDB, Shodan, VirusTotal | Abuse score, open ports, CVEs, ASN, risk score |
| **Domain Recon** | Whois, DNS, crt.sh, VirusTotal | Registrar, A/MX/TXT records, subdomains, risk score |
| **Email Recon** | Hudson Rock (infostealer DB) | Breach count, infection details, risk score |
| **People Search** | Sherlock (username), DDG dork (full name) | Social profile URLs across 300+ sites |
| **AI Summary** | OpenRouter (free tier) | Threat assessment, suspicious flags, risk verdict |

---

## Installation

```bash
# Clone
git clone https://github.com/Parin070/GhostMap.git
cd GhostMap

# Create venv
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install
pip install -e .

# Setup keys
cp .env.example .env
nano .env
```

---

## API Keys Required

```env
ABUSEIPDB_API_KEY=        # https://www.abuseipdb.com/api
SHODAN_API_KEY=           # https://account.shodan.io
VIRUSTOTAL_API_KEY=       # https://www.virustotal.com/gui/my-apikey
OPENROUTER_API_KEY=       # https://openrouter.ai/keys
```

All free tier. No paid keys needed.

---

## Usage

```bash
python -m osint.main
```

```
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███╗   ███╗ █████╗ ██████╗
...

What do you want to recon?
1. IP
2. Domain
3. Email
4. People
0. Exit
```

### Examples

```bash
# IP recon
Enter your choice: 1
Enter IP: 8.8.8.8

# Domain recon
Enter your choice: 2
Enter domain: google.com

# Email breach check
Enter your choice: 3
Enter email: target@example.com

# Username search (Sherlock)
Enter your choice: 4
Enter username or full name: johndoe

# Full name search (DDG dork)
Enter your choice: 4
Enter username or full name: John Doe
```

---

## Risk Scoring

GhostMap calculates a risk score per module:

| Score | Verdict |
|-------|---------|
| 0–30 | Low risk |
| 31–60 | Medium risk |
| 61–100 | High risk |

**IP** — weighted average of AbuseIPDB confidence, VirusTotal detections, Shodan CVEs  
**Domain** — VirusTotal malicious/total engine ratio  
**Email** — tiered by infostealer breach count (0 / <10 / <50 / 50+)

---

## Tech Stack

```
Python 3.10+    asyncio / aiohttp    Typer    Rich
Shodan API      AbuseIPDB API        VirusTotal API
Hudson Rock     crt.sh               DDG Search
Sherlock        OpenRouter AI        python-whois / dnspython
```

---

## Roadmap

- [x] IP recon (async)
- [x] Domain recon
- [x] Email breach check
- [x] People search (username + full name)
- [x] AI threat summary
- [x] Rich terminal output
- [ ] Facial recognition module (Phase 10)
- [ ] Full async across all modules

---

## Legal

GhostMap queries **publicly available data only**. No authentication bypass. No private data access. Built for authorized security research, penetration testing, and OSINT investigations.

> Use responsibly. The author is not liable for misuse.

---

<p align="center">
  <i>Stay in the shadows. Leave no trace. GhostMap.</i>
</p>