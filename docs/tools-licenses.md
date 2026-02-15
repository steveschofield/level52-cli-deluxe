# Guardian Tool Licenses

This document lists the external tools used by Guardian and their upstream licenses, based on the tool wrappers in `tools/` and SAST tools referenced in `core/source_analyzer.py`.

## Verified (sorted by license)

### AGPL-3.0
- masscan
- trufflehog
- hydra (THC-Hydra)
- Arjun
- kiterunner
- SSLyze

### Apache-2.0
- amass
- trivy
- Retire.js

### BSD-3-Clause
- Metasploit Framework

### BSD-like
- snmpwalk (net-snmp)

### GPL-2.0
- sqlmap
- WhatWeb
- wafw00f
- Nikto
- testssl.sh
- enum4linux (repo notes mixed/unknown licensing)
- onesixtyone
- dnsrecon

### GPL-3.0
- WPScan
- XSStrike
- CMSeeK
- jwt_tool

### GPL-3.0-or-later
- smbclient (Samba)

### LGPL-2.1
- semgrep

### MIT
- naabu
- asnmap
- subfinder
- httpx
- dnsx
- shuffledns
- puredns
- katana
- nuclei
- ffuf
- gitleaks
- subjs
- LinkFinder
- ParamSpider
- Schemathesis
- graphql-cop

### NPSL (Nmap Public Source License)
- nmap

### No license declared (verify upstream)
- waybackurls

## Needs confirmation

The following tools are referenced by wrappers but the upstream license needs manual verification in the repo/package used:

- OWASP ZAP (zaproxy)
- Dalfox
- Commix
- Feroxbuster
- xnLinkFinder
- showmount (nfs-utils; distro/package license varies)
- whois client (implementation/package varies)
- god-eye (wrapper calls `god-eye`; upstream repo/package unclear)

## Internal tools (covered by this repo’s LICENSE)

- headers
- upload_scanner
- csrf_tester
- base_tool

