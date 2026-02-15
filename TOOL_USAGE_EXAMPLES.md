# Guardian Enhanced Tools - Usage Examples

## New Reconnaissance Tools

### 1. Interactsh Client (OOB Detection)
```bash
# Start interactsh server and get callback URL
interactsh-client

# Use the URL in your tests for SSRF/XXE/RCE detection
# Example: Test SSRF
curl "http://target.com/fetch?url=http://YOUR_INTERACTSH_URL"

# Interactsh will show any callbacks from the target
```

**Use Cases:**
- SSRF detection (Server-Side Request Forgery)
- XXE detection (XML External Entity)
- Blind RCE verification
- DNS exfiltration testing

---

### 2. GAU (Get All URLs)
```bash
# Fetch all historical URLs for a domain
gau example.com

# Get URLs from specific sources
gau --providers wayback,commoncrawl example.com

# Filter for specific file extensions
gau example.com | grep -E '\.(php|asp|aspx|jsp)$'

# Combine with other tools
gau example.com | httpx -status-code -title
```

---

### 3. Waybackurls
```bash
# Get URLs from Wayback Machine
waybackurls example.com

# Pipe to parameter finder
waybackurls example.com | grep '='

# Find interesting endpoints
waybackurls example.com | grep -E '/api/|/admin/|/config'
```

---

### 4. Arjun (Parameter Discovery)
```bash
# Discover GET parameters
arjun -u https://example.com/search

# Discover POST parameters
arjun -u https://example.com/login -m POST

# Use custom wordlist
arjun -u https://example.com/api -w /path/to/params.txt

# JSON output
arjun -u https://example.com/endpoint -oJ output.json
```

---

### 5. CORScanner
```bash
# Scan a single URL
cors-scan -u https://example.com

# Scan from a list
cors-scan -i urls.txt

# Detailed output
cors-scan -u https://example.com -v
```

---

## Enhanced ZAP (Hybrid Mode)

### Check ZAP Mode
```bash
# Guardian will auto-detect best ZAP
guardian-zap
# Outputs: "docker" or "native"
```

### Manual ZAP Usage
```bash
# Docker ZAP
docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -port 8080 -host 0.0.0.0

# Native ZAP
zap.sh -daemon -port 8080
```

---

## Smart Port Scanning Strategy

### Using guardian-portscan
```bash
# Fast + detailed scan
guardian-portscan 192.168.1.100 ./output 10000

# This will:
# 1. Use masscan for fast port discovery (if available)
# 2. Use nmap for detailed service enumeration
```

### Manual Strategy
```bash
# Phase 1: Fast discovery with masscan
sudo masscan 192.168.1.0/24 -p1-65535 --rate=10000 -oL open_ports.txt

# Phase 2: Detailed enumeration with nmap
PORTS=$(awk '/open/ {print $3}' open_ports.txt | cut -d'/' -f1 | paste -sd,)
nmap -sV -sC -p $PORTS 192.168.1.0/24 -oX services.xml
```

---

## Reconnaissance Workflow Example

### Complete target enumeration:
```bash
TARGET="example.com"

# 1. Subdomain discovery
subfinder -d $TARGET -o subdomains.txt

# 2. Historical URLs
gau $TARGET > urls_gau.txt
waybackurls $TARGET > urls_wayback.txt
cat urls_*.txt | sort -u > all_urls.txt

# 3. Live host check
cat subdomains.txt | httpx -o live_hosts.txt

# 4. Parameter discovery on live endpoints
while read url; do
    arjun -u "$url" -oJ "params_$(echo $url | md5sum | cut -d' ' -f1).json"
done < live_hosts.txt

# 5. CORS check
cors-scan -i live_hosts.txt -o cors_results.txt

# 6. Port scanning
while read host; do
    guardian-portscan "$host" "./scans/$host"
done < subdomains.txt
```

---

## Integration with Guardian Workflows

### Reconnaissance Phase
```python
# Guardian should use these tools in this order:
1. subfinder/amass - Subdomain enumeration
2. gau/waybackurls - Historical data
3. httpx - Live host check
4. katana - Modern crawling
5. arjun - Parameter discovery
6. nuclei - Vulnerability scanning
# Nmap vuln profile uses: --script vuln,vulners (configurable via tools.nmap.vuln_args)
```

### Advanced SSRF Testing
```python
# 1. Start interactsh
interactsh_url = start_interactsh_client()

# 2. Test endpoints with callback URL
test_ssrf(target_url, callback=interactsh_url)

# 3. Monitor for callbacks
check_interactsh_interactions()
```

---

## Tool Comparison & When to Use What

### URL Discovery: GAU vs Waybackurls
- **GAU**: Multiple sources (Wayback, Common Crawl, Alien Vault)
- **Waybackurls**: Only Wayback Machine, but simpler
- **Use both**: Combine results for maximum coverage

### Port Scanning: Masscan vs Nmap
- **Masscan**: Fast initial discovery (entire /24 in seconds)
- **Nmap**: Detailed service enumeration
- **Best**: Use masscan first, then nmap on found ports

### Parameter Discovery: Arjun vs Manual
- **Arjun**: Automated, smart detection
- **Manual**: Analyze JS files, wayback URLs
- **Best**: Use both approaches

---

## Performance Tips

### Speed Up Reconnaissance
```bash
# Parallel subdomain checking
cat subdomains.txt | parallel -j 50 'curl -s -o /dev/null -w "%{http_code} {}" {}'

# Fast live host detection
cat subdomains.txt | httpx -threads 100 -silent

# Batch parameter discovery
cat urls.txt | parallel -j 10 'arjun -u {} -q'
```

### Resource Management
```bash
# Limit masscan rate to avoid detection
masscan TARGET -p1-65535 --rate=1000  # Slower but stealthier

# Throttle concurrent requests
arjun -u TARGET --stable  # More stable, fewer requests
```

---

## Troubleshooting

### Interactsh Issues
```bash
# If default server is down, use custom
interactsh-client -server interactsh.com

# Self-hosted interactsh
docker run -p 80:80 projectdiscovery/interactsh-server
```

### ZAP Issues
```bash
# Check which mode Guardian is using
guardian-zap

# Force Docker mode
docker run --rm -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon

# Check ZAP logs
docker logs <zap_container_id>
```

### Masscan Issues
```bash
# Requires root for raw sockets
sudo masscan TARGET -p1-65535

# If no root, use nmap instead
nmap -p- -T4 TARGET
```
