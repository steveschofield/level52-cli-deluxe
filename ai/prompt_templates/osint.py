"""
Prompt templates for the OSINT Agent
Handles open-source intelligence gathering and correlation
"""

OSINT_SYSTEM_PROMPT = """You are Guardian's OSINT (Open Source Intelligence) Specialist.

Core responsibilities:
- Passive reconnaissance using public data sources
- Domain and subdomain enumeration
- Technology stack identification
- Historical data analysis (DNS, WHOIS, certificates)
- Breach database correlation
- Social engineering vector identification

Intelligence gathering principles:
- Use ONLY passive techniques (no direct target interaction)
- Aggregate data from multiple sources for validation
- Identify patterns and anomalies
- Respect data privacy and legal boundaries
- Document all data sources for transparency

OSINT workflow:
1. Target profiling (domain, organization, infrastructure)
2. Subdomain discovery (passive DNS, certificate transparency)
3. Technology identification (web archives, public scans)
4. People and organization mapping (LinkedIn, GitHub, public records)
5. Breach intelligence (compromised credentials, data leaks)
6. Attack surface analysis (exposed services, misconfigurations)

Data sources priority:
- Certificate Transparency logs
- DNS aggregators (SecurityTrails, VirusTotal)
- Web archives (Wayback Machine)
- Code repositories (GitHub, GitLab)
- Shodan/Censys (public scan data)
- Breach databases (HaveIBeenPwned, DeHashed)"""

OSINT_DOMAIN_PROFILE_PROMPT = """Create comprehensive domain intelligence profile.

TARGET DOMAIN: {domain}

Gather intelligence on:

1. DOMAIN INFORMATION
   - Registrar and registration date
   - Nameservers and DNS configuration
   - WHOIS data (registrant, admin contacts)
   - Domain age and historical ownership
   - Related domains (same registrant/nameserver)

2. SUBDOMAIN ENUMERATION
   - Certificate Transparency logs
   - DNS aggregators (passive)
   - Search engine enumeration
   - Web archives
   - Estimated total subdomains: <count>

3. INFRASTRUCTURE MAPPING
   - IP ranges (ASN lookup)
   - Hosting providers
   - CDN usage (Cloudflare, Akalike, etc.)
   - Email infrastructure (MX records, SPF, DMARC)
   - Cloud services (AWS, Azure, GCP)

4. TECHNOLOGY STACK
   - Web servers (Apache, Nginx, IIS)
   - Programming languages
   - CMS/frameworks (WordPress, Django, React)
   - JavaScript libraries
   - Analytics and tracking (Google Analytics, etc.)

5. HISTORICAL ANALYSIS
   - Wayback Machine snapshots (oldest to newest)
   - DNS history (IP changes, subdomain evolution)
   - SSL/TLS certificate history
   - Technology changes over time

6. SECURITY INDICATORS
   - Previous breaches or incidents
   - Exposed credentials in dumps
   - Public vulnerability disclosures
   - Security headers implementation
   - DNSSEC, CAA records

PROFILE OUTPUT:
Provide structured intelligence report with:
- Key findings and risk indicators
- Attack surface summary
- Recommended reconnaissance targets
- Data source citations for all claims

CONFIDENCE LEVELS:
Mark each finding: HIGH/MEDIUM/LOW confidence based on source reliability."""

OSINT_SUBDOMAIN_DISCOVERY_PROMPT = """Enumerate subdomains using passive OSINT techniques.

TARGET: {domain}

Subdomain Discovery Methods:

1. CERTIFICATE TRANSPARENCY
   - crt.sh search
   - Censys certificates
   - Certificate patterns (wildcards, SANs)

2. DNS AGGREGATORS
   - SecurityTrails passive DNS
   - VirusTotal subdomains
   - DNSdumpster
   - RapidDNS

3. SEARCH ENGINE ENUMERATION
   - Google: site:{domain}
   - Bing: domain:{domain}
   - DuckDuckGo
   - Yahoo

4. WEB ARCHIVES
   - Wayback Machine URLs
   - Common Crawl

5. CODE REPOSITORIES
   - GitHub code search: "{domain}"
   - GitLab repositories
   - Bitbucket

6. PUBLIC SCAN DATA
   - Shodan: hostname:{domain}
   - Censys
   - BinaryEdge

SUBDOMAIN CATEGORIES:
Organize findings by function:
- Production (www, api, app)
- Development (dev, staging, test, qa)
- Infrastructure (mail, dns, vpn, proxy)
- Legacy (old, v1, backup, archive)
- Third-party integrations
- Security risks (exposed admin panels, dev servers)

OUTPUT FORMAT:
subdomain.{domain} | IP Address | Status | Technology | Risk Level
<subdomain> | <ip> | <online/offline> | <tech> | <HIGH/MEDIUM/LOW>

PRIORITIZATION:
Rank subdomains by attack value:
1. Development/staging environments (likely less secure)
2. Admin/management panels
3. API endpoints
4. Legacy systems
5. Third-party integrations

Total discovered: <count>
High-priority targets: <count>"""

OSINT_BREACH_INTELLIGENCE_PROMPT = """Search for compromised credentials and data leaks.

TARGET DOMAIN: {domain}
EMAIL PATTERN: {email_pattern}

Breach Intelligence Sources:

1. PUBLIC BREACH DATABASES
   - HaveIBeenPwned API
   - DeHashed
   - LeakCheck
   - Snusbase

2. PASTE SITES
   - Pastebin
   - GitHub Gists
   - Ghostbin

3. CODE REPOSITORIES
   - GitHub exposed secrets
   - GitLab leaks
   - Exposed .git directories

4. DARK WEB MONITORING
   - Known breach forums
   - Credential markets
   - Data dump repositories

SEARCH CRITERIA:
- Domain: {domain}
- Email addresses: *@{domain}
- API keys/tokens containing domain
- Database dumps mentioning organization

FINDINGS FORMAT:
Breach: <breach name>
Date: <breach date>
Exposed Data: <data types>
Affected Accounts: <count>
Password Format: <plaintext/hashed/unknown>
Source: <source URL if public>
Risk: <CRITICAL/HIGH/MEDIUM/LOW>

RISK ASSESSMENT:
- Plaintext passwords: CRITICAL
- Hashed passwords (weak algorithm): HIGH
- Email + metadata only: MEDIUM
- Outdated breach (5+ years): LOWER

RECOMMENDATIONS:
1. Credential rotation priorities
2. Accounts requiring immediate password reset
3. Multi-factor authentication gaps
4. Monitoring requirements

COMPLIANCE NOTE:
- Only use public/authorized breach data sources
- Do NOT access underground markets directly
- Document all data sources
- Respect data privacy regulations"""

OSINT_PEOPLE_ENUMERATION_PROMPT = """Identify key personnel and potential social engineering vectors.

ORGANIZATION: {organization}
DOMAIN: {domain}

People Intelligence (OSINT Only):

1. LINKEDIN ENUMERATION
   - Company employees
   - Job titles and roles
   - Technology skills
   - Organizational structure
   - Recent hires/departures

2. GITHUB/GITLAB ACTIVITY
   - Developers committing to public repos
   - Email addresses in git logs
   - Technology stack insights
   - Code patterns and quality

3. PUBLIC DOCUMENTS
   - Conference presentations
   - Research papers
   - Patents
   - Press releases
   - Job postings (tech stack hints)

4. SOCIAL MEDIA (PUBLIC ONLY)
   - Twitter/X technical discussions
   - Stack Overflow profiles
   - Blog posts
   - YouTube channels

ROLE IDENTIFICATION:
Target roles of interest:
- System Administrators (high-privilege access)
- Developers (code/infrastructure knowledge)
- Security Team (incident response contacts)
- Executives (social engineering targets)
- IT Support (potential weak points)

SOCIAL ENGINEERING VECTORS:
Identify potential attack vectors (DO NOT EXECUTE):
- Common email patterns (firstname.lastname@domain)
- Phishing target identification
- Pretexting scenarios (vendor, support, executive)
- Trust relationships (partners, clients)

OUTPUT:
Role: <job title>
Name: <public name or "Unknown">
Email Pattern: <inferred pattern>
Technologies: <known skills>
Access Level: <estimated>
SE Risk: <HIGH/MEDIUM/LOW>

ETHICAL BOUNDARIES:
- Use ONLY publicly available information
- Do NOT contact individuals
- Do NOT access private social media
- Do NOT create fake profiles for reconnaissance
- Document all sources"""

OSINT_TECHNOLOGY_PROFILING_PROMPT = """Build comprehensive technology stack profile.

TARGET: {target}

Technology Identification Sources:

1. PASSIVE WEB ANALYSIS
   - Wappalyzer signatures
   - BuiltWith data
   - HTTP headers
   - HTML/CSS/JS patterns
   - Error messages

2. PUBLIC SCAN DATA
   - Shodan technology tags
   - Censys service identification
   - Historical scan results

3. WEB ARCHIVES
   - Wayback Machine snapshots
   - Technology evolution over time
   - Deprecated endpoints

4. CODE REPOSITORIES
   - Public repos mentioning domain
   - Configuration files (package.json, requirements.txt)
   - Infrastructure as Code (Terraform, CloudFormation)

5. JOB POSTINGS
   - Required skills
   - Technology stack mentions
   - Infrastructure hints

TECHNOLOGY CATEGORIES:

FRONTEND:
- JavaScript frameworks (React, Vue, Angular)
- CSS frameworks (Bootstrap, Tailwind)
- Build tools (Webpack, Vite)

BACKEND:
- Languages (Python, Node.js, Java, PHP, Go)
- Frameworks (Django, Express, Spring, Laravel)
- API types (REST, GraphQL, gRPC)

INFRASTRUCTURE:
- Web servers (Nginx, Apache, IIS)
- Databases (PostgreSQL, MySQL, MongoDB, Redis)
- Cloud providers (AWS, Azure, GCP)
- CDN (Cloudflare, Fastly, Akamai)
- Containers (Docker, Kubernetes)

SECURITY:
- WAF (Cloudflare, Imperva, AWS WAF)
- DDoS protection
- SSL/TLS configuration
- Security headers

THIRD-PARTY SERVICES:
- Analytics (Google Analytics, Mixpanel)
- Payment processors (Stripe, PayPal)
- Email services (SendGrid, Mailgun)
- Authentication (Auth0, Okta)

OUTPUT:
Category | Technology | Version | Confidence | Vulnerabilities | Risk
<category> | <tech> | <version> | <HIGH/MED/LOW> | <known CVEs> | <risk level>

VULNERABILITY CORRELATION:
For each identified technology with version:
- Known CVEs affecting this version
- Publicly available exploits
- Default credentials
- Common misconfigurations

ATTACK SURFACE SUMMARY:
- Total technologies identified: <count>
- Technologies with known vulnerabilities: <count>
- End-of-life/unsupported software: <count>
- Recommended prioritization for testing"""

OSINT_CORRELATION_PROMPT = """Correlate OSINT data from multiple sources into actionable intelligence.

COLLECTED INTELLIGENCE:
Domain Data: {domain_data}
Subdomains: {subdomains}
Technologies: {technologies}
Breaches: {breaches}
People: {people_data}

CORRELATION ANALYSIS:

1. INFRASTRUCTURE PATTERNS
   - Hosting consolidation (single cloud provider?)
   - IP range ownership
   - Subdomain naming conventions
   - Technology consistency across assets

2. SECURITY GAPS
   - Development servers exposed
   - Legacy systems still running
   - Unpatched software versions
   - Breach credential overlap

3. ATTACK CHAINS
   - Subdomain takeover opportunities
   - Credential stuffing targets
   - Social engineering paths
   - API endpoint discovery

4. TEMPORAL ANALYSIS
   - Recent infrastructure changes
   - New subdomain patterns
   - Technology migrations
   - Security improvement trends

5. ANOMALY DETECTION
   - Outlier subdomains (different hosting/tech)
   - Inconsistent security postures
   - Unusual DNS patterns
   - Suspicious recent changes

INTELLIGENCE SUMMARY:
Priority: <HIGH/MEDIUM/LOW>
Finding: <correlated insight>
Evidence: <supporting data from multiple sources>
Attack Vector: <how this could be exploited>
Recommendation: <next reconnaissance or testing step>

ATTACK SURFACE MAP:
Generate visual attack surface representation:
1. Primary targets (production systems)
2. Secondary targets (dev/staging)
3. Third-party integrations
4. Credential exposure risks
5. Social engineering vectors

RECOMMENDED NEXT STEPS:
Based on OSINT findings, prioritize:
1. <specific reconnaissance action>
2. <specific vulnerability testing>
3. <specific credential validation>

CONFIDENCE METRICS:
Overall intelligence quality: <HIGH/MEDIUM/LOW>
Data source diversity: <count> unique sources
Cross-validation rate: <percentage>% of findings confirmed by multiple sources"""
