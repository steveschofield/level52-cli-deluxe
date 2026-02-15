# OSINT Sources

Guardian CLI integrates multiple OSINT (Open Source Intelligence) sources to enrich vulnerability findings with comprehensive threat intelligence.

## Available Sources

### 1. CISA KEV (Known Exploited Vulnerabilities)
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None (static JSON)
- **Purpose**: Identifies CVEs actively exploited in the wild
- **Source**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Config**: `osint.sources.cisa_kev`

### 2. GitHub Exploit PoC Search
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: 60/hour (no auth), 5000/hour (with token)
- **Purpose**: Searches GitHub for community exploit proof-of-concepts
- **Config**: `osint.sources.github`
- **Requires**: Optional GitHub Personal Access Token

### 3. EPSS (Exploit Prediction Scoring System)
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None
- **Purpose**: Provides exploitation probability predictions (0-1 scale)
- **Source**: https://api.first.org/data/v1/epss
- **Config**: `osint.sources.epss`
- **Features**:
  - Daily probability scores for CVE exploitation likelihood
  - Percentile rankings
  - Automatic risk level classification (critical/high/medium/low)

### 4. OSV (Open Source Vulnerabilities)
- **Status**: Active
- **Cost**: FREE
- **Rate Limit**: None
- **Purpose**: Distributed vulnerability database for open source packages
- **Source**: https://api.osv.dev
- **Config**: `osint.sources.osv`
- **Features**:
  - Aggregates data from multiple ecosystems:
    - GitHub Security Advisories
    - Python PyPI advisories
    - Go vulndb
    - RustSec
    - npm advisories
    - Maven Central
  - Package-level vulnerability information
  - CVSS scoring and references

## Configuration

All OSINT sources can be configured in `config/guardian.yaml` under the `osint` section:

```yaml
osint:
  enabled: true
  cache_ttl_hours: 24

  sources:
    # Enable/disable individual sources
    cisa_kev:
      enabled: true

    github:
      enabled: true
      token: ""  # Optional but recommended

    epss:
      enabled: true
      high_risk_threshold: 0.7

    osv:
      enabled: true
      include_aliases: true
```

## Enrichment Data Structure

The OSINT enricher returns enrichment data keyed by finding ID with the following structure:

```python
{
    "finding_id": {
        "cve_data": {},
        "kev_status": {
            "CVE-YYYY-XXXXX": {
                "cve_id": "CVE-YYYY-XXXXX",
                "vulnerability_name": "...",
                "date_added": "YYYY-MM-DD",
                "due_date": "YYYY-MM-DD",
                "required_action": "..."
            }
        },
        "github_pocs": [
            {
                "name": "username/repo",
                "url": "https://github.com/...",
                "stars": 100,
                "language": "Python",
                "description": "..."
            }
        ],
        "epss_scores": {
            "CVE-YYYY-XXXXX": {
                "epss": 0.85,
                "percentile": 0.95,
                "risk_level": "critical",
                "epss_percentage": "85.00%",
                "percentile_rank": "95.0th"
            }
        },
        "osv_data": {
            "CVE-YYYY-XXXXX": {
                "id": "CVE-YYYY-XXXXX",
                "summary": "...",
                "affected_packages": [
                    {
                        "ecosystem": "PyPI",
                        "name": "package-name",
                        "purl": "pkg:pypi/package-name"
                    }
                ],
                "references": [...]
            }
        }
    }
}
```

## Usage

The OSINT enricher is automatically used by Guardian CLI when enabled in the configuration. It enriches vulnerability findings during scanning and includes the enrichment data in reports.

### Programmatic Usage

```python
from utils.osint import OSINTEnricher

# Initialize enricher with config
enricher = OSINTEnricher(config, logger)

# Enrich findings
enrichment_data = enricher.enrich_findings(findings)

# Get summary of OSINT sources
summary = enricher.get_summary()
```

## API Keys and Authentication

### Optional API Keys

1. **GitHub**: Create at https://github.com/settings/tokens
   - Increases rate limit from 60/hour to 5000/hour
   - Required scopes: `public_repo` (read-only)

## Dependencies

The new OSINT sources require the following Python packages (automatically installed):

- `requests>=2.31.0` - For HTTP requests to OSINT APIs

## Performance Considerations

- **EPSS**: Very fast, single API call for multiple CVEs
- **OSV**: Fast, supports batch queries

## Recommendations

1. **Enable all sources** for maximum coverage
2. **Add GitHub token** if scanning frequently (rate limit improvement)
3. **Monitor rate limits** when scanning large numbers of CVEs
4. **Use caching** (default 24 hours) to reduce API calls

## Future Enhancements

Potential additional OSINT sources to consider:

- ExploitDB API (local database)
- NVD (National Vulnerability Database)
- VulnCheck KEV
- Tenable VPR (Vulnerability Priority Rating)
- GreyNoise (for threat intelligence correlation)
