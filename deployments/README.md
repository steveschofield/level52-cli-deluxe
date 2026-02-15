# Guardian CLI Test Deployments

This directory contains Docker Compose configurations for vulnerable target applications used in automated testing.

## Available Targets

### Web Application Targets

1. **DVWA (Damn Vulnerable Web Application)**
   - Port: `8081`
   - URL: `http://localhost:8081`
   - Credentials: `admin:password`
   - Focus: SQL injection, XSS, CSRF, command injection

2. **OWASP WebGoat**
   - Port: `8082`
   - URL: `http://localhost:8082/WebGoat`
   - Self-contained lessons on various vulnerabilities
   - Focus: OWASP Top 10 vulnerabilities

3. **OWASP Juice Shop**
   - Port: `8083`
   - URL: `http://localhost:8083`
   - Modern vulnerable web application
   - Focus: OWASP Top 10, API security, modern frameworks

4. **OWASP NodeGoat**
   - Port: `8084`
   - URL: `http://localhost:8084`
   - Node.js vulnerable application
   - Focus: NoSQL injection, insecure deserialization

### Network Targets

5. **Metasploitable 3**
   - Ports: Multiple (80, 443, 21, 22, 445, 3306, etc.)
   - URL: `http://localhost:8085`
   - Comprehensive vulnerable infrastructure
   - Focus: Network services, privilege escalation, exploitation

## Deployment

### Deploy All Targets

```bash
python homelab_test_orchestrator.py --deploy-only
```

### Deploy Specific Target

```bash
python homelab_test_orchestrator.py --deploy-only --target dvwa
```

### Manual Deployment

```bash
cd deployments
docker-compose -f dvwa-compose.yml up -d
```

## Teardown

### Teardown All

```bash
python homelab_test_orchestrator.py --teardown-only
```

### Manual Teardown

```bash
cd deployments
docker-compose -f dvwa-compose.yml down -v
```

## Port Mapping

| Target | Port | URL |
|--------|------|-----|
| DVWA | 8081 | http://localhost:8081 |
| WebGoat | 8082 | http://localhost:8082/WebGoat |
| Juice Shop | 8083 | http://localhost:8083 |
| NodeGoat | 8084 | http://localhost:8084 |
| Metasploitable3 | 8085 | http://localhost:8085 |

## Expected Findings

### DVWA
- **Critical**: 3-5 (SQL injection, command injection, file upload)
- **High**: 8-12 (XSS, CSRF, weak session management)
- **Medium**: 10-15 (security headers, information disclosure)

### WebGoat
- **Critical**: 2-4 (XXE, SQL injection)
- **High**: 5-8 (authentication bypass, insecure deserialization)
- **Medium**: 15-20 (CSRF, clickjacking, weak crypto)

### Juice Shop
- **Critical**: 4-6 (SQL injection, XSS, broken authentication)
- **High**: 10-15 (SSRF, XXE, privilege escalation)
- **Medium**: 20-30 (security misconfiguration, sensitive data exposure)

### NodeGoat
- **Critical**: 3-5 (NoSQL injection, insecure deserialization)
- **High**: 7-10 (broken authentication, security misconfiguration)
- **Medium**: 12-18 (CSRF, weak crypto, information disclosure)

### Metasploitable3
- **Critical**: 10-15 (remote code execution, privilege escalation)
- **High**: 15-20 (weak credentials, unpatched services)
- **Medium**: 25-35 (misconfigurations, information disclosure)

## Validation

After deployment, verify targets are accessible:

```bash
# Check all containers
docker ps

# Test HTTP endpoints
curl http://localhost:8081  # DVWA
curl http://localhost:8082  # WebGoat
curl http://localhost:8083  # Juice Shop
curl http://localhost:8084  # NodeGoat
curl http://localhost:8085  # Metasploitable3
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose -f deployments/dvwa-compose.yml logs

# Restart
docker-compose -f deployments/dvwa-compose.yml restart
```

### Port Conflicts

If ports are already in use, edit the compose file and change the host port:

```yaml
ports:
  - "8091:80"  # Change 8081 to 8091
```

### Resource Issues

Some targets (especially Metasploitable3) require significant resources:

```bash
# Check resource usage
docker stats

# Increase Docker resources in Docker Desktop settings
# Recommended: 4GB+ RAM, 2+ CPUs
```
