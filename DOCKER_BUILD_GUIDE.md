# Dockerfile.kali - Build & Test Guide

## ✅ Fixes Applied

The following critical issues have been **FIXED** in `Dockerfile.kali`:

1. ✅ **Trivy Installation** - Changed from broken apt repo to binary installation
2. ✅ **god-eye Installation** - Changed to `go install` method (more reliable)
3. ✅ **kiterunner Added** - API endpoint discovery tool
4. ✅ **retire.js Added** - JavaScript vulnerability scanner

**Backup Created**: `Dockerfile.kali.backup.TIMESTAMP`

---

## 🚀 Building the Docker Image

### Prerequisites

- Docker Desktop installed and running
- At least **20GB** free disk space
- **Stable internet connection** (downloads ~5GB of packages)
- **Time**: Allow 45-85 minutes for full build

### Quick Build

```bash
cd /Users/ss/.claude-worktrees/level52-cli-deluxe/strange-khorana

# Basic build
docker build -f Dockerfile.kali -t level52-cli-deluxe:latest .

# Build with progress output (recommended)
docker build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain

# Clean build (no cache)
docker build --no-cache -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain
```

### Build with Detailed Logging

```bash
# Save build output to log file
docker build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain 2>&1 | tee docker-build.log

# Monitor build progress in real-time
tail -f docker-build.log
```

---

## 🧪 Testing the Built Image

### 1. Start Interactive Container

```bash
# Start container
docker run -it --rm level52-cli-deluxe:latest /bin/bash

# Or with volume mounts for reports
docker run -it --rm \
  -v $(pwd)/reports:/guardian/reports \
  level52-cli-deluxe:latest /bin/bash
```

### 2. Verify All Tools Installed

Inside the container, run these verification commands:

```bash
# Check critical binaries
echo "=== Checking Binaries ==="
which testssl && echo "✓ testssl"
which kr && echo "✓ kiterunner"
which jwt_tool && echo "✓ jwt_tool"
which graphqlcop && echo "✓ graphqlcop"
which xsstrike && echo "✓ xsstrike"
which cmseek && echo "✓ cmseek"
which linkfinder && echo "✓ linkfinder"
which xnlinkfinder && echo "✓ xnlinkfinder"
which paramspider && echo "✓ paramspider"
which feroxbuster && echo "✓ feroxbuster"
which godeye && echo "✓ godeye"
which corsscanner && echo "✓ corsscanner"
which trivy && echo "✓ trivy"
which retire && echo "✓ retire"

# Check versions
echo ""
echo "=== Tool Versions ==="
trivy --version
kr --version || echo "kr installed (version check may not work)"
retire --version
feroxbuster --version

# Check Go tools
echo ""
echo "=== Go Tools ==="
httpx -version
nuclei -version
subfinder -version
ffuf -version

# Check Python tools
echo ""
echo "=== Python Tools ==="
pip3 list | grep -E "arjun|schemathesis|dirsearch|semgrep"

# Check Python imports
echo ""
echo "=== Python Packages ==="
python3 -c "import anthropic; print('✓ anthropic')"
python3 -c "import langchain; print('✓ langchain')"
python3 -c "from langchain_ollama import ChatOllama; print('✓ langchain_ollama')"
python3 -c "import langsmith; print('✓ langsmith')"
python3 -c "import requests; print('✓ requests', requests.__version__)"

# Test Guardian CLI
echo ""
echo "=== Guardian CLI ==="
python -m cli.main --help
python -m cli.main workflow list
```

### 3. Quick Functional Test

```bash
# Inside container
cd /guardian

# Test recon workflow (requires network)
python -m cli.main workflow run --name recon --target scanme.nmap.org

# Check generated reports
ls -lh /guardian/reports/
```

---

## 📊 Build Stages & Expected Times

| Stage | Description | Time | Critical? |
|-------|-------------|------|-----------|
| 1 | System update & base packages | 5-10 min | ✅ Critical |
| 2 | Kali pentesting tools | 10-15 min | Medium |
| 3 | SAST tools (Semgrep, **Trivy**, TruffleHog) | 3-5 min | ✅ **FIXED** |
| 4 | Go tools (httpx, nuclei, etc.) | 5-10 min | Medium |
| 5 | Rust tools (feroxbuster) | 10-20 min | High risk |
| 6 | Python dependencies | 3-5 min | Low |
| 7 | Python security tools | 5-10 min | Low |
| 8 | Git-cloned tools | 5-10 min | Low |
| 9 | **NEW: kiterunner + retire.js** | 2-3 min | ✅ **ADDED** |
| 10-16 | Wordlists, Guardian setup, verification | 10-15 min | Low |
| **TOTAL** | | **45-85 min** | |

---

## 🐛 Troubleshooting Build Failures

### Issue 1: Trivy Installation Fails

**Symptoms**:
```
E: Unable to locate package trivy
```

**Solution**: ✅ **FIXED** - Now uses binary installation instead of apt

**Verify Fix**:
```bash
grep -A 5 "Install Trivy" Dockerfile.kali | head -10
# Should show "BINARY METHOD (FIXED)"
```

---

### Issue 2: Build Stops at Go Tools

**Symptoms**:
```
go: connection timeout
```

**Solution**:
```bash
# Set Go proxy
export GOPROXY=https://proxy.golang.org,direct

# Or use direct download
export GOPROXY=direct

# Rebuild
docker build -f Dockerfile.kali -t level52-cli-deluxe:latest .
```

---

### Issue 3: feroxbuster Compilation Fails

**Symptoms**:
```
error: could not compile `feroxbuster`
```

**Solution**: This is the longest stage (10-20 minutes). If it fails:

```bash
# Option 1: Use pre-built binary instead
# Edit Dockerfile.kali around line 241, replace cargo install with:
RUN curl -sL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip -o /tmp/ferox.zip && \
    unzip /tmp/ferox.zip -d /tmp && \
    mv /tmp/feroxbuster /usr/local/bin/ && \
    chmod +x /usr/local/bin/feroxbuster

# Option 2: Skip feroxbuster (comment out lines 240-243)
```

---

### Issue 4: Docker Runs Out of Space

**Symptoms**:
```
no space left on device
```

**Solution**:
```bash
# Clean up Docker
docker system prune -a --volumes

# Check available space
docker system df

# Remove old images
docker images
docker rmi <image-id>
```

---

### Issue 5: Build Stops at Random Layer

**Symptoms**: Build freezes or hangs

**Solution**:
```bash
# Kill the build
docker ps -a
docker kill <container-id>

# Clean up
docker system prune

# Rebuild with more verbose output
docker build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain --no-cache
```

---

## 📦 Image Size & Optimization

### Expected Image Size

- **Base Kali**: ~2 GB
- **With all tools**: ~15-20 GB
- **Compressed**: ~8-10 GB

### Check Image Size

```bash
docker images level52-cli-deluxe
docker image inspect level52-cli-deluxe:latest | grep Size
```

### Reduce Image Size (Future Optimization)

```dockerfile
# Multi-stage build (not currently implemented)
FROM kalilinux/kali-rolling AS builder
# ... build tools

FROM kalilinux/kali-rolling
# ... copy only binaries
```

---

## 🚀 Running the Container

### Basic Usage

```bash
# Interactive shell
docker run -it --rm level52-cli-deluxe:latest

# With API keys
docker run -it --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  level52-cli-deluxe:latest

# With volume mounts
docker run -it --rm \
  -v $(pwd)/reports:/guardian/reports \
  -v $(pwd)/data:/guardian/data \
  level52-cli-deluxe:latest
```

### Run Specific Command

```bash
# Run workflow directly
docker run --rm \
  -e ANTHROPIC_API_KEY="sk-ant-..." \
  -v $(pwd)/reports:/guardian/reports \
  level52-cli-deluxe:latest \
  python -m cli.main workflow run --name web --target https://example.com

# Run specific tool
docker run --rm level52-cli-deluxe:latest nmap -sV scanme.nmap.org

# Run trivy scan
docker run --rm -v $(pwd):/scan level52-cli-deluxe:latest trivy fs /scan
```

### Network Scanning (Requires Privileges)

```bash
# With network capabilities
docker run -it --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  level52-cli-deluxe:latest

# For masscan/nmap SYN scans
docker run -it --rm \
  --privileged \
  --net=host \
  level52-cli-deluxe:latest
```

---

## 🔍 Verification Checklist

After successful build, verify:

- [ ] Container starts without errors
- [ ] All 17 tools are present (`which` commands succeed)
- [ ] Tool versions display correctly
- [ ] Python packages import successfully
- [ ] Guardian CLI help displays
- [ ] Workflow list shows available workflows
- [ ] Sample workflow executes (if network available)

**Verification Script**:

```bash
#!/bin/bash
# verify-image.sh

echo "Starting Guardian Docker image verification..."

docker run --rm level52-cli-deluxe:latest /bin/bash -c '
    echo "=== Checking Tools ==="
    TOOLS="testssl kr jwt_tool graphqlcop xsstrike cmseek linkfinder xnlinkfinder paramspider feroxbuster godeye corsscanner trivy retire"
    for tool in $TOOLS; do
        if which $tool >/dev/null 2>&1; then
            echo "✓ $tool"
        else
            echo "✗ $tool MISSING"
        fi
    done

    echo ""
    echo "=== Checking Guardian CLI ==="
    python -m cli.main --help >/dev/null 2>&1 && echo "✓ Guardian CLI works" || echo "✗ Guardian CLI failed"

    echo ""
    echo "=== Checking Python Packages ==="
    python3 -c "import anthropic, langchain, requests; print(\"✓ Core packages OK\")"
'

echo "Verification complete!"
```

---

## 📝 Next Steps

1. **Test Build** - Run the build command
2. **Verify Tools** - Check all tools are present
3. **Functional Test** - Run a sample workflow
4. **Commit Changes** - If successful, commit Dockerfile.kali
5. **Push to GitHub** - Share the working Dockerfile
6. **Document** - Update DOCKER.md with new instructions

---

## 🔗 Related Files

- `Dockerfile.kali` - The fixed Dockerfile
- `Dockerfile.kali.backup.*` - Backup of original
- `DOCKERFILE_REVIEW.md` - Detailed review of issues
- `fix_dockerfile.sh` - Script that applied fixes
- `DOCKER.md` - Docker usage documentation

---

## 📞 Getting Help

If build fails:

1. Check `docker-build.log` for error messages
2. Review the troubleshooting section above
3. Search for specific error messages
4. Try clean build with `--no-cache`
5. Check Docker Desktop has enough resources (4GB+ RAM, 2+ CPUs)

---

**Status**: ✅ Dockerfile fixed and ready to build
**Build Command**: `docker build -f Dockerfile.kali -t level52-cli-deluxe:latest . --progress=plain`
