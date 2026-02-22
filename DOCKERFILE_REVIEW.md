# Dockerfile.kali - Comprehensive Review & Fixes

## 🔍 Current Status Analysis

**File**: `Dockerfile.kali`
**Size**: 651 lines
**Purpose**: Build Level52 CLI Deluxe in a Kali Linux Docker container with full tool parity

## ⚠️ Known Issues Found

### 1. **Trivy Installation - BROKEN** (Lines 185-191)

**Problem**:

```dockerfile
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy
```

**Issue**: Kali Linux's codename isn't supported by Trivy's Debian repository. This will fail during build.

**Fix**: Use binary installation instead:

```dockerfile
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp/ && \
    mv /tmp/trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f /tmp/trivy.tar.gz && \
    trivy --version
```

---

### 2. **Missing Tools from Ansible Playbook**

The Dockerfile is missing several tools that we added to the Ansible playbook:

| Tool         | Status in Dockerfile    |
| ------------ | ----------------------- |
| testssl      | ✅ Included (line 332)  |
| jwt_tool     | ✅ Included (line 361)  |
| graphql-cop  | ✅ Included (line 375)  |
| arjun        | ✅ Included (line 290)  |
| xsstrike     | ✅ Included (line 336)  |
| cmseek       | ✅ Included (line 342)  |
| retire.js    | ❌**MISSING**     |
| linkfinder   | ✅ Included (line 382)  |
| xnlinkfinder | ✅ Included (line 297)  |
| paramspider  | ✅ Included (line 389)  |
| schemathesis | ✅ Included (line 292)  |
| feroxbuster  | ✅ Included (line 241)  |
| godeye       | ✅ Included (line 229)  |
| corsscanner  | ✅ Included (line 406)  |
| trivy        | ⚠️ Broken (needs fix) |

**Missing Tools**:

2. **retire.js** - JavaScript vulnerability scanner

---

### 3. **God-Eye Build Might Fail** (Line 229-231)

**Problem**:

```dockerfile
RUN git clone --depth 1 https://github.com/Vyntral/god-eye.git /opt/tools/god-eye && \
    cd /opt/tools/god-eye && \
    go build -o /usr/local/bin/god-eye ./cmd/god-eye 2>/dev/null || echo "god-eye build failed - skipping"
```

**Issue**: Silently fails if build errors occur. Should use `go install` instead.

**Fix**:

```dockerfile
RUN go install -v github.com/Vyntral/god-eye@latest 2>/dev/null || \
    echo "Warning: god-eye installation failed"
```

---

### 4. **Potential npm Not Configured Globally**

For retire.js and other npm tools, need to ensure npm global prefix is set correctly.

---

## ✅ Recommended Fixes

### Fix Priority 1: Critical Fixes

```dockerfile
# BEFORE (around line 184-191) - REMOVE THIS
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    trivy --version

# AFTER - ADD THIS INSTEAD
RUN TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp/ && \
    mv /tmp/trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f /tmp/trivy.tar.gz && \
    trivy --version
```

### Fix Priority 2: Add Missing Tools

Add after line 410 (after git-cloned tools section):

```dockerfile
# ============================================================================
# ============================================================================


# Install retire.js via npm
RUN npm install -g retire && \
    retire --version
```

### Fix Priority 3: Copy Guardian Source Code Earlier

Move the `COPY . /guardian` command to around line 550 (BEFORE pip install attempts).

Current location (around line 550):

```dockerfile
# Guardian installation
COPY . /guardian
RUN cd /guardian && pip3 install -e .
```

Should verify this is in correct order.

---

## 📋 Complete Fixed Dockerfile Sections

### Section 1: Trivy Installation (Replace lines 184-191)

```dockerfile
# ============================================================================
# Install Trivy (vulnerability/secret/config scanner) - BINARY METHOD
# ============================================================================
RUN echo "Installing Trivy..." && \
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    echo "Trivy version: ${TRIVY_VERSION}" && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp/ && \
    mv /tmp/trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f /tmp/trivy.tar.gz && \
    trivy --version
```

### Section 2: Add Missing Tools (Insert after line 410)

```dockerfile
# ============================================================================
# STAGE 9: Install Additional Missing Tools
# ============================================================================


# Install retire.js (JavaScript library vulnerability scanner)
RUN echo "Installing retire.js..." && \
    npm config set prefix /usr/local && \
    npm install -g retire && \
    retire --version
```

### Section 3: Fix god-eye Installation (Replace lines 229-231)

```dockerfile
# Install god-eye (comprehensive recon tool)
RUN echo "Installing god-eye..." && \
    go install -v github.com/Vyntral/god-eye@latest && \
    ln -sf ${GOPATH}/bin/god-eye /usr/local/bin/godeye || \
    echo "Warning: god-eye installation failed or binary not found"
```

---

## 🧪 Testing the Build

### Test Build Command

```bash
cd /Users/ss/.claude-worktrees/level52-cli-deluxe/strange-khorana

# Build with verbose output
docker build -f Dockerfile.kali -t level52-cli-deluxe:test . --progress=plain

# Or build without cache (clean build)
docker build --no-cache -f Dockerfile.kali -t level52-cli-deluxe:test . --progress=plain
```

### Test Build in Stages

To test specific stages without building everything:

```bash
# Test up to STAGE 3 (SAST tools)
docker build -f Dockerfile.kali --target <stage-name> -t guardian-test:stage3 .

# But since there are no named stages, build and stop on error
docker build -f Dockerfile.kali -t guardian-test . 2>&1 | tee build.log
```

### Quick Verification After Build

```bash
# Run container
docker run -it --rm level52-cli-deluxe:test /bin/bash

# Inside container, verify tools
which testssl jwt_tool graphqlcop xsstrike cmseek \
      linkfinder xnlinkfinder paramspider feroxbuster \
      godeye corsscanner trivy retire

# Check versions
trivy --version
retire --version
feroxbuster --version

# Test Guardian
python -m cli.main --help
```

---

## 📊 Build Time Estimates

| Stage            | Estimated Time          | Can Fail?                  |
| ---------------- | ----------------------- | -------------------------- |
| Base packages    | 5-10 min                | Low risk                   |
| Kali tools (apt) | 10-15 min               | Low risk                   |
| SAST tools       | 3-5 min                 | ⚠️ Trivy (fixed now)     |
| Go tools         | 5-10 min                | Medium risk                |
| Rust tools       | 10-20 min               | High (feroxbuster compile) |
| Python tools     | 5-10 min                | Low risk                   |
| Git-cloned tools | 5-10 min                | Low risk                   |
| Guardian install | 2-5 min                 | Low risk                   |
| **TOTAL**  | **45-85 minutes** |                            |

---

## 🚀 Optimizations for Faster Builds

### 1. Use Multi-Stage Build

```dockerfile
# Build stage
FROM kalilinux/kali-rolling:latest AS builder
# ... install build tools, compile stuff

# Runtime stage
FROM kalilinux/kali-rolling:latest
# ... copy only binaries from builder
```

### 2. Layer Caching Strategy

- Group frequently changing layers at the end
- Put static dependencies first
- Guardian source code should be near the end

### 3. Parallel Builds

Some RUN commands can be combined to run in parallel.

---

## ✅ Final Checklist Before Build

- [ ] Replace Trivy installation (lines 184-191)
- [ ] Add retire.js installation
- [ ] Fix god-eye installation
- [ ] Verify Guardian source copied before pip install
- [ ] Test build with `--progress=plain` for debugging
- [ ] Verify all tools after successful build

---

## 📝 Recommended Next Steps

1. **Apply fixes** to Dockerfile.kali
2. **Test build** locally
3. **Verify all tools** are present
4. **Document** final working version
5. **Commit** to git
6. **Push** to GitHub

---

## 🔗 Related Files

- `Dockerfile.kali` - The Dockerfile being reviewed
- `setup.sh` - Native setup script (reference for tool list)
- `DOCKER.md` - Docker documentation
- `devops/ansible-playbooks/install_missing_tools.yml` - Ansible equivalent

---

**Status**: Ready for fixes to be applied
**Priority**: High (build currently broken due to Trivy)
**Complexity**: Medium (straightforward fixes)
