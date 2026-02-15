#!/bin/bash
# Script to apply fixes to Dockerfile.kali
# This fixes:
# 1. Trivy installation (broken apt repo)
# 2. Adds kiterunner
# 3. Adds retire.js
# 4. Fixes god-eye installation

set -e

DOCKERFILE="Dockerfile.kali"
BACKUP="Dockerfile.kali.backup.$(date +%Y%m%d_%H%M%S)"

echo "Creating backup: $BACKUP"
cp "$DOCKERFILE" "$BACKUP"

echo "Applying fixes to $DOCKERFILE..."

# Create temp file for modifications
TMP_FILE=$(mktemp)

# Fix 1: Replace Trivy installation (lines 184-191)
sed -n '1,183p' "$DOCKERFILE" > "$TMP_FILE"

cat >> "$TMP_FILE" << 'EOF'

# Install Trivy (vulnerability/secret/config scanner) - BINARY METHOD (FIXED)
RUN echo "Installing Trivy via binary..." && \
    TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    echo "Trivy version: ${TRIVY_VERSION}" && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /tmp/ && \
    mv /tmp/trivy /usr/local/bin/trivy && \
    chmod +x /usr/local/bin/trivy && \
    rm -f /tmp/trivy.tar.gz && \
    trivy --version

EOF

# Skip old Trivy lines (184-191) and continue from 192
sed -n '192,228p' "$DOCKERFILE" >> "$TMP_FILE"

# Fix 2: Replace god-eye installation (lines 229-231)
cat >> "$TMP_FILE" << 'EOF'
# Install god-eye (comprehensive recon tool) - FIXED
RUN echo "Installing god-eye..." && \
    (go install -v github.com/Vyntral/god-eye@latest && \
     ln -sf ${GOPATH}/bin/god-eye /usr/local/bin/godeye) || \
    echo "Warning: god-eye installation failed - this is non-critical"

EOF

# Continue from line 232 to line 410 (end of git-cloned tools)
sed -n '232,410p' "$DOCKERFILE" >> "$TMP_FILE"

# Fix 3: Add kiterunner and retire.js after git-cloned tools
cat >> "$TMP_FILE" << 'EOF'

# ============================================================================
# STAGE 9: Install Additional Missing Tools (ADDED)
# ============================================================================

# Install kiterunner (API endpoint discovery)
RUN echo "Installing kiterunner..." && \
    KR_VERSION=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') && \
    echo "Kiterunner version: ${KR_VERSION}" && \
    curl -sSL "https://github.com/assetnote/kiterunner/releases/download/v${KR_VERSION}/kiterunner_${KR_VERSION}_linux_amd64.tar.gz" -o /tmp/kiterunner.tar.gz && \
    tar -xzf /tmp/kiterunner.tar.gz -C /tmp/ && \
    mv /tmp/kr /usr/local/bin/kr && \
    chmod +x /usr/local/bin/kr && \
    rm -f /tmp/kiterunner.tar.gz && \
    (kr --version || echo "kiterunner installed (version check may fail)")

# Install retire.js (JavaScript library vulnerability scanner)
RUN echo "Installing retire.js..." && \
    npm config set prefix /usr/local && \
    npm install -g retire && \
    retire --version

EOF

# Continue with the rest of the file from line 411
sed -n '411,$p' "$DOCKERFILE" >> "$TMP_FILE"

# Replace original with fixed version
mv "$TMP_FILE" "$DOCKERFILE"

echo ""
echo "✅ Fixes applied successfully!"
echo ""
echo "Changes made:"
echo "  1. ✅ Fixed Trivy installation (binary method instead of apt)"
echo "  2. ✅ Fixed god-eye installation (go install method)"
echo "  3. ✅ Added kiterunner installation"
echo "  4. ✅ Added retire.js installation"
echo ""
echo "Backup saved as: $BACKUP"
echo ""
echo "To test the build:"
echo "  docker build -f Dockerfile.kali -t level52-cli-deluxe:test . --progress=plain"
echo ""
