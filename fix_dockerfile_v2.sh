#!/bin/bash
# Fix Dockerfile.kali - Build errors v2
# Fixes:
# 1. Remove packages not in Kali repos
# 2. Fix Python externally-managed-environment errors
# 3. Use --break-system-packages for pip (Docker-safe)

set -e

DOCKERFILE="Dockerfile.kali"
BACKUP="Dockerfile.kali.backup.$(date +%Y%m%d_%H%M%S)"

echo "Creating backup: $BACKUP"
cp "$DOCKERFILE" "$BACKUP"

echo "Applying fixes to $DOCKERFILE..."

# Fix 1: Remove rustscan (not in repos) - comment it out
sed -i '' 's/^    rustscan \\/    # rustscan (not in Kali repos) \\/' "$DOCKERFILE"

# Fix 2: Remove rpcclient (not in repos) - comment it out
sed -i '' 's/^    rpcclient \\/    # rpcclient (already in samba-common-bin) \\/' "$DOCKERFILE"

# Fix 3: Remove standalone snmpwalk - comment it out
sed -i '' 's/^    snmpwalk \\/    # snmpwalk (included in snmp package) \\/' "$DOCKERFILE"

# Fix 4: Add --break-system-packages to pip3 install commands
sed -i '' 's/pip3 install --no-cache-dir/pip3 install --break-system-packages --no-cache-dir/g' "$DOCKERFILE"
sed -i '' 's/pip3 install --upgrade/pip3 install --break-system-packages --upgrade/g' "$DOCKERFILE"
sed -i '' 's/pip3 install --force-reinstall/pip3 install --break-system-packages --force-reinstall/g' "$DOCKERFILE"

# Fix pip3 install with -r (requirements files)
sed -i '' 's/pip3 install -r/pip3 install --break-system-packages -r/g' "$DOCKERFILE"

# Fix pip3 install with -e (editable installs)
sed -i '' 's/pip3 install -e/pip3 install --break-system-packages -e/g' "$DOCKERFILE"

# Fix lines that might have double --break-system-packages
sed -i '' 's/--break-system-packages --break-system-packages/--break-system-packages/g' "$DOCKERFILE"

echo ""
echo "✅ Fixes applied successfully!"
echo ""
echo "Changes made:"
echo "  1. ✅ Commented out rustscan (not in Kali repos)"
echo "  2. ✅ Commented out rpcclient (already in samba-common-bin)"
echo "  3. ✅ Commented out snmpwalk (included in snmp package)"
echo "  4. ✅ Added --break-system-packages to all pip3 commands"
echo ""
echo "Backup saved as: $BACKUP"
echo ""
echo "To test the build:"
echo "  docker build -f Dockerfile.kali -t level52-cli-deluxe:test . --progress=plain"
echo ""
