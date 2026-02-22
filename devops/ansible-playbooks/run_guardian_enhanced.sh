#!/bin/bash
# Script to run the enhanced Guardian playbook on remote server
# This will install all missing tools that were showing warnings

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${SCRIPT_DIR}/inventory/hosts.ini"
PLAYBOOK="${SCRIPT_DIR}/remote_playbook_guardian_enhanced.yml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Guardian Enhanced Playbook Runner${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if inventory exists
if [ ! -f "$INVENTORY" ]; then
    echo -e "${RED}ERROR: Inventory file not found: $INVENTORY${NC}"
    exit 1
fi

# Check if playbook exists
if [ ! -f "$PLAYBOOK" ]; then
    echo -e "${RED}ERROR: Playbook not found: $PLAYBOOK${NC}"
    exit 1
fi

# Show current configuration
echo -e "${YELLOW}Configuration:${NC}"
echo "  Inventory: $INVENTORY"
echo "  Playbook:  $PLAYBOOK"
echo ""

# Show target hosts
echo -e "${YELLOW}Target hosts:${NC}"
ansible -i "$INVENTORY" guardian_workers --list-hosts
echo ""

# Test connectivity
echo -e "${YELLOW}Testing connectivity...${NC}"
if ansible -i "$INVENTORY" guardian_workers -m ping; then
    echo -e "${GREEN}✓ All hosts reachable${NC}"
else
    echo -e "${RED}✗ Some hosts unreachable${NC}"
    echo -e "${YELLOW}Continue anyway? (y/N)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi
echo ""

# Ask for confirmation
echo -e "${YELLOW}This will:${NC}"
echo "  1. Install all missing security tools (testssl, jwt_tool, etc.)"
echo "  2. Create wrapper scripts for Python-based tools"
echo "  3. Install Go, Python, npm-based security tools"
echo "  4. Download and configure Docker images (ZAP, BloodHound)"
echo "  5. Re-run Guardian setup.sh to ensure everything is configured"
echo ""
echo -e "${YELLOW}Estimated time: 30-45 minutes${NC}"
echo ""
echo -e "${YELLOW}Continue? (y/N)${NC}"
read -r response

if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Run the playbook
echo ""
echo -e "${GREEN}Starting playbook execution...${NC}"
echo ""

# Run with verbose output
ansible-playbook -i "$INVENTORY" "$PLAYBOOK" -v

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Playbook execution completed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. SSH into your server:"
echo "     ssh 52pickup@192.168.1.148"
echo ""
echo "  2. Verify tools are installed:"
echo "     which testssl jwt_tool graphqlcop xsstrike"
echo ""
echo "  3. Test Guardian:"
echo "     cd ~/level52-cli-deluxe"
echo "     source venv/bin/activate"
echo "     python -m cli.main workflow run --name recon --target 192.168.1.232"
echo ""
echo "  4. Check for missing tool warnings (should be none!)"
echo ""
