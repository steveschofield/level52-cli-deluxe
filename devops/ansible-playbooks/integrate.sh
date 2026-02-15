#!/bin/bash
# Integration script to install missing tools both locally and remotely
# This updates the main Guardian setup across all environments

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="${SCRIPT_DIR}/inventory/hosts.ini"
MISSING_TOOLS_PLAYBOOK="${SCRIPT_DIR}/install_missing_tools.yml"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Guardian Tools Integration${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

show_menu() {
    echo -e "${YELLOW}What would you like to do?${NC}"
    echo ""
    echo "  1) Install missing tools on LOCAL machine (this Mac/Linux)"
    echo "  2) Install missing tools on REMOTE server (via Ansible)"
    echo "  3) Install on BOTH local and remote"
    echo "  4) Just show what's missing"
    echo "  5) Exit"
    echo ""
    echo -n "Choose [1-5]: "
}

check_missing_tools() {
    echo -e "${BLUE}Checking for missing tools...${NC}"
    echo ""

    MISSING=()

    # Check each tool
    for tool in testssl kr jwt_tool graphqlcop arjun xsstrike cmseek retire \
                linkfinder xnlinkfinder paramspider schemathesis feroxbuster \
                godeye corsscanner trivy; do
        if ! command -v "$tool" &> /dev/null; then
            MISSING+=("$tool")
        fi
    done

    if [ ${#MISSING[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All tools are installed!${NC}"
        return 0
    else
        echo -e "${YELLOW}Missing tools:${NC}"
        for tool in "${MISSING[@]}"; do
            echo "  ✗ $tool"
        done
        echo ""
        return 1
    fi
}

install_local() {
    echo -e "${BLUE}Installing missing tools locally...${NC}"
    echo ""

    if [ -f "${SCRIPT_DIR}/../../ansible-playbooks/local_playbook_kali.yml" ]; then
        # Use the claude-worktrees version
        PLAYBOOK="${SCRIPT_DIR}/../../ansible-playbooks/local_playbook_kali.yml"
    else
        # Use install_missing_tools.yml
        PLAYBOOK="${MISSING_TOOLS_PLAYBOOK}"
    fi

    echo "Running: ansible-playbook -K $PLAYBOOK --connection=local"
    echo ""

    ansible-playbook -K "$PLAYBOOK" --connection=local --inventory localhost,
}

install_remote() {
    echo -e "${BLUE}Installing missing tools on remote server(s)...${NC}"
    echo ""

    # Check inventory
    if [ ! -f "$INVENTORY" ]; then
        echo -e "${RED}ERROR: Inventory file not found: $INVENTORY${NC}"
        exit 1
    fi

    # Test connectivity
    echo "Testing connectivity to remote hosts..."
    if ansible -i "$INVENTORY" guardian_workers -m ping; then
        echo -e "${GREEN}✓ All hosts reachable${NC}"
    else
        echo -e "${RED}✗ Some hosts unreachable${NC}"
        return 1
    fi
    echo ""

    # Show target hosts
    echo -e "${YELLOW}Installing on:${NC}"
    ansible -i "$INVENTORY" guardian_workers --list-hosts
    echo ""

    # Run playbook
    echo "Running: ansible-playbook -i $INVENTORY $MISSING_TOOLS_PLAYBOOK"
    echo ""

    ansible-playbook -i "$INVENTORY" "$MISSING_TOOLS_PLAYBOOK"
}

verify_installation() {
    echo ""
    echo -e "${BLUE}Verifying installation...${NC}"
    echo ""

    check_missing_tools

    echo ""
    echo -e "${YELLOW}Test Guardian:${NC}"
    echo "  cd ~/level52-cli-deluxe"
    echo "  source venv/bin/activate"
    echo "  python -m cli.main workflow run --name recon --target scanme.nmap.org"
    echo ""
}

# Main menu loop
while true; do
    show_menu
    read -r choice

    case $choice in
        1)
            echo ""
            install_local
            verify_installation
            ;;
        2)
            echo ""
            install_remote
            echo ""
            echo -e "${GREEN}Remote installation complete!${NC}"
            echo -e "${YELLOW}SSH into your server to verify:${NC}"
            echo "  ssh 52pickup@192.168.1.148"
            echo "  which testssl kr jwt_tool graphqlcop"
            ;;
        3)
            echo ""
            echo -e "${BLUE}Installing on both local and remote...${NC}"
            echo ""
            install_local
            echo ""
            install_remote
            verify_installation
            ;;
        4)
            echo ""
            check_missing_tools
            ;;
        5)
            echo ""
            echo "Exiting."
            exit 0
            ;;
        *)
            echo ""
            echo -e "${RED}Invalid choice. Please choose 1-5.${NC}"
            echo ""
            ;;
    esac

    echo ""
    echo -e "${BLUE}Press Enter to continue...${NC}"
    read -r
    echo ""
done
