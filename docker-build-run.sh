#!/bin/bash
# Guardian CLI Deluxe - Kali Linux Docker - Fully Automated Build & Run
# This script handles everything automatically

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Banner
echo -e "${BOLD}${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║     Guardian CLI Deluxe - Kali Linux Docker Builder     ║
║     Fully Automated Build & Deployment                  ║
╚══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

echo -e "${GREEN}✓${NC} Docker found: $(docker --version)"

# Check if Docker Compose is installed
if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}⚠${NC} Docker Compose not found, will use docker build/run"
    USE_COMPOSE=false
else
    if command -v docker compose &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    echo -e "${GREEN}✓${NC} Docker Compose found: $($COMPOSE_CMD --version)"
    USE_COMPOSE=true
fi

# Check if .env file exists, create if not
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠${NC} .env file not found, creating template..."
    cat > .env << 'ENVEOF'
# Guardian CLI Deluxe Environment Variables
# Copy this template and fill in your API keys

# Anthropic (Claude) API Key
ANTHROPIC_API_KEY=

# Google Gemini API Key  
GOOGLE_API_KEY=

# OpenAI API Key (optional)
OPENAI_API_KEY=

# Other settings
GUARDIAN_LOG_LEVEL=INFO
GUARDIAN_MAX_WORKERS=4
ENVEOF
    echo -e "${GREEN}✓${NC} Created .env template - please edit it with your API keys"
    echo -e "${YELLOW}⚠${NC} At minimum, you need ANTHROPIC_API_KEY or GOOGLE_API_KEY"
fi

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Parse command line arguments
ACTION=${1:-all}

case $ACTION in
    build)
        echo -e "\n${BOLD}=== Building Docker Image ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD build --no-cache
        else
            docker build -t guardian-cli-deluxe:kali-latest -f Dockerfile.kali .
        fi
        echo -e "\n${GREEN}✓${NC} Build complete!"
        ;;
    
    run)
        echo -e "\n${BOLD}=== Starting Guardian Container ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD up -d
            echo -e "\n${GREEN}✓${NC} Container started!"
            echo -e "\nTo attach to the container:"
            echo -e "  ${BLUE}$COMPOSE_CMD exec guardian-kali bash${NC}"
        else
            docker run -it --rm \
                --name guardian-kali \
                --hostname guardian-kali \
                -v $(pwd):/guardian \
                -v guardian-reports:/guardian/reports \
                -v guardian-logs:/guardian/logs \
                -v guardian-data:/guardian/data \
                -e ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY} \
                -e GOOGLE_API_KEY=${GOOGLE_API_KEY} \
                -e OPENAI_API_KEY=${OPENAI_API_KEY} \
                --cap-add=NET_ADMIN \
                --cap-add=NET_RAW \
                guardian-cli-deluxe:kali-latest
        fi
        ;;
    
    shell|bash)
        echo -e "\n${BOLD}=== Opening Shell in Container ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD exec guardian-kali bash
        else
            CONTAINER_ID=$(docker ps -q -f name=guardian-kali)
            if [ -z "$CONTAINER_ID" ]; then
                echo -e "${YELLOW}⚠${NC} Container not running, starting it..."
                docker run -it --rm \
                    --name guardian-kali \
                    -v $(pwd):/guardian \
                    -e ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY} \
                    -e GOOGLE_API_KEY=${GOOGLE_API_KEY} \
                    guardian-cli-deluxe:kali-latest
            else
                docker exec -it guardian-kali bash
            fi
        fi
        ;;
    
    stop)
        echo -e "\n${BOLD}=== Stopping Container ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD down
        else
            docker stop guardian-kali 2>/dev/null || true
        fi
        echo -e "${GREEN}✓${NC} Container stopped"
        ;;
    
    clean)
        echo -e "\n${BOLD}=== Cleaning Up ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD down -v
        else
            docker stop guardian-kali 2>/dev/null || true
            docker rm guardian-kali 2>/dev/null || true
        fi
        docker rmi guardian-cli-deluxe:kali-latest 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Cleanup complete"
        ;;
    
    logs)
        echo -e "\n${BOLD}=== Container Logs ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD logs -f
        else
            docker logs -f guardian-kali
        fi
        ;;
    
    test)
        echo -e "\n${BOLD}=== Testing Guardian Installation ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD exec guardian-kali python -m cli.main --version
            $COMPOSE_CMD exec guardian-kali python -m cli.main workflow list
        else
            docker exec guardian-kali python -m cli.main --version
            docker exec guardian-kali python -m cli.main workflow list
        fi
        echo -e "\n${GREEN}✓${NC} Guardian is working!"
        ;;
    
    scan)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Please provide a target${NC}"
            echo "Usage: $0 scan <target>"
            exit 1
        fi
        TARGET=$2
        echo -e "\n${BOLD}=== Running Scan Against $TARGET ===${NC}\n"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD exec guardian-kali python -m cli.main workflow run --name network_pentest --target $TARGET
        else
            docker exec guardian-kali python -m cli.main workflow run --name network_pentest --target $TARGET
        fi
        ;;
    
    all|*)
        echo -e "\n${BOLD}=== Full Automated Build & Run ===${NC}\n"
        
        # Build
        echo -e "${BOLD}Step 1/3: Building Docker image...${NC}"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD build
        else
            docker build -t guardian-cli-deluxe:kali-latest -f Dockerfile.kali .
        fi
        echo -e "${GREEN}✓${NC} Build complete!\n"
        
        # Start
        echo -e "${BOLD}Step 2/3: Starting container...${NC}"
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD up -d
        else
            docker run -d \
                --name guardian-kali \
                --hostname guardian-kali \
                -v $(pwd):/guardian \
                -v guardian-reports:/guardian/reports \
                -v guardian-logs:/guardian/logs \
                -e ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY} \
                -e GOOGLE_API_KEY=${GOOGLE_API_KEY} \
                guardian-cli-deluxe:kali-latest \
                tail -f /dev/null
        fi
        echo -e "${GREEN}✓${NC} Container started!\n"
        
        # Test
        echo -e "${BOLD}Step 3/3: Testing installation...${NC}"
        sleep 2
        if [ "$USE_COMPOSE" = true ]; then
            $COMPOSE_CMD exec guardian-kali python3 --version
            $COMPOSE_CMD exec guardian-kali which nmap
            $COMPOSE_CMD exec guardian-kali which enum4linux
        else
            docker exec guardian-kali python3 --version
            docker exec guardian-kali which nmap
            docker exec guardian-kali which enum4linux
        fi
        echo -e "${GREEN}✓${NC} All tests passed!\n"
        
        # Summary
        echo -e "${BOLD}${GREEN}=== Guardian CLI Deluxe is Ready! ===${NC}\n"
        echo -e "Container: ${BLUE}guardian-kali${NC}"
        echo -e "\nQuick commands:"
        if [ "$USE_COMPOSE" = true ]; then
            echo -e "  Enter shell:     ${BLUE}$COMPOSE_CMD exec guardian-kali bash${NC}"
            echo -e "  View logs:       ${BLUE}$COMPOSE_CMD logs -f${NC}"
            echo -e "  Stop container:  ${BLUE}$COMPOSE_CMD down${NC}"
        else
            echo -e "  Enter shell:     ${BLUE}docker exec -it guardian-kali bash${NC}"
            echo -e "  View logs:       ${BLUE}docker logs -f guardian-kali${NC}"
            echo -e "  Stop container:  ${BLUE}docker stop guardian-kali${NC}"
        fi
        echo -e "\nInside container:"
        echo -e "  Run workflow:    ${BLUE}python -m cli.main workflow run --name network_pentest --target <target>${NC}"
        echo -e "  List workflows:  ${BLUE}python -m cli.main workflow list${NC}"
        echo -e "  Help:            ${BLUE}python -m cli.main --help${NC}"
        ;;
esac

echo ""
