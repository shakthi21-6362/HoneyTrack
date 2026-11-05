# =============================================================================
# HoneyTrack - Quick Deploy Script (Linux / macOS / WSL)
# Usage: ./deploy.sh [--demo | --prod | --timescale | --timescale-prod | --down | --logs]
# =============================================================================
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "  _   _                        _____               _    "
echo " | | | | ___  _ __   ___ _   _|_   _| __ __ _  ___| | __"
echo " | |_| |/ _ \| '_ \ / _ \ | | | | | | '__/ _\` |/ __| |/ /"
echo " |  _  | (_) | | | |  __/ |_| | | | | | | (_| | (__|   < "
echo " |_| |_|\___/|_| |_|\___|\__, | |_| |_|  \__,_|\___|_|\_\\"
echo "                          |___/                          "
echo -e "${GREEN}==> HoneyTrack Docker 1-Command Deployment <==${NC}"
echo ""

# Ensure .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}[!] .env not found. Creating from .env.example with random SECRET_KEY...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        touch .env
    fi
    # Generate random secret key if openssl is available
    if command -v openssl >/dev/null 2>&1; then
        RAND_KEY=$(openssl rand -hex 32)
        if grep -q "SECRET_KEY=" .env; then
            sed -i.bak "s/SECRET_KEY=.*/SECRET_KEY=$RAND_KEY/" .env && rm -f .env.bak
        else
            echo "SECRET_KEY=$RAND_KEY" >> .env
        fi
    fi
    echo -e "${GREEN}[+] Created .env file.${NC}"
fi

# Ensure data and ssh_keys directories exist
mkdir -p data ssh_keys

MODE="${1:-demo}"

case "$MODE" in
    --down|down)
        echo -e "${YELLOW}[*] Stopping HoneyTrack containers...${NC}"
        docker compose --profile timescale down
        echo -e "${GREEN}[+] HoneyTrack stopped.${NC}"
        exit 0
        ;;
    --logs|logs)
        docker compose logs -f
        exit 0
        ;;
    --timescale|timescale|--ts|ts)
        echo -e "${CYAN}[*] Deploying HoneyTrack with TimescaleDB / PostgreSQL time-series backend (DEMO mode)...${NC}"
        docker compose --profile timescale up -d --build
        ;;
    --timescale-prod|timescale-prod|--tsprod)
        echo -e "${CYAN}[*] Deploying HoneyTrack with TimescaleDB / PostgreSQL backend (PRODUCTION live sensors only)...${NC}"
        docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile timescale up -d --build
        ;;
    --prod|prod)
        echo -e "${BLUE}[*] Deploying HoneyTrack in PRODUCTION mode (live sensors only, SQLite)...${NC}"
        docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile default up -d
        ;;
    --demo|demo|*)
        echo -e "${BLUE}[*] Deploying HoneyTrack in DEMO mode (sensors + simulated adversary feed, SQLite)...${NC}"
        docker compose --profile default up -d
        ;;
esac

echo ""
echo -e "${GREEN}===================================================================${NC}"
echo -e "${GREEN} [✓] HoneyTrack deployed successfully!                             ${NC}"
echo -e "${GREEN}===================================================================${NC}"
echo -e "  🌐 Dashboard:       ${BLUE}http://localhost:5000${NC}"
echo -e "  🛡️  SSH Honeypot:    ${YELLOW}port 2222${NC}"
echo -e "  🌐 HTTP Honeypot:   ${YELLOW}port 8080${NC}"
echo -e "  📁 FTP Honeypot:    ${YELLOW}port 2121${NC}"
if [[ "$MODE" == *"timescale"* || "$MODE" == *"ts"* ]]; then
echo -e "  🐘 TimescaleDB:     ${CYAN}port 5432 (hypertables active)${NC}"
fi
echo ""
echo -e "  View logs:          ${BLUE}docker compose logs -f${NC} or ${BLUE}./deploy.sh --logs${NC}"
echo -e "  Stop HoneyTrack:    ${BLUE}./deploy.sh --down${NC}"
echo -e "${GREEN}===================================================================${NC}"
