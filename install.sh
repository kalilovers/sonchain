#!/bin/bash
# Official Installation Script for Sonchain (Public Version)
# Version: 1.0.0
# License: MIT

set -euo pipefail
trap 'echo "Error: Script failed at line $LINENO"; exit 1' ERR

REPO_OWNER="kalilovers"
REPO_NAME="sonchain"
INSTALL_DIR="/opt/sonchain"
SCRIPT_NAME="sonchain"
CONFIG_DIR="/etc/sonchain"
MIN_DEBIAN=8
MIN_UBUNTU=18.04

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

check_os() {
    echo -e "${YELLOW}Checking OS compatibility...${NC}"
    
    if ! [[ -f /etc/os-release ]]; then
        die "Unsupported operating system"
    fi

    source /etc/os-release
    case $ID in
        debian)
            if (( $(echo "$VERSION_ID < $MIN_DEBIAN" | bc -l) )); then
                die "Debian $VERSION_ID is not supported (Minimum: Debian $MIN_DEBIAN)"
            fi
            ;;
        ubuntu)
            if (( $(echo "$VERSION_ID < $MIN_UBUNTU" | bc -l) )); then
                die "Ubuntu $VERSION_ID is not supported (Minimum: Ubuntu $MIN_UBUNTU)"
            fi
            ;;
        *)
            die "Only Debian/Ubuntu distributions are supported"
            ;;
    esac
}

check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        if ! sudo -n true 2>/dev/null; then
            echo -e "${YELLOW}This operation requires root privileges.${NC}"
            sudo -v || die "Failed to get sudo privileges"
        fi
    fi
}

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    export APT_LISTCHANGES_FRONTEND=none

    local PKGS=(
        apt-transport-https ca-certificates 
        curl wget sudo ed
        python3 python3-pip python3-venv
        iptables iproute2 ipset
        netcat-traditional conntrack
        build-essential git automake autoconf libtool
        jq logrotate attr dnsutils
    )

    echo -e "${GREEN}Updating package lists...${NC}"
    sudo apt-get update -qq 2>/dev/null || {
        echo -e "${RED}Failed to update package lists!${NC}" >&2
        exit 1
    }

    echo -e "${GREEN}Installing required packages...${NC}"
    sudo apt-get install -y --no-install-recommends -qq "${PKGS[@]}" 2>/dev/null || {
        echo -e "${RED}Package installation failed!${NC}" >&2
        exit 1
    }

    echo -e "${GREEN}Installing Python packages...${NC}"
    python3 -m pip install --user --disable-pip-version-check --no-warn-script-location \
        -q requests websockets cryptography || {
        echo -e "${RED}Python package installation failed!${NC}" >&2
        exit 1
    }

    echo -e "${GREEN}Verifying core components...${NC}"
    local critical_commands=("python3" "iptables" "curl" "git")
    local missing=()
    
    for cmd in "${critical_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing components: ${missing[*]}${NC}" >&2
        exit 1
    fi

    echo -e "\n${GREEN}All dependencies installed successfully!${NC}"
}

setup_application() {
    echo -e "${YELLOW}Setting up Sonchain...${NC}"
    
    sudo mkdir -p "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"

    echo -e "${YELLOW}Downloading from public repository...${NC}"
    sudo curl -fsSL "https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/main/sonchain.py" \
        -o "$INSTALL_DIR/sonchain.py"

    sudo chmod 755 "$INSTALL_DIR/sonchain.py"
    
    sudo ln -sf "$INSTALL_DIR/sonchain.py" "/usr/local/bin/sonchain"
}


main() {
    check_os
    check_privileges
    install_dependencies
    setup_application

    echo -e "\n${GREEN}Successfully installed!${NC}"
    echo -e "\n${GREEN}https://github.com/kalilovers/sonchain${NC}"
    echo -e "Run the application with: ${YELLOW}$SCRIPT_NAME${NC}"
    echo -e "Uninstall with: ${YELLOW}sudo $SCRIPT_NAME --uninstall${NC}"
}

main
