#!/bin/bash
# Official Installation Script for Sonchain (Public Version)
# Version: 1.4.2 (Installer Optimized)
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

# ---------------------- Core Functions ----------------------
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

# ---------------------- Enhanced Package Check ----------------------

test_connection() {
    local url="$1"
    local ipv4_url="${url}"
    local ipv6_url="${url}"

    # Test IPv4 connection
    if curl --connect-timeout 5 -4 -s -o /dev/null -w "%{http_code}" "$ipv4_url" >/dev/null; then
        echo "IPv4"
        return
    fi

    # Test IPv6 connection
    if curl --connect-timeout 5 -6 -s -o /dev/null -w "%{http_code}" "$ipv6_url" >/dev/null; then
        echo "IPv6"
        return
    fi

    die "Failed to connect using both IPv4 and IPv6"
}



is_package_installed() {
    local package="$1"
    
    # Method 1: Check binary existence
    if command -v "$package" &>/dev/null; then
        return 0
    fi
    
    # Method 2: Check dpkg database
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
        return 0
    fi
    
    # Method 3: Check apt policy (improved regex)
    local policy_output
    policy_output=$(apt-cache policy "$package" 2>/dev/null)
    if [[ "$policy_output" =~ Installed:[[:space:]]+([^[:space:]]+) ]]; then
        local installed_status="${BASH_REMATCH[1]}"
        if [[ "$installed_status" != "(none)" ]]; then
            return 0
        fi
    fi
    
    # Method 4: Remove service check for resolvconf (doesn't have a service)
    return 1
}

# ---------------------- resolvconf Handling ----------------------
handle_resolvconf() {
    echo -e "${YELLOW}Handling resolvconf installation...${NC}"

    # Check if already installed using 4 methods
    if is_package_installed "resolvconf"; then
        echo -e "${GREEN}✔ resolvconf is already installed (verified by multiple checks).${NC}"
        return 0
    fi

    # Backup resolv.conf with metadata
    echo -e "${YELLOW}Backing up resolv.conf state...${NC}"
    local RESOLV_BACKUP=$(mktemp)
    local RESOLV_TYPE=$(stat -c "%F" /etc/resolv.conf)
    local RESOLV_TARGET=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
    local RESOLV_PERM=$(stat -c "%a" /etc/resolv.conf)
    local RESOLV_OWNER=$(stat -c "%u:%g" /etc/resolv.conf)
    local RESOLV_LOCK=$(lsattr /etc/resolv.conf 2>/dev/null | grep -o '\-i-')

    sudo cp -a /etc/resolv.conf "$RESOLV_BACKUP"

    # Remove immutable flag if present
    if [[ "$RESOLV_LOCK" == *"i"* ]]; then
        echo -e "${YELLOW}Unlocking resolv.conf...${NC}"
        sudo chattr -i /etc/resolv.conf || {
            sudo rm -f "$RESOLV_BACKUP"
            die "Failed to unlock resolv.conf"
        }
    fi

    # Install resolvconf
    echo -e "${GREEN}Installing resolvconf...${NC}"
    sudo apt-get update -qq
    if ! sudo apt-get install -y resolvconf; then
        echo -e "${YELLOW}Restoring original resolv.conf...${NC}"
        sudo cp -af "$RESOLV_BACKUP" /etc/resolv.conf
        [[ "$RESOLV_LOCK" == *"i"* ]] && sudo chattr +i /etc/resolv.conf
        sudo rm -f "$RESOLV_BACKUP"
        die "Failed to install resolvconf"
    fi

    # Restore original state
    echo -e "${YELLOW}Restoring original network configuration...${NC}"
    sudo rm -f /etc/resolv.conf
    if [[ "$RESOLV_TYPE" == "symbolic link" ]]; then
        sudo ln -sf "$RESOLV_TARGET" /etc/resolv.conf
    else
        sudo cp -af "$RESOLV_BACKUP" /etc/resolv.conf
    fi
    sudo chmod "$RESOLV_PERM" /etc/resolv.conf
    sudo chown "$RESOLV_OWNER" /etc/resolv.conf
    [[ "$RESOLV_LOCK" == *"i"* ]] && sudo chattr +i /etc/resolv.conf
    sudo rm -f "$RESOLV_BACKUP"
}

# ---------------------- Package Installation ----------------------
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
        echo -e "${YELLOW}Warning: Some package lists failed to update, continuing anyway...${NC}" >&2
    }

    echo -e "${GREEN}Installing required packages...${NC}"
    sudo apt-get install -y --no-install-recommends -qq \
        -o Dpkg::Options::="--force-confold" \
        -o Dpkg::Options::="--force-unsafe-io" \
        "${PKGS[@]}" 2>/dev/null || {
        echo -e "${YELLOW}Warning: Some packages may have failed to install${NC}" >&2
    }

    echo -e "${GREEN}Installing Python packages...${NC}"

    # Test connection and determine protocol
    local protocol
    protocol=$(test_connection "https://files.pythonhosted.org")

    if [[ "$protocol" == "IPv4" ]]; then
        python3 -m pip install --user --disable-pip-version-check --no-warn-script-location \
            -q requests packaging || {
            echo -e "${RED}Python package installation failed!${NC}" >&2
            exit 1
        }
    elif [[ "$protocol" == "IPv6" ]]; then
        python3 -m pip install --user --disable-pip-version-check --no-warn-script-location \
            -q requests packaging -i https://mirrors.aliyun.com/pypi/simple/ || {
            echo -e "${RED}Python package installation failed!${NC}" >&2
            exit 1
        }
    fi

    echo -e "${GREEN}Verifying core components...${NC}"
    local critical_commands=("python3" "iptables" "curl" "git" "jq")
    local missing=()
    
    for cmd in "${critical_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing critical components: ${missing[*]}"
    fi

    echo -e "\n${GREEN}All critical dependencies verified!${NC}"
}
# ---------------------- Application Setup ----------------------
setup_application() {
    echo -e "${YELLOW}Setting up Sonchain...${NC}"
    
    sudo mkdir -p "$INSTALL_DIR" || die "❌ Directory creation failed"
    sudo chmod 755 "$INSTALL_DIR"

    echo -e "${YELLOW}Downloading latest release...${NC}"
    local download_url
    download_url=$(fetch_latest_release)
    
    [[ "$download_url" =~ ^https://github.com/.*/releases/download/.*/sonchain.py$ ]] || die "❌ Invalid URL pattern"

    # Test connection and determine protocol
    local protocol
    protocol=$(test_connection "$download_url")

    local temp_file
    temp_file=$(mktemp -p "$INSTALL_DIR" sonchain.py.XXXXXXXXXX)

    if [[ "$protocol" == "IPv4" ]]; then
        if ! sudo curl -4 -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$temp_file" "$download_url"; then
            sudo rm -f "$temp_file"
            die "❌ Download failed! Check network connection"
        fi
    elif [[ "$protocol" == "IPv6" ]]; then
        if ! sudo curl -6 -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$temp_file" "$download_url"; then
            sudo rm -f "$temp_file"
            die "❌ Download failed! Check network connection"
        fi
    fi

    local backup_file
    if [[ -f "${INSTALL_DIR}/sonchain.py" ]]; then
        backup_file="${INSTALL_DIR}/sonchain.py.bak.$(date +%s)"
        sudo mv -f "${INSTALL_DIR}/sonchain.py" "$backup_file" || die "❌ Backup failed"
        echo -e "${GREEN}✔ Backup created: $(basename "$backup_file")${NC}"
    fi

    if sudo mv -f "$temp_file" "${INSTALL_DIR}/sonchain.py"; then
        sudo rm -f "$temp_file"
    else
        [[ -n "$backup_file" ]] && sudo mv -f "$backup_file" "${INSTALL_DIR}/sonchain.py"
        sudo rm -f "$temp_file"
        die "❌ Atomic replacement failed"
    fi

    sudo chmod 755 "${INSTALL_DIR}/sonchain.py"
    sudo ln -sfT "${INSTALL_DIR}/sonchain.py" "/usr/local/bin/${SCRIPT_NAME}" || die "❌ Symlink creation failed"
    sudo rm -f "${INSTALL_DIR}"/sonchain.py.bak.* 2>/dev/null
}

fetch_latest_release() {
    echo -e "${YELLOW}Fetching latest release info...${NC}" >&2
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

    # Test connection and determine protocol
    local protocol
    protocol=$(test_connection "$api_url")

    # Use the appropriate protocol for curl
    if [[ "$protocol" == "IPv4" ]]; then
        local release_info
        release_info=$(curl -4 -fsSL "$api_url" 2>/dev/null) || die "Failed to connect to GitHub"
    elif [[ "$protocol" == "IPv6" ]]; then
        local release_info
        release_info=$(curl -6 -fsSL "$api_url" 2>/dev/null) || die "Failed to connect to GitHub"
    fi

    if ! jq -e '.assets' <<< "$release_info" >/dev/null; then
        die "Invalid GitHub API response"
    fi

    local asset_url
    asset_url=$(jq -r '.assets[] | select(.name == "sonchain.py").browser_download_url' <<< "$release_info" | tr -d '\r\n')

    [[ -z "$asset_url" || "$asset_url" == "null" ]] && die "Asset 'sonchain.py' not found"

    echo "$asset_url"
}

# ---------------------- Main Flow ----------------------
main() {
    check_os
    check_privileges
    handle_resolvconf  # Changed from install_dependencies
    install_dependencies
    setup_application

    echo -e "\n${GREEN}✅ Successfully installed latest version!${NC}"
    echo -e "\nGithub : ${GREEN}https://github.com/${REPO_OWNER}/${REPO_NAME}${NC}"
    echo -e "\nRun With : ${YELLOW}${SCRIPT_NAME}${NC}\n"
}

main
