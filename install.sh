#!/bin/bash
# Official Installation Script for Sonchain (Public Version)
# Version: 1.4.5 (Installer Updated)
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

MIN_PYTHON="3.6"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=6


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





#=====================================
#### Installing python3 packs

	echo -e "${GREEN}Checking Python version...${NC}"
	local python_version python_major python_minor
	python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" || die "Python3 not found")
	python_major=$(python3 -c "import sys; print(sys.version_info.major)")
	python_minor=$(python3 -c "import sys; print(sys.version_info.minor)")

	if [ "$python_major" -lt 3 ]; then
		die "Python version $python_version is not supported (Minimum required: 3.9)"
	elif [ "$python_major" -eq 3 ] && [ "$python_minor" -lt 9 ]; then
		die "Python version $python_version is not supported (Minimum required: 3.9)"
	fi


	echo -e "${GREEN}Installing Python packages...${NC}"


    try_pip_install() {
        python3 -m pip install --user --disable-pip-version-check --no-warn-script-location "$@" -q requests packaging
    }

    if ! try_pip_install; then
        echo -e "${YELLOW}Retrying with aliyun mirror...${NC}"
        if ! try_pip_install -i https://mirrors.aliyun.com/pypi/simple/; then
            echo -e "${YELLOW}Trying with --break-system-packages...${NC}"
            if ! try_pip_install --break-system-packages; then
                echo -e "${YELLOW}Retrying with aliyun mirror and --break-system-packages...${NC}"
                try_pip_install --break-system-packages -i https://mirrors.aliyun.com/pypi/simple/ || \
                    die "Python package installation failed!"
            fi
        fi
    fi

    echo -e "${GREEN}Verifying core components...${NC}"
    local critical_commands=("python3" "curl" "git" "jq")
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

#=====================================


# ---------------------- Application Setup ----------------------
setup_application() {
    echo -e "${YELLOW}Setting up Sonchain...${NC}"
    

	local temp_dir=$(mktemp -d -p /tmp sonchain_install.XXXXXXXXXX) || die "Failed to create temp dir"
	temp_dir=${temp_dir:-}
	trap 'sudo rm -rf "${temp_dir:-}"; echo -e "${RED}Cleaning temporary files${NC}"' EXIT

    # Step 1: Fetch download URL
    echo -e "${YELLOW}Fetching latest release...${NC}"
    local download_url
    download_url=$(fetch_latest_release)
    
    # Validate URL pattern
    [[ "$download_url" =~ ^https://github.com/.*/releases/download/.*/sonchain.tar.gz$ ]] || die "❌ Invalid asset format"

    # Step 2: Download tarball
    local tarball_path="${temp_dir}/sonchain.tar.gz"
    echo -e "${YELLOW}Downloading package...${NC}"
    if ! curl -4 -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$tarball_path" "$download_url"; then
        echo -e "${YELLOW}IPv4 failed, trying IPv6...${NC}"
        curl -6 -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$tarball_path" "$download_url" || die "❌ Download failed"
    fi

#     Step 3: Validate tarball
#    echo -e "${YELLOW}Validating package...${NC}"
#    if ! tar -tzf "$tarball_path" | grep -q 'main.py'; then
#        die "❌ Invalid tarball content"
#    fi

	# Step 4: Backup existing installation
	local timestamp=$(date +%Y%m%d-%H%M%S)
	local backup_path="/opt/sonchain-backup-${timestamp}"
	if [[ -d "$INSTALL_DIR" ]]; then
		echo -e "${YELLOW}Creating backup...${NC}"
		sudo mv -f "$INSTALL_DIR" "$backup_path" || die "❌ Backup failed"
		trap 'rollback_backup "$backup_path"' ERR
	fi

    # Step 5: Atomic installation
    (
        echo -e "${YELLOW}Installing new version...${NC}"
        sudo mkdir -p "$INSTALL_DIR" || exit 1
        sudo tar --warning=no-timestamp -xzf "$tarball_path" -C "$INSTALL_DIR" --strip-components=0 || exit 1
        
        echo -e "${YELLOW}Setting permissions...${NC}"
        sudo find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
        sudo find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
		sudo find "$INSTALL_DIR/src" -type f -name "*.py" -exec chmod 755 {} \;
        sudo chmod 755 "${INSTALL_DIR}/main.py"
        
        echo -e "${YELLOW}Creating symlink...${NC}"
        sudo ln -sfT "${INSTALL_DIR}/main.py" "/usr/local/bin/${SCRIPT_NAME}" || exit 1
    ) || die "❌ Installation failed"

    # Step 6: Cleanup
    [[ -d "$backup_path" ]] && sudo rm -rf "$backup_path"
    echo -e "\n${GREEN}✅ The project download and placement steps were completed successfully!${NC}"
}

rollback_backup() {
    local backup_path="$1"
    if [[ -d "$backup_path" ]]; then
        echo -e "${YELLOW}Restoring backup...${NC}"
        sudo mv -f "$backup_path" "$INSTALL_DIR"
    fi
    die "❌ Installation rolled back"
}

fetch_latest_release() {
    echo -e "${YELLOW}Fetching release info...${NC}" >&2
    local api_url="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
    
    # Try IPv4 first
    local release_info=$(curl -4 -fsSL --max-time 30 "$api_url" 2>/dev/null) || {
        # Fallback to IPv6
        echo -e "${YELLOW}IPv4 failed, trying IPv6...${NC}" >&2
        release_info=$(curl -6 -fsSL --max-time 30 "$api_url" 2>/dev/null) || die "Failed to connect to GitHub"
    }
    
    # Validate response
    jq -e '.assets' <<< "$release_info" >/dev/null || die "Invalid GitHub API response"
    
    # Extract asset URL
    local asset_url=$(jq -r '.assets[] | select(.name == "sonchain.tar.gz").browser_download_url' <<< "$release_info" | tr -d '\r\n')
    
    [[ -n "$asset_url" ]] || die "❌ Asset 'sonchain.tar.gz' not found"
    
    echo "$asset_url"
}
# ---------------------- Main Flow ----------------------
main() {
    check_os
    check_privileges
    handle_resolvconf
    install_dependencies
    setup_application

    echo -e "\n${GREEN}✅ Successfully installed latest version!${NC}"
    echo -e "\nGithub : ${GREEN}https://github.com/${REPO_OWNER}/${REPO_NAME}${NC}"
    echo -e "\nRun With : ${YELLOW}${SCRIPT_NAME}${NC}\n"
}

main
