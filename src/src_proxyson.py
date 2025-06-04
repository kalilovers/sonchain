#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_utils
from src import src_menus
from src import src_status
from src import src_remover
from src import src_tor

#modules >
import os
import re



# -------------------- ProxysonManager --------------------




def handle_proxyson_setup():
    # ProxySon Setup Handler: Manages the ProxySon setup menu and its operations.
    while True:
        src_menus.display_proxyson_menu()
        proxy_choice = input("\nSelect an option : ").strip()
        
        if proxy_choice == '0':
            break
        elif proxy_choice == '1':
            src_status.proxyson_status()
            input("\nPress Enter to Return...")

        elif proxy_choice == '2':
            install_proxyson()
            
        elif proxy_choice == '3':
            change_proxyson_destination()

        elif proxy_choice == '4':
            change_proxyson_command()
            
        elif proxy_choice == '5':
            sync_proxyson_with_tor()

        elif proxy_choice == '6':
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Remove ProxySon")
            print("=========================================\n")

            confirm_remove = src_utils.get_confirmation(
                "Warning: This will completely remove ProxySon .\n"
                "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_remove:
                src_utils.warning("Removal aborted by user", solution="Re-run setup to try again")
                input("Press Enter to Return...")
                continue

            src_remover.remove_proxyson()
            input("\nPress Enter to Return...")

        else:
            src_utils.error(
                "Invalid menu choice",
                solution="Select a valid number from the menu options.",
                details=f"Received: {proxy_choice}"
            )
            input("Press Enter to try again...")



def install_proxyson():
    src_utils.clear_screen()
    print("=========================================")
    print("         INSTALL PROXYSON".center(40))
    print("=========================================\n")
    
    # Check if proxyson script already exists
    script_path = "/usr/local/bin/proxyson"
    if src_utils.file_exists(script_path):
        choice = src_utils.get_confirmation(f"{src_utils.YELLOW}⚠️ ProxySon already exists! It will be deleted for reinstallation, \nDo you confirm?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel):")
        if not choice:
            src_utils.warning("Installation aborted. Existing script remains unchanged.")
            input("Press Enter to return to the menu...")
            return
        else:
            try:
                os.remove(script_path)
                src_utils.success("Previous PROXYSON script removed successfully.")
            except Exception as e:
                src_utils.error(f"Error removing previous script: {e}")
                input("Press Enter to return to the menu...")
                return

    try:
        # DNS 
        dns_ip, dns_port = None, None
        sync_choice = src_utils.get_confirmation(f"\n{src_utils.YELLOW}🔗 Sync with Tor? (Y/n): {src_utils.RESET}")
        if sync_choice:
            dns_ip, dns_port = src_tor.get_tor_dns_info()
            if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
                src_utils.warning("Invalid Tor DNS configuration. Switching to manual input.")
                sync_choice = False

        if not sync_choice:
            # Loop until valid DNS IP is entered
            dns_ip = None
            while dns_ip is None:
                dns_ip = src_utils.prompt_for_ip("🌐 Enter DNS IP (e.g. 127.45.67.89): ")

            # Loop until valid DNS Port is entered
            dns_port = None
            while dns_port is None:
                dns_port = src_utils.prompt_for_port("🔢 Enter DNS Port (e.g. 5353): ")


        base_cmd = src_utils.get_user_input(
            "⌨️ Enter base command (default: socksify): ",
            default="socksify",
            validator=lambda x, _: bool(x.strip())
        )

        try:
            create_proxyson_script(
                dns_ip=dns_ip,
                dns_port=dns_port,
                base_command=base_cmd.strip()
            )
            src_utils.success("ProxySon installed successfully!", 
                          details=f"DNS: {dns_ip}:{dns_port} | Command: {base_cmd}")

        except Exception as e:
            src_utils.error(f"Error installing ProxySon: {str(e)}", 
                        solution="Try again with valid DNS settings")
            input("Press Enter to return to the menu...")
            return

    except KeyboardInterrupt:
        src_utils.warning("User interrupted the installation! Rolling back changes...")
        if src_utils.file_exists(script_path):
            os.remove(script_path)
        src_utils.success("Cleanup completed. Exiting...", details="All temporary files removed")

    input("\nPress Enter to return to the menu...")



def sync_proxyson(dns_ip, dns_port):
    file_path = "/usr/local/bin/proxyson"
    if not src_utils.file_exists(file_path):
        return False

    if dns_ip is None or dns_port is None:
        src_utils.warning("Invalid DNSPort configuration. Skipping Proxyson sync.")
        return False

    with open(file_path, "r") as f:
        content = f.read()

    new_content = re.sub(
        r'(-j\s+DNAT\s+(?:--to-destination\s+)?)(\d{1,3}(?:\.\d{1,3}){3}:\d{1,5})',
        rf'\g<1>{dns_ip}:{dns_port}',
        content,
        flags=re.IGNORECASE
    )

    new_content = re.sub(
        r'(nameserver\s+)(\d{1,3}(?:\.\d{1,3}){3})',
        rf'\g<1>{dns_ip}',
        new_content,
        flags=re.IGNORECASE
    )

    with open(file_path, "w") as f:
        f.write(new_content)

    return True






def sync_proxyson_with_tor():
    torrc_file = "/etc/tor/torrc"
    if not src_utils.file_exists("/usr/local/bin/proxyson"):
        src_utils.error("ProxySon not installed!")
        input("\nPress Enter to return...")
        return

    if not src_utils.is_installed("tor") or not src_utils.file_exists(torrc_file):
        src_utils.error("Tor is not installed or Tor configuration file is missing!")
        input("Press Enter to return...")
        return

    dns_ip, dns_port = src_tor.get_tor_dns_info()

    if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
        src_utils.error("Tor DNS configuration is missing or invalid!")
        input("Press Enter to return...")
        return

    if sync_proxyson(dns_ip, dns_port):
        src_utils.success("ProxySon synchronized with Tor successfully.", details=f"DNS: {dns_ip}:{dns_port}")
    else:
        src_utils.error("Failed to synchronize ProxySon with Tor.")

    input("Press the Enter button to return to the menu...")







def change_proxyson_destination():
    if not src_utils.file_exists("/usr/local/bin/proxyson"):
        src_utils.error("ProxySon not installed!", solution="Install ProxySon first")
        input("\nPress Enter to return...")
        return

    # Loop until valid DNS IP is entered
    dns_ip = None
    while dns_ip is None:
        dns_ip = src_utils.prompt_for_ip("Enter new DNS IP: ")

    # Loop until valid DNS Port is entered
    dns_port = None
    while dns_port is None:
        dns_port = src_utils.prompt_for_port("Enter new DNS Port: ")

    if sync_proxyson(dns_ip, dns_port):
        src_utils.success("Destination updated!", details=f"New DNS: {dns_ip}:{dns_port}")
    else:
        src_utils.error("Failed to update!", solution="Check DNS format and permissions")

    input("\nPress Enter to return...")






def change_proxyson_command():
    script_path = "/usr/local/bin/proxyson"
    if not src_utils.file_exists(script_path):
        src_utils.error("ProxySon not installed!", solution="Install ProxySon first using the setup menu")
        input("\nPress Enter to return...")
        return

    new_cmd = src_utils.get_user_input(
        "⌨️ Enter new base command (e.g. torsocks , default=socksify): ",
        default="socksify",
        validator=lambda x, _: bool(x.strip())
    )

    with open(script_path, "r") as f:
        content = f.read()
    

    content = re.sub(
        r'(echo\s+")([^":]+)(: \$\*")(\s+>&2)',
        rf'\g<1>{new_cmd}\g<3>\g<4>',
        content
    )
    

    content = re.sub(
        r'^\s*(\S+)\s+"\$@"\s*$', 
        rf'{new_cmd} "$@"', 
        content,
        flags=re.MULTILINE
    )
    
    try:
        with open(script_path, "w") as f:
            f.write(content)
        src_utils.success("Command updated successfully", 
        details=f"New command: {new_cmd}")
    except Exception as e:
        src_utils.error(f"Failed to update command: {str(e)}", solution="Check script permissions")
        input("\nPress Enter to return...")
        return
    
    input("\nPress Enter to return...")
 
 
 
 
 

def create_proxyson_script(dns_ip, dns_port, base_command="socksify"):
    script_path = "/usr/local/bin/proxyson"
    script_content = f"""#!/bin/bash
# proxyson wrapper script with robust in-place resolv.conf editing
#
# Usage: proxyson <command> [args...]
#
set -e
set -o pipefail

RED='\\033[1;91m'
GREEN='\\033[1;92m'
BLUE='\\033[1;94m'
YELLOW='\\033[1;93m'
RESET='\\033[0m'

CLEANED=0

log() {{
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}}

cleanup() {{
    if [ "$CLEANED" -eq 1 ]; then
        exit $?
    fi

    echo -e "\\n${{GREEN}}[—————Command Finished———————————] ${{RESET}}\\n" >&2

    CLEANED=1
    local status=$?
    log "${{BLUE}}Starting Cleanup...${{RESET}}"

    $IPTABLES -t nat -D OUTPUT -p tcp --dport domain -j DNAT --to-destination {dns_ip}:{dns_port} 2>/dev/null || true
    $IPTABLES -t nat -D OUTPUT -p udp --dport domain -j DNAT --to-destination {dns_ip}:{dns_port} 2>/dev/null || true

    if [ "$CREATED_TEMP" -eq 1 ]; then
        log "${{BLUE}}Removing temporary resolv.conf...${{RESET}}"
        rm -f "$RESOLV_CONF"
    elif [ -f "$TEMP_BACKUP" ]; then
        log "${{BLUE}}Restoring original /etc/resolv.conf from backup...${{RESET}}"
        ed -s "$RESOLV_CONF" <<EOF
1,\\$d
.r $TEMP_BACKUP
w
q
EOF
        rm -f "$TEMP_BACKUP"
    fi

    if [ "$LOCKED" -eq 1 ]; then
        log "${{BLUE}}Restoring immutable flag on $RESOLV_CONF...${{RESET}}"
        chattr +i "$RESOLV_CONF" || log "${{RED}}Warning: Failed to restore immutable flag.${{RESET}}"
    fi

    if [ $status -eq 0 ]; then
        log "${{GREEN}}Proxyson Process Completed Successfully.${{RESET}}"
    else
        log "${{RED}}proxyson terminated with errors (exit code $status).${{RESET}}"
    fi

    sleep 0.5
    exit $status
}}

trap cleanup EXIT INT TERM

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <command> [args...]" >&2
    exit 1
fi

IPTABLES=/sbin/iptables
RESOLV_CONF="/etc/resolv.conf"

echo -e "\\n${{YELLOW}}ProxySon Details : ${{RESET}}\\n" >&2
log "${{BLUE}}Starting Proxyson Wrapper...${{RESET}}"

CREATED_TEMP=0
if [ -f "$RESOLV_CONF" ]; then
    TEMP_BACKUP=$(mktemp /tmp/resolv.conf.XXXXXX)
    cat "$RESOLV_CONF" > "$TEMP_BACKUP"
    log "${{BLUE}}Backup of resolv.conf created at $TEMP_BACKUP.${{RESET}}"
else
    log "${{BLUE}}resolv.conf not found, creating temporary one.${{RESET}}"
    touch "$RESOLV_CONF"
    CREATED_TEMP=1
fi

if lsattr "$RESOLV_CONF" 2>/dev/null | grep -q "i"; then
    LOCKED=1
    log "${{BLUE}}$RESOLV_CONF is immutable. Removing immutable flag temporarily...${{RESET}}"
    chattr -i "$RESOLV_CONF"
else
    LOCKED=0
fi

log "${{BLUE}}Modifying resolv.conf in-place...${{RESET}}"
if [ -s "$RESOLV_CONF" ]; then
    ed -s "$RESOLV_CONF" <<'EOF'
1,$s/^/#--/
0a
nameserver {dns_ip}
.
w
q
EOF
else
    ed -s "$RESOLV_CONF" <<'EOF'
0a
nameserver {dns_ip}
.
w
q
EOF
fi

log "${{GREEN}}resolv.conf modified. New content:${{RESET}}"
cat "$RESOLV_CONF" >&2

log "${{BLUE}}Adding DNAT rules to iptables...${{RESET}}"
$IPTABLES -t nat -A OUTPUT -p tcp --dport domain -j DNAT --to-destination {dns_ip}:{dns_port}
$IPTABLES -t nat -A OUTPUT -p udp --dport domain -j DNAT --to-destination {dns_ip}:{dns_port}
log "${{GREEN}}Iptables DNAT Rules added Successfully.${{RESET}}"

echo -e "\\n${{GREEN}}[—————Running Your Command———————] ${{RESET}}\\n" >&2
echo "{base_command}: $*" >&2

{base_command} "$@"
CMD_STATUS=$?
exit $CMD_STATUS
"""
    with open(script_path, "w") as script_file:
        script_file.write(script_content)
    src_utils.run_command(f"sudo chmod 750 {script_path}", "Failed to make proxyson executable.")
    print("proxyson script created and configured successfully.")

