#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_menus
from src import src_status
from src import src_utils
from src import src_tor
from src import src_remover
from src import src_installer

#modules >
import re
import os



# -------------------- DnssonManager --------------------





def handle_dnsson_setup():
    # Dnsson Setup Handler: Manages the Dnsson setup menu and its operations.
    while True:
        src_menus.display_dnsson_menu()
        dns_choice = input("\nEnter your choice: ").strip()
        
        if dns_choice == '0':
            break

        elif dns_choice == '1':
            src_status.dnsson_status()
            input("\nPress Enter to Return...")

        elif dns_choice == '2':
            install_dnsson()

        elif dns_choice == '3':
            change_dnsson_destination()


        elif dns_choice == '4':
            sync_dnsson_with_tor()

        elif dns_choice == '5':
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Remove DnsSon")
            print("=========================================\n")

            confirm_remove = src_utils.get_confirmation(
                f"{src_utils.YELLOW}Warning: This will completely remove DnsSon .{src_utils.RESET}\n"
                f"{src_utils.YELLOW}Do you want to proceed?{src_utils.RESET} \n(Press Enter for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_remove:
                src_utils.warning("Removal aborted by user", solution="Re-run setup to try again")
                input("Press Enter to Return...")
                continue

            src_remover.remove_dnsson()
            input("\nPress Enter to Return...")

        else:
            src_utils.error(
                "Invalid menu choice",
                solution="Select a valid number from the menu options.",
                details=f"Received: {dns_choice}"
            )
            input("Press Enter to try again...")





def install_dnsson():
    src_utils.clear_screen()
    print("=========================================")
    print("         Installing DnsSon")
    print("=========================================\n")

    # Check if dnsson script already exists
    script_path = "/usr/local/bin/dnsson"
    if src_utils.file_exists(script_path):
        choice = src_utils.get_confirmation(f"{src_utils.YELLOW}⚠️ DnsSon script already exists , It will be deleted for reinstallation, \nDo you confirm? {src_utils.RESET}(Press Enter for confirmation, or type 'n' or 'no' to cancel):")
        if not choice:
            src_utils.warning("Installation aborted. Existing script remains unchanged.")
            input("Press Enter to return to the menu...")
            return
        else:
            try:
                os.remove(script_path)
                src_utils.success("Previous DnsSon script removed successfully.")
            except Exception as e:
                src_utils.error(f"Error removing previous script: {e}", 
                            solution="Check file permissions or try again with sudo")
                input("Press Enter to return to the menu...")
                return

    try:
        dns_ip, dns_port = None, None
        sync_choice = src_utils.get_confirmation(f"\n{src_utils.YELLOW}🔗 Sync with Tor? (Y/n):{src_utils.RESET} ")
        if sync_choice:
            dns_ip, dns_port = src_tor.get_tor_dns_info()
            if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
                src_utils.warning("Invalid Tor DNS configuration. Switching to manual input.", 
                              solution="Check Tor's torrc file for DNSPort settings")
                sync_choice = False

        if not sync_choice:
            # Loop until valid IP is entered
            while True:
                dns_ip = src_utils.prompt_for_ip("🌐 Enter DNS IP (e.g. 127.45.67.89): ")
                if dns_ip is not None:
                    break
                src_utils.warning("Please re-enter a valid DNS IP address...")

            # Loop until valid Port is entered
            while True:
                dns_port = src_utils.prompt_for_port("🔢 Enter DNS Port (e.g. 5353): ")
                if dns_port is not None:
                    break
                src_utils.warning("Please re-enter a valid DNS port number...")

        try:
            create_dnsson_script(dns_ip, dns_port)
            src_utils.success("DnsSon installed and configured successfully", 
                          details=f"Iptables settings:\n"
                                  f"  - Destination DNAT: {dns_ip}:{dns_port}\n"
                                  f"  - Nameserver set to: {dns_ip}")
        except Exception as e:
            src_utils.error(f"Error installing DnsSon: {str(e)}", 
                        solution="Check DNS format and script permissions")
            input("Press Enter to return to the menu...")
            return

    except KeyboardInterrupt:
        src_utils.warning("User interrupted the installation! Rolling back changes...")
        if src_utils.file_exists(script_path):
            os.remove(script_path)
        src_utils.success("Cleanup completed. Exiting...", context="All temporary files removed")

    input("\nPress Enter to return to the menu...")

















def sync_dnsson(dns_ip, dns_port):
    file_path = "/usr/local/bin/dnsson"
    if not src_utils.file_exists(file_path):
        return False

    if dns_ip is None or dns_port is None:
        src_utils.warning("Invalid DNSPort configuration. Skipping DnsSon sync.", 
                      solution="Check Tor DNS settings")
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








def sync_dnsson_with_tor():
    file_path = "/usr/local/bin/dnsson"
    torrc_file = "/etc/tor/torrc"
    if not src_utils.file_exists(file_path):
        src_utils.error("DnsSon not installed!", solution="Install DnsSon first")
        input("Press Enter to return...")
        return

    if not src_utils.is_installed("tor") or not src_utils.file_exists(torrc_file):
        src_utils.error("Tor is not installed or Tor configuration missing!", 
                    solution="Install Tor and ensure torrc exists")
        input("Press Enter to return...")
        return

    dns_ip, dns_port = src_tor.get_tor_dns_info()

    if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
        src_utils.error("Tor DNS configuration invalid!", 
                    solution="Check DNSPort settings in torrc")
        input("Press Enter to return...")
        return

    if sync_dnsson(dns_ip, dns_port):
        src_utils.success("DnsSon synchronized with Tor", 
                      details=f"DNS: {dns_ip}:{dns_port}")
    else:
        src_utils.error("Synchronization failed", 
                    solution="Retry with valid DNS settings")

    input("Press the Enter button to return to the menu...")








def change_dnsson_destination():
    if not src_utils.file_exists("/usr/local/bin/dnsson"):
        src_utils.error("DnsSon not installed!", solution="Install DnsSon first")
        input("Press the Enter button to return to the menu...")
        return

    # Loop until valid DNS IP is entered
    dns_ip = None
    while dns_ip is None:
        dns_ip = src_utils.prompt_for_ip("Enter new DNS IP: ")

    # Loop until valid DNS Port is entered
    dns_port = None
    while dns_port is None:
        dns_port = src_utils.prompt_for_port("Enter new DNS Port: ")

    if sync_dnsson(dns_ip, dns_port):
        src_utils.success("DnsSon destination updated", 
                      details=f"New DNS: {dns_ip}:{dns_port}")
    else:
        src_utils.error("Failed to update DnsSon destination", 
                    solution="Check DNS format and permissions")

    input("Press the Enter button to return to the menu...")

 
 


def create_dnsson_script(dns_ip, dns_port):

    script_path = "/usr/local/bin/dnsson"
    script_content = f"""#!/bin/bash
# dnsson wrapper script with robust in-place resolv.conf editing
#
# Usage: dnsson <command> [args...]
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
        log "${{GREEN}}DnsSon Process Completed Successfully.${{RESET}}"
    else
        log "${{RED}}DnsSon terminated with errors (exit code $status).${{RESET}}"
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

echo -e "\\n${{YELLOW}}DnsSon Details : ${{RESET}}\\n" >&2
log "${{BLUE}}Starting DnsSon Wrapper...${{RESET}}"

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

LOCKED=0
if lsattr "$RESOLV_CONF" 2>/dev/null | grep -q "i"; then
    LOCKED=1
    log "${{BLUE}}$RESOLV_CONF is immutable. Removing immutable flag temporarily...${{RESET}}"
    chattr -i "$RESOLV_CONF"
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

echo "Running command: $*" >&2
"$@"
CMD_STATUS=$?
exit $CMD_STATUS
"""
    with open(script_path, "w") as script_file:
        script_file.write(script_content)
    src_utils.run_command(f"sudo chmod 750 {script_path}", "Failed to make dnsson executable.")
    print("dnsson script created and configured successfully.")

 
