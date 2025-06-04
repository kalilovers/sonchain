#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_utils
from src import src_menus
from src import src_status
from src import src_installer
from src import src_remover
from src import src_dnsson
from src import src_proxyson
from src import src_socksify
from src import src_proxychains

#modules >
import os
import re
import subprocess
import shutil
import uuid
import socket
import time




# -------------------- Tor Manager --------------------







def handle_tor_setup():

    while True:
        src_menus.display_setup_tor_menu()
        tor_choice = input("\nEnter your choice: ").strip()

        if tor_choice == '0':
            break  # Return to main menu

        #-------------------------------------------------------------------

        elif tor_choice == '1':  # Tor Status
            src_utils.clear_screen()
            src_status.tor_status()
            input("Press Enter to return to Tor Setup menu...")  # Preserve navigation

        #-------------------------------------------------------------------


        elif tor_choice == '2':  # Install Tor
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Installing Tor ")               # Preserve title
            print("=========================================\n")

            confirm_tor_install = src_utils.get_confirmation(
                f"{src_utils.YELLOW}it will be removed for a clean installation, \nDo you confirm?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_tor_install:
                src_utils.warning("Installation aborted by user", solution="Re-run setup to try again")
                input("Press Enter to Return...")
                continue

            try:
                print(f"\n{src_utils.YELLOW}Trying To Update repositories{src_utils.RESET}\n")
                if not src_utils.run_apt_update("sudo apt update", timeout=300):
                    src_utils.error("Apt Update failed.", 
                                solution="Check package repositories")
                    input("Press Enter to return to the Auto Setup menu...")
                    return

                src_utils.info("Preparing for fresh installation...")
                src_remover.remove_tor()

                try:
                    socks_ip, socks_port, dns_ip, dns_port = src_installer.install_tor()
                    print("\n——————————————— Attention ———————————————")
                    src_utils.warning("Wait for the Tor connection to be established")
                    src_utils.success(f"You can use the {src_utils.CYAN}'nyx'{src_utils.RESET} {src_utils.GREEN}command to monitor Tor more precisely.{src_utils.RESET}\n")
                except Exception as e:
                    src_utils.error(f"Tor installation failed: {str(e)}", 
                                solution="Check dependencies and system permissions")
                    src_utils.warning("Rolling back partial installation...", 
                                  solution="System will revert changes")
                    src_remover.remove_tor()
                    input("Press Enter to return to Tor Setup menu...")
                    continue

            except KeyboardInterrupt:
                src_utils.warning("User interrupted installation! Rolling back changes...", 
                              solution="Installation aborted")
                src_remover.remove_tor()
                src_utils.success("Cleanup completed", details="Aborted installation rolled back")
                input("\nPress Enter to return to Tor Setup menu...")
                return

            input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation


        #-------------------------------------------------------------------


        elif tor_choice == '3':  # Manual Configuration (with partial sync)
            src_utils.clear_screen()
            print("=========================================")
            print("            Manual Tor Configuration")
            print("=========================================\n")
            
            # 1. Check prerequisites
            if not src_utils.is_installed("tor") or not src_utils.file_exists("/etc/tor/torrc"):
                src_utils.error("[Critical] Tor or torrc file not found!", 
                             solution="Install Tor first from main menu", 
                             details="Path Checked: /etc/tor/torrc")
                input("\nPress Enter to return...")
                continue

            # 2. Create unique backup using UUID
            backup_uuid = str(uuid.uuid4())[:8]
            backup_path = f"/etc/tor/torrc.backup_{backup_uuid}"
            try:
                shutil.copyfile("/etc/tor/torrc", backup_path)
                src_utils.success("Backup created", details=f"Path: {backup_path}")
            except Exception as e:
                src_utils.error(f"Failed to create backup: {str(e)}", 
                            solution="Check disk space and file permissions")
                input("\nPress Enter to return...")
                continue

            # 3. Edit torrc file
            src_utils.info("Editing torrc configuration file in nano editor...", 
                       details="Opening with sudo nano")
            edit_result = os.system("sudo nano /etc/tor/torrc")
            
            # 4. Extract and validate new settings
            socks_ip, socks_port = get_tor_socks_info()
            dns_ip, dns_port = get_tor_dns_info()

            validation_errors = []
            
            # Validate SocksPort
            if socks_ip in ("TORRC_NOT_FOUND", None) or socks_port in ("TORRC_NOT_FOUND", None):
                validation_errors.append("Invalid SocksPort configuration detected!")
            
            # Validate DNSPort
            if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
                validation_errors.append("Invalid DNSPort configuration detected!")

            # Handle validation failures
            if validation_errors:
                print("\n".join(validation_errors))
                print("\n🚫 Configuration validation failed! Sync aborted.")
                
                # Backup restoration logic
                restore_choice = src_utils.get_confirmation("⚠️ Restore original configuration from backup? (Y/n): ")
                if restore_choice:
                    try:
                        shutil.copyfile(backup_path, "/etc/tor/torrc")
                        src_utils.success("Configuration restored from backup", 
                                      details=f"Restored from: {backup_path}")
                    except Exception as e:
                        src_utils.error(f"Failed to restore backup: {str(e)}", 
                                    solution="Manually copy backup file")
                else:
                    src_utils.warning("Keeping modified configuration", 
                                  solution="This may cause system instability")

                # Final cleanup
                try:
                    os.remove(backup_path)
                    src_utils.info("Backup removed", details=f"Path: {backup_path}")
                except Exception as e:
                    src_utils.warning(f"Failed to remove backup: {str(e)}", 
                                  solution="Delete manually if needed")

                # Attempt Tor restart with current config
                print("\n🔁 Attempting Tor restart...")
                restart_ok = restart_tor()
                if restart_ok:
                    print("✅ Tor restarted with current configuration")
                else:
                    print("❌ Tor restart failed! Check logs with:")
                    print("  ├─ sudo systemctl status tor")
                    print("  ╰─ journalctl -u tor -n 50 --no-pager")

                input("\nPress Enter to return...")
                continue

            # 5. Service synchronization
            sync_results = {
                'dnsson': {'status': 'skipped', 'msg': ''},
                'proxyson': {'status': 'skipped', 'msg': ''},
                'Socksify': {'status': 'skipped', 'msg': ''}
            }

            # Sync DnsSon
            if src_utils.get_confirmation("\n🔗 Sync DnsSon with new DNS settings? (Y/n): "):
                if src_utils.file_exists("/usr/local/bin/dnsson"):
                    try:
                        if src_dnsson.sync_dnsson(dns_ip, dns_port):
                            sync_results['dnsson'] = {
                                'status': 'success',
                                'msg': f"DNS: {dns_ip}:{dns_port}"
                            }
                        else:
                            sync_results['dnsson'] = {
                                'status': 'error',
                                'msg': "Script update failed"
                            }
                    except Exception as e:
                        sync_results['dnsson'] = {
                            'status': 'error',
                            'msg': f"Error: {str(e)}"
                        }
                else:
                    sync_results['dnsson'] = {
                        'status': 'error',
                        'msg': "DnsSon not installed"
                    }

            # Sync ProxySon
            if src_utils.get_confirmation("\n🔗 Sync ProxySon with new DNS settings? (Y/n): "):
                if src_utils.file_exists("/usr/local/bin/proxyson"):
                    try:
                        if src_proxyson.sync_proxyson(dns_ip, dns_port):
                            sync_results['proxyson'] = {
                                'status': 'success',
                                'msg': f"DNS: {dns_ip}:{dns_port}"
                            }
                        else:
                            sync_results['proxyson'] = {
                                'status': 'error',
                                'msg': "Script update failed"
                            }
                    except Exception as e:
                        sync_results['proxyson'] = {
                            'status': 'error',
                            'msg': f"Error: {str(e)}"
                        }
                else:
                    sync_results['proxyson'] = {
                        'status': 'error',
                        'msg': "ProxySon not installed"
                    }

            # Sync Dante
            if src_utils.get_confirmation("\n🔗 Sync Socksify with new SOCKS settings? (Y/n): "):
                if src_utils.file_exists("/etc/socks.conf"):
                    try:
                        if src_socksify.update_dante_config(socks_ip, socks_port):
                            sync_results['Socksify'] = {
                                'status': 'success',
                                'msg': f"SOCKS: {socks_ip}:{socks_port}"
                            }
                        else:
                            sync_results['Socksify'] = {
                                'status': 'error',
                                'msg': "Config update failed"
                            }
                    except Exception as e:
                        sync_results['Socksify'] = {
                            'status': 'error',
                            'msg': f"Error: {str(e)}"
                        }
                else:
                    sync_results['Socksify'] = {
                        'status': 'error',
                        'msg': "Socksify config missing"
                    }


            # Sync Proxychains
            if src_utils.get_confirmation("\n🔗 Sync Proxychains with new SOCKS settings? (Y/n): "):
                if src_utils.file_exists("/etc/proxychains.conf"):
                    try:
                        if src_proxychains.sync_proxychains_with_tor():
                            sync_results['Proxychains'] = {
                                'status': 'success',
                                'msg': f"SOCKS: {socks_ip}:{socks_port}"
                            }
                        else:
                            sync_results['Proxychains'] = {
                                'status': 'error',
                                'msg': "Config update failed"
                            }
                    except Exception as e:
                        sync_results['Proxychains'] = {
                            'status': 'error',
                            'msg': f"Error: {str(e)}"
                        }
                else:
                    sync_results['Proxychains'] = {
                        'status': 'error',
                        'msg': "Proxychains config missing"
                    }



            # 6. Display results
            print("\n" + "═"*40)
            print("          SYNCHRONIZATION REPORT")
            print("═"*40)
            for service, data in sync_results.items():
                status_icon = "🟢" if data['status'] == 'success' else \
                             "🔴" if data['status'] == 'error' else "⚪"
                print(f"{status_icon} {service.upper():<9} - {data['msg']}")

            # 7. Final cleanup and restart
            try:
                os.remove(backup_path)
                src_utils.success("Backup removed", details=f"Path: {backup_path}")
            except Exception as e:
                src_utils.warning(f"Failed to remove backup: {str(e)}", 
                              solution="Delete manually if needed")

            src_utils.info("Final Tor restart...", context="Post-synchronization")
            restart_ok = restart_tor()
            if restart_ok:
                print("✅ Tor service restarted successfully")
            else:
                print("❌ Tor restart failed! Check:")
                print("  ├─ sudo systemctl status tor")
                print("  ╰─ journalctl -u tor -n 50 --no-pager")

            input("\nPress Enter to return to menu...")


        #-------------------------------------------------------------------


        elif tor_choice == '4':
            display_advanced_tor_settings_menu()

        #-------------------------------------------------------------------


        elif tor_choice == '5':  # Stop Tor
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Stopping Tor")
            print("=========================================\n")
            stop_tor()  # Core functionality preserved
            input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation


        #-------------------------------------------------------------------


        elif tor_choice == '6':  # Restart Tor
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Restarting Tor")
            print("=========================================\n")
            src_utils.info("Restarting Tor service...", context="Initiating restart sequence")
            restart_tor()

            input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation


        #-------------------------------------------------------------------


        elif tor_choice == '7':  # Remove Tor
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Remove Tor")
            print("=========================================\n")

            confirm_remove = src_utils.get_confirmation(
                f"{src_utils.YELLOW}Warning: This will completely remove Tor and its configurations.\n"
                f"Do you want to proceed?{src_utils.RESET}"
                "\n(Press Enter|y for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_remove:
                src_utils.warning("Removal aborted by user", solution="Re-run setup to try again")
                input("Press Enter to Return...")
                continue

            src_utils.info("Removing Tor...", context="Starting uninstall process")
            src_remover.remove_tor()
            src_utils.success("Tor removed successfully", 
                          details="All components and configurations deleted")
            input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation


        #-------------------------------------------------------------------
        else:
            src_utils.error(
                "Invalid menu choice",
                solution="Select a valid number from the menu options.",
                details=f"Received: {tor_choice}"
            )
            input("Press Enter to try again...")











def parse_torrc(torrc_path="/etc/tor/torrc"):

    result = {
        "socks_ip": None,
        "socks_port": None,
        "dns_ip": None,
        "dns_port": None,
        "exists": False
    }

    if not src_utils.file_exists(torrc_path):
        return result

    result["exists"] = True
    with open(torrc_path, "r") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue


            lower_line = line.lower()
            if lower_line.startswith("socksport"):
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    token = parts[1].strip()
                    if ":" in token:
                        ip_part, port_part = token.split(":", 1)
                        result["socks_ip"] = ip_part.strip()
                        result["socks_port"] = port_part.strip()
                    else:

                        result["socks_ip"] = "127.0.0.1"
                        result["socks_port"] = token
            elif lower_line.startswith("dnsport"):
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    token = parts[1].strip()
                    if ":" in token:
                        ip_part, port_part = token.split(":", 1)
                        result["dns_ip"] = ip_part.strip()
                        result["dns_port"] = port_part.strip()
                    else:

                        result["dns_ip"] = "127.0.0.1"
                        result["dns_port"] = token
    return result









def get_tor_socks_info():

    TORRC_NOT_FOUND = ("TORRC_NOT_FOUND", "TORRC_NOT_FOUND")
    
    config = parse_torrc("/etc/tor/torrc")
    if not config.get("exists", False):
        src_utils.warning("Tor configuration file not found", 
                      solution="Verify /etc/tor/torrc exists", 
                      details="Path: /etc/tor/torrc")
        return TORRC_NOT_FOUND

    socks_ip = config.get("socks_ip")
    socks_port = config.get("socks_port")

    if not socks_port:
        src_utils.warning("SocksPort port not specified in torrc", 
                      solution="Add 'SocksPort <IP>:<PORT>' to configuration")
        return None, None

    if not socks_port.isdigit() or not (1 <= int(socks_port) <= 65535):
        src_utils.warning("Invalid SocksPort port specified", 
                      solution="Port must be between 1-65535")
        return None, None

    if not socks_ip:
        socks_ip = "127.0.0.1"
    else:
        try:
            socket.inet_aton(socks_ip)
            parts = socks_ip.split('.')
            if parts[0] != "127":
                src_utils.warning("SocksPort IP must be internal (127.x.x.x)", 
                              solution="Update IP to local interface format")
                return None, None
        except socket.error:
            src_utils.warning("Invalid SocksPort IP format", 
                          solution="Use valid IPv4 address (e.g., 127.0.0.5)")
            return None, None

    return socks_ip, socks_port








def get_tor_dns_info():

    TORRC_NOT_FOUND = ("TORRC_NOT_FOUND", "TORRC_NOT_FOUND")
    
    config = parse_torrc("/etc/tor/torrc")
    if not config.get("exists", False):
        src_utils.warning("Tor configuration file not found", 
                      solution="Verify /etc/tor/torrc exists", 
                      details="Path: /etc/tor/torrc")
        return TORRC_NOT_FOUND

    dns_ip = config.get("dns_ip")
    dns_port = config.get("dns_port")

    if not dns_port:
        src_utils.warning("DNSPort port not specified in torrc", 
                      solution="Add 'DNSPort <IP>:<PORT>' to configuration")
        return None, None

    if not dns_port.isdigit() or not (1 <= int(dns_port) <= 65535):
        src_utils.warning("Invalid DNSPort port specified", 
                      solution="Port must be between 1-65535")
        return None, None

    if not dns_ip:
        dns_ip = "127.0.0.1"
    else:
        try:
            socket.inet_aton(dns_ip)
            parts = dns_ip.split('.')
            if parts[0] != "127":
                src_utils.warning("DNSPort IP must be internal (127.x.x.x)", 
                              solution="Update IP to local interface format")
                return None, None
        except socket.error:
            src_utils.warning("Invalid DNSPort IP format", 
                          solution="Use valid IPv4 address (e.g., 127.0.0.5)")
            return None, None

    return dns_ip, dns_port







### 1. `check_tor_repo_access()` ###

def check_tor_repo_access():

    repo_domain = "deb.torproject.org"
    
    src_utils.info("Checking direct connectivity to the Tor repository (port 443)...")
    
    connectivity_test = subprocess.run(
        'timeout 3 bash -c "</dev/tcp/deb.torproject.org/443"',
        shell=True, capture_output=True
    )

    if connectivity_test.returncode == 0:
        src_utils.success("Tor repository is accessible")
        return True
    else:
        src_utils.error("Tor repository is unreachable", solution="Check network connectivity or try later")
        return False






### 2. `validate_and_clean_torrc()` ###

def validate_and_clean_torrc(torrc_path):

    valid_lines = []
    with open(torrc_path, "r") as torrc:
        for line in torrc:
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith("#"):
                valid_lines.append(line)
    with open(torrc_path, "w") as torrc:
        torrc.writelines(valid_lines)
    src_utils.success("torrc file validated and cleaned", details=f"Path: {torrc_path}")





### 3. `stop_tor()` ###

def stop_tor():

    src_utils.info("Stopping Tor service...")
    
    src_utils.run_command("sudo systemctl stop tor", "Failed to stop Tor service.")
    src_utils.run_command("sudo systemctl stop tor@default", "Failed to stop Tor@default service.")
    src_utils.run_command("sudo killall tor", "Failed to kill Tor processes with 'killall'.")
    src_utils.run_command("sudo pkill tor", "Failed to kill Tor processes with 'pkill'.")
    src_utils.run_command("sudo pkill -9 tor", "Failed to force kill Tor processes with 'pkill -9'.")
    src_utils.run_command("sudo systemctl daemon-reexec", "Failed to re-execute systemd daemon.")
    
    src_utils.success("Tor stopped successfully", details="All services and processes terminated")






### 4. `restart_tor()` ###

def restart_tor():
    if not src_utils.is_installed("tor") or not src_utils.file_exists("/etc/tor/torrc"):
        src_utils.error("Tor service not installed or torrc missing", solution="Install Tor first")
        return True

    src_utils.info("Stopping Tor services...")
    src_utils.run_command("sudo systemctl stop tor", "Failed to stop Tor service.")
    src_utils.run_command("sudo systemctl stop tor@default", "Failed to stop Tor@default service.")
    src_utils.run_command("sudo killall tor", "Failed to kill Tor processes with 'killall'.")
    src_utils.run_command("sudo pkill tor", "Failed to kill Tor processes with 'pkill'.")
    src_utils.run_command("sudo pkill -9 tor", "Failed to force kill Tor processes with 'pkill -9'.")
    src_utils.run_command("sudo systemctl daemon-reexec", "Failed to re-execute systemd daemon.")
    time.sleep(2)

    src_utils.info("Starting Tor services...")
    src_utils.run_command("sudo systemctl start tor", "Failed to start Tor service.")
    src_utils.run_command("sudo systemctl start tor@default", "Failed to start Tor@default service.")
    time.sleep(2)

    socks_ip, socks_port = get_tor_socks_info()
    if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
        src_utils.warning("torrc file not found during restart", solution="Verify /etc/tor/torrc exists")
    elif socks_ip is None or socks_port is None:
        src_utils.warning("Invalid SocksPort configuration in torrc", 
                      details="Check SocksPort format in configuration file")
    else:
        src_utils.success("Configuration validated ' Restarted successfully", 
                   details=f"Tor is listening on port {socks_port} at {socks_ip}")

    src_utils.info("Checking tor Service Activation")
    if not src_utils.run_command("sudo systemctl is-active tor", "Tor service is not active."):
        src_utils.warning("Tor service may not be active after restart", 
                      solution="Check service status with 'systemctl status tor'")
    src_utils.info("Checking tor@default Service Activation")
    if not src_utils.run_command("sudo systemctl is-active tor@default", "❌ Tor@default service is Inactive"):
        src_utils.warning("Tor@default service may not be active after restart", 
                      solution="Check service status with 'systemctl status tor@default'")
    
    return True






def display_advanced_tor_settings_menu():
    while True:
        src_utils.clear_screen()
        print(f"{src_utils.BORDER_COLOR}╔{'═'*41}╗{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' ADVANCED TOR SETTINGS '.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")

        menu_items = [
            "1 | Configure Node Country",
            "2 | Configure Node Country Exclusion",
            "3 | Set NumEntryGuards (1–8)",
            "4 | Set NumDirectoryGuards (1–5)",
            "5 | Configure Strict Modes",
            "6 | Remove Specific Setting",
            "7 | Reset to Default Settings"
        ]

        
        for item in menu_items:
            print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(39)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")

        print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}║ 0 | {src_utils.EXIT_STYLE}{'Back'.ljust(36)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}╚{'═'*41}╝{src_utils.RESET}")

        choice = input("\nEnter your choice: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            configure_tor_node_country()
            input("\nPress Enter to continue...")
        elif choice == "2":
            configure_tor_node_exclusion()
            input("\nPress Enter to continue...")
        elif choice == "3":
            set_tor_entry_guard_count()
            input("\nPress Enter to continue...")
        elif choice == "4":
            set_tor_directory_guard_count()
            input("\nPress Enter to continue...")
        elif choice == "5":
            configure_tor_strict_modes()
            input("\nPress Enter to continue...")
        elif choice == "6":
            display_remove_tor_settings_menu()
            input("\nPress Enter to continue...")
        elif choice == "7":
            reset_tor_settings_to_default()
            input("\nPress Enter to continue...")





def display_remove_tor_settings_menu():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    cfg = src_utils.read_file(torrc).splitlines()
    options = {
        "1": ("EntryNodes", r"^\s*EntryNodes\b", "country list"),
        "2": ("ExitNodes", r"^\s*ExitNodes\b", "country list"),
        "3": ("ExcludeEntryNodes", r"^\s*ExcludeEntryNodes\b", "country list"),
        "4": ("ExcludeExitNodes", r"^\s*ExcludeExitNodes\b", "country list"),
        "5": ("ExcludeNodes", r"^\s*ExcludeNodes\b", "country list"),
        "6": ("StrictEntryNodes", r"^\s*StrictEntryNodes\b", "flag"),
        "7": ("StrictExitNodes", r"^\s*StrictExitNodes\b", "flag"),
        "8": ("StrictNodes", r"^\s*StrictNodes\b", "flag"),
        "9": ("NumEntryGuards", r"^\s*NumEntryGuards\b", "count"),
        "10": ("NumDirectoryGuards", r"^\s*NumDirectoryGuards\b", "count"),
    }

    while True:
        src_utils.clear_screen()
        src_utils.info("Remove Specific Tor Settings")

        print(f"\nCurrent detected settings:\n")
        shown = []
        for k, (label, pattern, _) in options.items():
            for line in cfg:
                if re.match(pattern, line, re.IGNORECASE):
                    print(f" {k}. {label}: {line.strip()}")
                    shown.append(k)
                    break

        if not shown:
            src_utils.info("No custom settings found.")
            return

        print("\n 0. Back")
        choice = input("\nSelect one or multiple settings to remove (comma-separated, 1,2,3 ...): ").strip()

        if choice == "0":
            break

        selected = [c.strip() for c in choice.split(',') if c.strip()]


        if any(c not in shown for c in selected):
            src_utils.error("Invalid selection(s) detected", solution="Select only visible options")
            input("Press Enter to continue...")
            continue


        for c in selected:
            label, pattern, _ = options[c]
            cfg = [line for line in cfg if not re.match(pattern, line, re.IGNORECASE)]
            src_utils.success(f"{label} removed from torrc")


        with open(torrc, "w") as f:
            f.write("\n".join(cfg) + "\n")

        restart_tor()
        break





def reset_tor_settings_to_default():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return


    if not src_utils.get_confirmation(
        f"{src_utils.YELLOW}Are you sure you want to reset advanced settings to default? (y/N): {src_utils.RESET}",
        default=False, language="en"
    ):
        src_utils.info("Reset canceled by user.")
        return


    keep_keys = [
        "SocksPort", "DNSPort", "RunAsDaemon",
        "AutomapHostsOnResolve", "VirtualAddrNetworkIPv4", "Log notice file"
    ]

    cfg = src_utils.read_file(torrc).splitlines()
    cleaned = []
    for line in cfg:
        if any(line.strip().startswith(k) for k in keep_keys):
            cleaned.append(line)
        elif not re.match(r"^\s*(EntryNodes|ExitNodes|Exclude.*|Strict.*|Num.*)", line, re.IGNORECASE):
            cleaned.append(line)

    with open(torrc, "w") as f:
        f.write("\n".join(cleaned) + "\n")
    src_utils.success("All advanced routing settings reset to default.")
    restart_tor()





def configure_tor_strict_modes():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    src_utils.clear_screen()
    src_utils.info("Configure Strict Mode Options")

    print(f"""
{src_utils.CYAN}ℹ️ Guide:{src_utils.RESET}
 {src_utils.BORDER_COLOR}- StrictEntryNodes:{src_utils.RESET} Only allow selected EntryNodes.
 {src_utils.BORDER_COLOR}- StrictExitNodes:{src_utils.RESET} Only allow selected ExitNodes.
 {src_utils.BORDER_COLOR}- StrictNodes:{src_utils.RESET} Enforce Exclude rules strictly.
""")

    cfg = src_utils.read_file(torrc).splitlines()

    strict_map = {
        "1": ("StrictEntryNodes", "Entry Node Lock"),
        "2": ("StrictExitNodes", "Exit Node Lock"),
        "3": ("StrictNodes", "Exclude Enforcement")
    }

    while True:
        print(f"\n{src_utils.BOLD}Select Strict Option to Modify:{src_utils.RESET}")
        for key, (_, desc) in strict_map.items():
            print(f" {key}) {desc}")
        print(" 0) Back")

        choice = input("\nEnter your choice: ").strip()
        if choice == "0":
            return

        if choice not in strict_map:
            src_utils.error("Invalid selection", solution="Choose a valid option")
            continue

        strict_key, desc = strict_map[choice]


        enabled = any(re.match(rf"^\s*{strict_key}\s+1\b", line, re.IGNORECASE) for line in cfg)
        current = f"{src_utils.GREEN}Enabled" if enabled else f"{src_utils.RED}Disabled"

        print(f"\n{src_utils.YELLOW}{strict_key} is currently: {current}{src_utils.RESET}")

        enable = src_utils.get_confirmation(
            f"Do you want to {'disable' if enabled else 'enable'} {strict_key}? (y/N): ",
            default=False,
            language="en"
        )


        cfg = [line for line in cfg if not re.match(rf"^\s*{strict_key}\b", line, re.IGNORECASE)]
        if enable:
            cfg.append(f"{strict_key} 1")


        try:
            with open(torrc, "w") as f:
                f.write("\n".join(cfg) + "\n")
            src_utils.success(f"{strict_key} {'enabled' if enable else 'disabled'}")
            restart_tor()
            return
            
        except Exception as e:
            src_utils.error("Failed to update torrc", details=str(e))
            return





def configure_tor_node_country():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    src_utils.clear_screen()
    src_utils.info("Configure Tor Node Country")

    print(f"""
    {src_utils.CYAN}ℹ️ Guide:{src_utils.RESET}
     {src_utils.BORDER_COLOR}- EntryNodes:{src_utils.RESET} Select the countries (e.g., nl,de) where your Tor connection should START from.
     {src_utils.BORDER_COLOR}- ExitNodes:{src_utils.RESET} Select the countries where your Tor connection should END.
     {src_utils.BORDER_COLOR}- Strict...:{src_utils.RESET} Forces Tor to use ONLY the nodes you specify.
    """)



    node_map = {
        "1": ("Exit", "ExitNodes", "StrictExitNodes"),
        "2": ("Entry", "EntryNodes", "StrictEntryNodes"),
    }
    

    while True:
        print("\n Select node type:")
        print(" 1) ExitNode")
        print(" 2) EntryNode")
        print(" 0) Back")
        choice = input("\nEnter choice [0-2]: ").strip()
        
        if choice == "0":
            return
            
        if choice in node_map:
            label, include_key, strict_key = node_map[choice]
            break

        src_utils.error("Invalid selection", solution="Choose 1 or 2")


    while True:
        countries = src_utils.get_user_input(
            f"{src_utils.YELLOW}Enter 2-letter country code(s) for {label}Node (comma-separated, e.g., nl,de,fr): {src_utils.RESET}",
            validator=lambda c,_: re.fullmatch(r"([a-zA-Z]{2})(,[a-zA-Z]{2})*", c) is not None
        ).lower()
        if countries:
            break


    strict = src_utils.get_confirmation(
        f"{src_utils.YELLOW}Enable {strict_key}? (y/N): {src_utils.RESET}",
        default=False, language="en"
    )


    cfg = src_utils.read_file(torrc).splitlines()
    pattern = rf"\s*({include_key}|{strict_key})\b"
    cleaned = [ln for ln in cfg if not re.match(pattern, ln, re.IGNORECASE)]

    formatted_countries = "},{" .join(c.strip() for c in countries.split(","))
    cleaned.append(f"{include_key} {{{formatted_countries}}}")

    if strict:
        cleaned.append(f"{strict_key} 1")

    try:
        with open(torrc, "w") as f:
            f.write("\n".join(cleaned) + "\n")
        src_utils.success(f"{include_key} set to {{{countries}}}")
        if strict:
            src_utils.success(f"{strict_key} enabled")
        else:
            src_utils.info(f"{strict_key} disabled")
        restart_tor()
    except Exception as e:
        src_utils.error("Failed to update torrc", details=str(e))





def configure_tor_node_exclusion():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    src_utils.clear_screen()
    src_utils.info("Configure Tor Node Exclusion")

    print(f"""
    {src_utils.CYAN}ℹ️ Guide:{src_utils.RESET}
     {src_utils.BORDER_COLOR}- ExcludeExitNodes:{src_utils.RESET} Avoid using nodes from certain countries at the end of circuit.
     {src_utils.BORDER_COLOR}- ExcludeEntryNodes:{src_utils.RESET} Avoid using nodes from certain countries at the start.
     {src_utils.BORDER_COLOR}- ExcludeNodes:{src_utils.RESET} Avoid nodes from these countries anywhere in the path.
     {src_utils.BORDER_COLOR}- StrictNodes:{src_utils.RESET} Must be enabled to enforce Exclude rules.
    """)

    node_map = {
        "1": ("Exit", "ExcludeExitNodes"),
        "2": ("Entry", "ExcludeEntryNodes"),
        "3": ("All", "ExcludeNodes")
    }

    while True:
        print("\n Select exclusion type:")
        print(" 1) ExcludeExitNodes")
        print(" 2) ExcludeEntryNodes")
        print(" 3) Exclude All Nodes (Entry + Middle + Exit)")
        print(" 0) Back")
        choice = input("\nEnter choice [0-3]: ").strip()
        
        if choice == "0":
            return
            
        if choice in node_map:
            label, exclude_key = node_map[choice]
            break
        src_utils.error("Invalid selection", solution="Choose 1, 2, or 3")


    while True:
        raw_list = src_utils.get_user_input(
            f"{src_utils.YELLOW}Enter comma-separated values to exclude for {label}Nodes (e.g., cn,ru,us): {src_utils.RESET}",
            validator=lambda c, _: re.fullmatch(r"([a-zA-Z]{2})(,[a-zA-Z]{2})*", c) is not None
        ).strip().lower()
        if raw_list:
            break

    formatted = "},{" .join(entry.strip() for entry in raw_list.split(","))
    formatted_exclusion = f"{{{formatted}}}"

    strict = src_utils.get_confirmation(
        f"{src_utils.YELLOW}Enable StrictNodes to enforce exclusion? (y/N): {src_utils.RESET}",
        default=False, language="en"
    )

    cfg = src_utils.read_file(torrc).splitlines()
    pattern = rf"\s*({exclude_key}|StrictNodes)\b"
    cleaned = [ln for ln in cfg if not re.match(pattern, ln, re.IGNORECASE)]

    cleaned.append(f"{exclude_key} {formatted_exclusion}")
    if strict:
        cleaned.append("StrictNodes 1")

    try:
        with open(torrc, "w") as f:
            f.write("\n".join(cleaned) + "\n")
        src_utils.success(f"{exclude_key} set to: {formatted_exclusion}")
        if strict:
            src_utils.success("StrictNodes enabled")
        else:
            src_utils.info("StrictNodes disabled")
        restart_tor()
    except Exception as e:
        src_utils.error("Failed to update torrc", details=str(e))






def set_tor_entry_guard_count():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    src_utils.clear_screen()
    src_utils.info("Configure Tor Entry Guard Count")


    print(f"""
    {src_utils.CYAN}ℹ️ Guide:{src_utils.RESET}
     {src_utils.BORDER_COLOR}- NumEntryGuards:{src_utils.RESET} Sets how many "entry" (guard) nodes Tor maintains in parallel.
     {src_utils.BORDER_COLOR}- Range:{src_utils.RESET} You can set between 1 and 8.
    """)



    while True:
        num_str = src_utils.get_user_input(
            f"{src_utils.YELLOW}Enter number of EntryGuards (1–8): {src_utils.RESET}"
        )
        if num_str.isdigit() and 1 <= int(num_str) <= 8:
            num = int(num_str)
            break
        src_utils.error("Invalid number", solution="Enter an integer between 1 and 8")


    cfg = src_utils.read_file(torrc).splitlines()
    cleaned = [
        ln for ln in cfg
        if not re.match(r"\s*NumEntryGuards\b", ln, re.IGNORECASE)
    ]


    cleaned.append(f"NumEntryGuards {num}")
    try:
        with open(torrc, "w") as f:
            f.write("\n".join(cleaned) + "\n")
        src_utils.success(f"NumEntryGuards set to {num}")
        restart_tor()
    except Exception as e:
        src_utils.error("Failed to update torrc", details=str(e))





def set_tor_directory_guard_count():
    torrc = "/etc/tor/torrc"
    if not src_utils.file_exists(torrc):
        src_utils.error("torrc file not found!", solution="Install Tor first")
        return

    src_utils.clear_screen()
    src_utils.info("Configure Tor Directory Guard Count")

    print(f"""
    {src_utils.CYAN}ℹ️ Guide:{src_utils.RESET}
     {src_utils.BORDER_COLOR}- NumDirectoryGuards:{src_utils.RESET} Controls how many directory guard nodes Tor connects to for consensus data.
     {src_utils.BORDER_COLOR}- Range:{src_utils.RESET} You can set between 1 and 5.
    """)


    while True:
        num_str = src_utils.get_user_input(
            f"{src_utils.YELLOW}Enter number of DirectoryGuards (1–5): {src_utils.RESET}"
        )
        if num_str.isdigit() and 1 <= int(num_str) <= 5:
            num = int(num_str)
            break
        src_utils.error("Invalid number", solution="Enter an integer between 1 and 5")


    cfg = src_utils.read_file(torrc).splitlines()
    cleaned = [
        ln for ln in cfg
        if not re.match(r"\s*NumDirectoryGuards\b", ln, re.IGNORECASE)
    ]


    cleaned.append(f"NumDirectoryGuards {num}")
    try:
        with open(torrc, "w") as f:
            f.write("\n".join(cleaned) + "\n")
        src_utils.success(f"NumDirectoryGuards set to {num}")
        restart_tor()
    except Exception as e:
        src_utils.error("Failed to update torrc", details=str(e))







def setup_tor_logrotate():

    logrotate_config = "/etc/logrotate.d/tor"

    if os.path.exists(logrotate_config):
        src_utils.info("Tor logrotate configuration already exists. Skipping creation.", 
                   details=f"File path: {logrotate_config}")
        return

    logrotate_config_content = """\
/var/log/tor/notice.log {
    size 100M
    rotate 0
    missingok
    notifempty
    copytruncate
    create 660 debian-tor debian-tor
}
"""
    try:
        with open(logrotate_config, "w") as f:
            f.write(logrotate_config_content)
        src_utils.run_command(f"sudo chmod 644 {logrotate_config}", 
                               "Failed to set permissions for Tor logrotate config.")
        src_utils.success("Tor logrotate configuration created", 
                      details=f"Config file: {logrotate_config}")
    except Exception as e:
        src_utils.error(f"Failed to create Tor logrotate configuration: {str(e)}", 
                    solution="Check write permissions and disk space")

    service_file = "/etc/systemd/system/logrotate-tor.service"
    service_content = """\
[Unit]
Description=Run logrotate for Tor logs

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate -f /etc/logrotate.d/tor
"""
    try:
        with open(service_file, "w") as f:
            f.write(service_content)
        src_utils.run_command(f"sudo chmod 644 {service_file}", 
                               "Failed to set permissions for Tor logrotate service file.")
        src_utils.success("logrotate-tor.service created", 
                      details=f"Service file: {service_file}")
    except Exception as e:
        src_utils.error(f"Failed to create Tor logrotate service: {str(e)}", 
                    solution="Verify systemd service syntax and permissions")

    timer_file = "/etc/systemd/system/logrotate-tor.timer"
    timer_content = """\
[Unit]
Description=Run logrotate for Tor logs every 6 hours

[Timer]
OnCalendar=*:0/6
Persistent=true

[Install]
WantedBy=timers.target
"""
    try:
        with open(timer_file, "w") as f:
            f.write(timer_content)
        src_utils.run_command(f"sudo chmod 644 {timer_file}", 
                               "Failed to set permissions for Tor logrotate timer file.")
        src_utils.success("logrotate-tor.timer created", 
                      details=f"Timer file: {timer_file}")
    except Exception as e:
        src_utils.error(f"Failed to create Tor logrotate timer: {str(e)}", 
                    solution="Check systemd timer syntax and file permissions")

    src_utils.run_command("sudo systemctl enable logrotate-tor.timer", 
                           "Failed to enable logrotate-tor timer.")
    src_utils.run_command("sudo systemctl start logrotate-tor.timer", 
                           "Failed to start logrotate-tor timer.")
    src_utils.success("logrotate-tor timer operational", 
                  details="Systemd timer enabled and started")

    src_utils.run_command("sudo logrotate -f /etc/logrotate.d/tor", 
                           "Failed to run logrotate for Tor logs.")
    src_utils.success("Tor logs manually rotated", 
                  details="Immediate rotation test completed successfully")
