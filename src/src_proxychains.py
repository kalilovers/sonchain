#!/usr/bin/env python3

# -*- coding: utf-8 -*-




#src_ > >>>
from src import src_utils
from src import src_status
from src import src_remover
from src import src_installer
from src import src_tor
from src import src_menus

#modules >
import os
import re
import shutil
import subprocess
import time
import uuid



# -------------------- ProxychainsManager --------------------




def handle_proxychains_menu():
    while True:
        src_menus.display_proxychains_menu()
        choice = input("\nSelect an option : ").strip()



        if choice == '0':
            break




        elif choice == '1':
            src_utils.clear_screen()
            src_status.proxychains_status()
            input("\nPress Enter to Return...")




        elif choice == '2':
            src_utils.clear_screen()
            print("═" * 40)
            print("🧦 PROXYCHAINS INSTALL".center(40))
            print("═" * 40)
            if not src_utils.get_confirmation(f"{src_utils.YELLOW}it will be removed for a clean installation, \nDo you confirm?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel): "):
                continue

            try:
                print(f"\n{src_utils.YELLOW}Trying To Update repositories{src_utils.RESET}\n")
                if not src_utils.run_apt_update("sudo apt update", timeout=300):
                    src_utils.error("Apt Update failed.", 
                                solution="Check package repositories")
                    input("Press Enter to return to the Auto Setup menu...")
                    return


                if not src_remover.remove_proxychains():
                    src_utils.error("Critical error during removal", 
                                solution="Verify dependencies or reinstall manually")
                    input("Press Enter to return...")
                    continue

                if not src_installer.install_proxychains():
                    src_utils.error("Installation failed", 
                                solution="Check logs for dependency issues")
                    src_remover.remove_proxychains()
                    input("Press Enter to return...")
                    continue

                if src_utils.get_confirmation(f"\n{src_utils.YELLOW}Sync with Tor settings? (Y/n): {src_utils.RESET}"):
                    src_utils.info("Checking Tor configuration...", icon="🔎")
                    tor_installed = src_utils.is_installed("tor")
                    torrc_exists = src_utils.file_exists("/etc/tor/torrc")

                    if not tor_installed or not torrc_exists:
                        print("❌ Tor not fully configured!")
                        print("  ├─ Installed: " + ("✅" if tor_installed else "❌"))
                        print("  ╰─ Config: " + ("✅" if torrc_exists else "❌"))
                        print("⤷ Switching to manual configuration")

                        # Loop until valid IP is entered
                        while True:
                            socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                            if socks_ip is not None:
                                break
                            src_utils.warning("Please re-enter a valid IP address...")

                        # Loop until valid Port is entered
                        while True:
                            socks_port = src_utils.prompt_for_port("Enter SOCKS Port: ")
                            if socks_port is not None:
                                break
                            src_utils.warning("Please re-enter a valid port number...")

                    else:
                        socks_ip, socks_port = src_tor.get_tor_socks_info()

                        if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
                            src_utils.error("Tor configuration file error", 
                                        solution="Fix permissions in /etc/tor/torrc")

                            # Loop until valid IP is entered
                            while True:
                                socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                                if socks_ip is not None:
                                    break
                                src_utils.warning("Please re-enter a valid IP address...")

                            # Loop until valid Port is entered
                            while True:
                                socks_port = src_utils.prompt_for_port("Enter SOCKS Port: ")
                                if socks_port is not None:
                                    break
                                src_utils.warning("Please re-enter a valid port number...")

                        elif socks_ip is None or socks_port is None:
                            src_utils.error("Invalid SocksPort in torrc , use manual entry", 
                                        solution="Check port settings in /etc/tor/torrc")

                            # Loop until valid IP is entered
                            while True:
                                socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                                if socks_ip is not None:
                                    break
                                src_utils.warning("Please re-enter a valid IP address...")

                            # Loop until valid Port is entered
                            while True:
                                socks_port = src_utils.prompt_for_port("Enter SOCKS Port: ")
                                if socks_port is not None:
                                    break
                                src_utils.warning("Please re-enter a valid port number...")

                        else:
                            src_utils.success("Tor settings detected", 
                                          details=f"Using Tor configuration: {socks_ip}:{socks_port}")

                    if configure_proxychains(socks_ip, socks_port):
                        src_utils.success("ProxyChains configured successfully", 
                                      details=f"Proxy: {socks_ip}:{socks_port}")
                    else:
                        src_utils.error("Critical configuration error", 
                                    solution="Check proxychains.conf syntax and permissions")
                        src_remover.remove_proxychains()

                else:
                    src_utils.info("Manual configuration selected", icon="📝")

                    # Loop until valid IP is entered
                    while True:
                        socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                        if socks_ip is not None:
                            break
                        src_utils.warning("Please re-enter a valid IP address...")

                    # Loop until valid Port is entered
                    while True:
                        socks_port = src_utils.prompt_for_port("Enter SOCKS Port: ")
                        if socks_port is not None:
                            break
                        src_utils.warning("Please re-enter a valid port number...")

                    if configure_proxychains(socks_ip, socks_port):
                        src_utils.success("ProxyChains configured manually", 
                                      details=f"Proxy: {socks_ip}:{socks_port}")
                    else:
                        src_utils.error("Configuration failed", 
                                    solution="Check proxy syntax and file permissions")
                        src_remover.remove_proxychains()

            except KeyboardInterrupt:
                src_utils.warning("Operation cancelled by user!", solution="Performing cleanup...")
                src_remover.remove_proxychains()
                src_utils.success("Partial installation removed", details="ProxyChains rollback completed")
                input("\nPress Enter to return...")
                continue

            input("\nPress Enter to return...")




        elif choice == '3':
            if not src_utils.file_exists("/etc/proxychains.conf"):
                src_utils.error("Proxychains configuration file missing!", 
                            solution="Reinstall Proxychains, or edit /etc/proxychains.conf manually")
                input("\nPress Enter to Return...")
                continue
            else:
                backup = f"/etc/proxychains.conf.bak-{int(time.time())}"
                try:
                    shutil.copyfile("/etc/proxychains.conf", backup)
                    src_utils.success("Backup created", details=f"Path: {backup}")

                    src_utils.info("Opening proxychains configuration in nano editor...", 
                               details="Editing /etc/proxychains.conf")
                    os.system("sudo nano /etc/proxychains.conf")

                    content = src_utils.read_file("/etc/proxychains.conf")
                    active_proxylist = any(
                        line.strip().startswith("[ProxyList]") and not line.strip().startswith("#")
                        for line in content.splitlines()
                    )

                    if not active_proxylist:
                        src_utils.error("Invalid configuration detected", 
                                    solution="Missing [ProxyList] section")

                        restore_choice = src_utils.get_confirmation(
                            "⚠️ [ProxyList] missing. Restore backup? (Y/n): ",
                            default=True,
                            language="en"
                        )
                        if restore_choice:
                            try:
                                shutil.copyfile(backup, "/etc/proxychains.conf")
                                src_utils.success("Backup restored successfully", 
                                              details=f"Restored from {backup}")
                            except Exception as e:
                                src_utils.error(f"Failed to restore backup: {str(e)}", 
                                            solution="Manually restore from {backup}")
                        else:
                            src_utils.warning("Keeping the modified (invalid) configuration", 
                                          solution="This may cause issues")

                finally:
                    if os.path.exists(backup):
                        os.remove(backup)
                        src_utils.info("Backup file cleaned up", details=f"Path: {backup}")

                input("\nPress Enter to Return...")






        elif choice == '4':
            if not src_utils.file_exists("/etc/proxychains.conf"):
                src_utils.error("Proxychains configuration missing!", 
                            solution="Install ProxyChains first")
                input("Press Enter to Return...")
                continue

            print("\nSelect Chain Type:")
            print("1. Dynamic Chain")
            print("2. Round Robin Chain")
            print("3. Random Chain")
            print("4. Strict Chain")
            
            sub_choice = input("Enter your choice (1-4): ").strip()
            chain_map = {
                "1": "dynamic_chain",
                "2": "round_robin_chain",
                "3": "random_chain",
                "4": "strict_chain"
            }
            
            selected_chain = chain_map.get(sub_choice)
            if selected_chain:
                change_chain_mode(selected_chain)
            else:
                src_utils.error("Invalid chain type selected", 
                            solution="Choose 1-4 for chain types")

            input("\nPress Enter to Return...")




        elif choice == '5':
            change_quiet_mode()
            input("\nPress Enter to Return...")




        elif choice == '6':
            if not src_utils.file_exists("/etc/proxychains.conf"):
                src_utils.error("Proxychains config file missing!",
                            solution="Reinstall Proxychains")
                input("Press Enter to Return...")
                continue
            print("\nSelect Proxy DNS Mode:")
            print("1. Enable proxy_dns")
            print("2. Enable proxy_dns_old")
            print("3. Disable both modes")
            
            sub_choice = input("Enter your choice (1/2/3): ").strip()
            mode = {"1": "proxy_dns", "2": "proxy_dns_old", "3": "disable"}.get(sub_choice)
            
            if mode:
                change_proxychain_dns_mode(mode)
            else:
                src_utils.error("Invalid DNS mode selected", 
                            solution="Choose 1 for proxy_dns, 2 for proxy_dns_old, or 3 to disable both")

            input("\nPress Enter to Return...")




        elif choice == '7':
            add_proxy_to_chain()
            input("\nPress Enter to Return...")




        elif choice == '8':
            if sync_proxychains_with_tor():
                src_utils.success("ProxyChains synced with Tor", 
                              details="DNS and SOCKS settings updated")

        elif choice == '9':
            sync_proxychains_with_psiphon()
            input("\nPress Enter to Return...")



        elif choice == '10':
            src_utils.clear_screen()
            print("=========================================")  # Preserve menu borders
            print("            Remove ProxyChains")
            print("=========================================\n")

            confirm_remove = src_utils.get_confirmation(
                "Warning: This will completely remove ProxyChains and its configurations.\n"
                "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
            )
            if not confirm_remove:
                src_utils.warning("Removal aborted by user", solution="Re-run setup to try again")
                input("Press Enter to Return...")
                continue

            if src_remover.remove_proxychains():
                src_utils.success("ProxyChains removed completely")
            else:
                src_utils.warning("Partial removal detected", 
                              details="Some files may remain - check manually")
            input("\nPress Enter to Return...")

        else:
            src_utils.error(
                "Invalid menu choice",
                solution="Select a valid number from the menu options.",
                details=f"Received: {choice}"
            )
            input("Press Enter to try again...")








def configure_proxychains(socks_ip, socks_port):

    config_file = "/etc/proxychains.conf"

    if not src_utils.file_exists(config_file):
        src_utils.error("Proxychains configuration file not found!", 
                    solution="Verify the file exists at /etc/proxychains.conf")
        return False

    config_content = src_utils.read_file(config_file).splitlines()
    new_config_content = []
    in_proxylist_section = False

    for line in config_content:
        stripped_line = line.strip()
        if stripped_line == "[ProxyList]":
            in_proxylist_section = True
            new_config_content.append("[ProxyList]")
            new_config_content.append(f"socks5 {socks_ip} {socks_port}")
        elif not in_proxylist_section:
            if stripped_line == "strict_chain":
                new_config_content.append("#strict_chain")
                new_config_content.append("dynamic_chain")
            else:
                new_config_content.append(line)
        elif stripped_line and not stripped_line.startswith("#"):
            continue
        else:
            new_config_content.append(line)

    try:
        with open(config_file, "w") as proxychains_conf:
            for line in new_config_content:
                proxychains_conf.write(f"{line}\n")
        src_utils.success("ProxyChains configuration updated successfully", 
                      details=f"Configured: socks5 {socks_ip}:{socks_port}")
        return True
    except Exception as e:
        src_utils.error(f"Failed to write ProxyChains configuration: {str(e)}", 
                    solution="Check file permissions or disk space")
        return False






def change_proxychain_dns_mode(mode):

    config_file = "/etc/proxychains.conf"

    if not src_utils.file_exists(config_file):
        src_utils.error("Proxychains configuration file not found!", 
                    solution="Verify the file exists at /etc/proxychains.conf")
        return False

    try:
        current_config = src_utils.read_file(config_file)
        new_config = current_config

        # Exact match for proxy_dns and proxy_dns_old
        has_proxy_dns_old = re.search(r'(^|\n)(#?proxy_dns_old)(\n|$)', current_config)
        has_proxy_dns = re.search(r'(^|\n)(#?proxy_dns)(\n|$)', current_config)

        if mode == "proxy_dns":
            # Enable proxy_dns and disable proxy_dns_old if exists
            if has_proxy_dns_old:
                new_config = re.sub(r'(^|\n)(#?proxy_dns_old)(\n|$)', r'\1#proxy_dns_old\3', new_config)
            if has_proxy_dns:
                new_config = re.sub(r'(^|\n)(#?proxy_dns)(\n|$)', r'\1proxy_dns\3', new_config)
            else:
                new_config = "proxy_dns\n" + new_config.strip() + "\n"
            src_utils.success("Proxy DNS mode set to proxy_dns", 
                          details=f"Configuration updated at: {config_file}")
        elif mode == "proxy_dns_old":
            # Enable proxy_dns_old and disable proxy_dns if exists
            if has_proxy_dns:
                new_config = re.sub(r'(^|\n)(#?proxy_dns)(\n|$)', r'\1#proxy_dns\3', new_config)
            if has_proxy_dns_old:
                new_config = re.sub(r'(^|\n)(#?proxy_dns_old)(\n|$)', r'\1proxy_dns_old\3', new_config)
            else:
                new_config = "proxy_dns_old\n" + new_config.strip() + "\n"
            src_utils.success("Proxy DNS mode set to proxy_dns_old", 
                          details=f"Configuration updated at: {config_file}")
        elif mode == "disable":
            changes = []
            if has_proxy_dns:
                new_config = re.sub(r'(^|\n)(#?proxy_dns)(\n|$)', r'\1#proxy_dns\3', new_config)
                changes.append("proxy_dns disabled")
            if has_proxy_dns_old:
                new_config = re.sub(r'(^|\n)(#?proxy_dns_old)(\n|$)', r'\1#proxy_dns_old\3', new_config)
                changes.append("proxy_dns_old disabled")

            if not changes:
                src_utils.warning("No proxy DNS settings found to disable", 
                              solution="Check existing settings in proxychains.conf")
            else:
                src_utils.success(f"{' and '.join(changes)} applied", 
                              details=f"Configuration updated at: {config_file}")

        with open(config_file, "w") as f:
            f.write(new_config)
        return True

    except Exception as e:
        src_utils.error(f"Failed to change Proxy DNS mode: {str(e)}", 
                    solution="Check file permissions or syntax in proxychains.conf", 
                    details=f"Mode attempted: {mode}")
        return False








def change_quiet_mode():

    config_file = "/etc/proxychains.conf"

    if not src_utils.file_exists(config_file):
        src_utils.error("Proxychains configuration file not found!", 
                    solution="Verify the file exists at /etc/proxychains.conf")
        return False

    try:
        current_config = src_utils.read_file(config_file)
        
        if "quiet_mode" in current_config:

            new_config = re.sub(r'(^|\n)(#?quiet_mode)',
                                lambda m: f"{m.group(1)}{'#quiet_mode' if m.group(2) == 'quiet_mode' else 'quiet_mode'}",
                                current_config,
                                count=1)
            new_status = "Activated" if "quiet_mode" in new_config and "#quiet_mode" not in new_config else "Disabled"
        else:

            new_config = "quiet_mode\n" + current_config.strip() + "\n"
            new_status = "Activated"

        with open(config_file, "w") as f:
            f.write(new_config)

        src_utils.success(f"Quiet Mode {new_status}", 
                      details=f"New configuration written to: {config_file}")
        return True

    except Exception as e:
        src_utils.error(f"Failed to toggle Quiet Mode: {str(e)}", 
                    solution="Check file permissions or syntax in proxychains.conf")
        return False






def change_chain_mode(selected_mode):

    config_file = "/etc/proxychains.conf"
    supported_modes = ["dynamic_chain", "round_robin_chain", "random_chain", "strict_chain"]

    if selected_mode not in supported_modes:
        src_utils.error(f"Invalid mode: {selected_mode}", 
                    solution=f"Supported modes: {', '.join(supported_modes)}")
        return False

    if not src_utils.file_exists(config_file):
        src_utils.error("Proxychains configuration file not found!", 
                    solution="Verify file exists at /etc/proxychains.conf")
        return False

    backup_file = None
    try:
        original_config = src_utils.read_file(config_file)
        lines = original_config.splitlines()
        new_lines = []
        selected_mode_active = False

        for line in lines:

            leading_ws = re.match(r'^\s*', line).group()
            stripped = line.strip()

            is_mode_line = False
            for mode in supported_modes:

                if stripped.lstrip('#').strip() == mode:
                    is_mode_line = True
                    if mode == selected_mode:
                        if not selected_mode_active:

                            new_lines.append(leading_ws + selected_mode)
                            selected_mode_active = True
                        else:

                            new_lines.append(leading_ws + "#" + selected_mode)
                    else:

                        new_lines.append(leading_ws + "#" + mode)
                    break
            if not is_mode_line:
                new_lines.append(line)


        if not selected_mode_active:
            insertion_index = 0
            for i, line in enumerate(new_lines):
                if line.strip() and not line.strip().startswith('#'):
                    insertion_index = i
                    break
            new_lines.insert(insertion_index, selected_mode)

        new_config = "\n".join(new_lines) + "\n"


        backup_file = f"{config_file}.bak-{uuid.uuid4()}"
        with open(backup_file, 'w') as file:  
            file.write(original_config)

        with open(config_file, 'w') as file:  
            file.write(new_config)


        active_count = sum(1 for line in new_config.splitlines() if line.strip() == selected_mode)
        if active_count == 1:
            src_utils.success(f"{selected_mode} mode activated successfully", 
                          details=f"Config file updated at: {config_file}")
            return True
        else:
            src_utils.error(f"Failed to activate {selected_mode}", 
                        details=f"Active count: {active_count}, Expected: 1")
            return False

    except Exception as e:
        src_utils.error(f"Error changing proxychains mode: {str(e)}", 
                    solution="Check file permissions or syntax in proxychains.conf",
                    details=f"Mode: {selected_mode}")

        if backup_file and os.path.exists(backup_file):
            with open(config_file, 'w') as file:  
                with open(backup_file, 'r') as backup:
                    file.write(backup.read())
            src_utils.warning("Configuration rolled back to backup", 
                          details=f"Backup file: {backup_file}")
        return False

    finally:

        if backup_file and os.path.exists(backup_file):
            os.remove(backup_file)
            src_utils.success("Backup file removed", 
                          details=f"Backup: {backup_file} deleted successfully")






def sync_proxychains_with_tor():
    config_file = "/etc/proxychains.conf"
    torrc_file = "/etc/tor/torrc"

    # Check if ProxyChains configuration file exists
    if not src_utils.file_exists(config_file):
        src_utils.error("ProxyChains configuration file not found!", 
                    solution="Verify the file exists at /etc/proxychains.conf")
        input("Press Enter to return...")
        return False

    # Check if Tor is installed and Tor configuration file exists
    if not src_utils.is_installed("tor") or not src_utils.file_exists(torrc_file):
        src_utils.error("Tor is not installed or Tor configuration file is missing!", 
                    solution="Install Tor and ensure /etc/tor/torrc exists")
        input("Press Enter to return...")
        return False

    socks_ip, socks_port = src_tor.get_tor_socks_info()
    if socks_ip in ("TORRC_NOT_FOUND", None) or socks_port in ("TORRC_NOT_FOUND", None):
        src_utils.error("Tor Socks configuration is missing or invalid!", 
                    solution="Check SocksPort settings in /etc/tor/torrc")
        input("Press Enter to return...")
        return False

    # Read the ProxyChains configuration file
    try:
        with open(config_file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        src_utils.error(f"Failed to read ProxyChains config: {str(e)}", 
                    solution="Check file permissions")
        input("Press Enter to return...")
        return False

    proxylist_found = False
    new_lines = []
    i = 0
    duplicate_found = False

    while i < len(lines):
        line = lines[i]
        if line.strip() == "[ProxyList]":
            proxylist_found = True
            new_lines.append(line)
            i += 1
            section_lines = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith("["):
                section_lines.append(lines[i])
                i += 1

            processed_section_lines = []
            for proxy_line in section_lines:
                if "#tor" in proxy_line:
                    continue
                processed_section_lines.append(proxy_line)

            new_tor_line = f"socks5 {socks_ip} {socks_port} #tor\n"

            if new_tor_line in processed_section_lines:
                duplicate_found = True
            else:
                duplicate_found = False

            if duplicate_found:
                src_utils.error("Tor proxy is already configured in the file!", 
                                solution="Remove existing socks5 line manually before retrying")
                input("Press Enter to return...")
                return False

            processed_section_lines.append(new_tor_line)

            new_lines.extend(processed_section_lines)

            while i < len(lines):
                new_lines.append(lines[i])
                i += 1
            break
        else:
            new_lines.append(line)
            i += 1

    if not proxylist_found:
        new_lines.append("\n[ProxyList]\n")
        new_lines.append(f"socks5 {socks_ip} {socks_port} #tor\n")

    backup_file = config_file + ".bak"
    try:
        shutil.copy(config_file, backup_file)
    except Exception as e:
        src_utils.error(f"Failed to create backup: {str(e)}", 
                    solution="Check write permissions and disk space")
        input("Press Enter to return...")
        return False

    try:
        with open(config_file, "w") as f:
            f.writelines(new_lines)
        src_utils.success("ProxyChains successfully synced with Tor", 
                      details=f"Configured: socks5 {socks_ip}:{socks_port}")
    except Exception as e:
        src_utils.error(f"Failed to update ProxyChains config: {str(e)}", 
                    solution="Check file permissions and try again")
        input("Press Enter to return...")
        return False

    input("Press Enter to return...")
    return True








def sync_proxychains_with_psiphon():
    from src import src_psiphon
    config_file = "/etc/proxychains.conf"
    socks_ip = "127.0.0.1"

    if not src_utils.file_exists(config_file):
        src_utils.error("ProxyChains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
        return False

    result = src_psiphon.check_parameters("LocalSocksProxyPort", validate=True)
    if not isinstance(result, dict):
        src_utils.error("Failed to get Psiphon configuration!", 
                        solution="Check if Psiphon is installed and configured properly")
        return False

    param = result.get("LocalSocksProxyPort", {})
    socks_port = param.get("value")
    valid = param.get("valid", False)

    if not valid or not socks_port:
        src_utils.error("Invalid or missing Psiphon SOCKS port!", 
                        solution="Check your Psiphon config file")
        return False

    try:
        with open(config_file, "r") as f:
            lines = f.readlines()
    except Exception as e:
        src_utils.error(f"Failed to read ProxyChains config: {str(e)}", 
                        solution="Check file permissions")
        return False

    proxylist_found = False
    new_lines = []
    i = 0
    duplicate_found = False

    while i < len(lines):
        line = lines[i]
        if line.strip() == "[ProxyList]":
            proxylist_found = True
            new_lines.append(line)
            i += 1
            section_lines = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith("["):
                section_lines.append(lines[i])
                i += 1

            processed_section_lines = []
            for proxy_line in section_lines:
                if "#psiphon" in proxy_line:
                    continue

                parts = proxy_line.strip().split()
                if len(parts) >= 3 and parts[0].lower() == "socks5":
                    if parts[1] == socks_ip and parts[2] == str(socks_port):
                        duplicate_found = True

                processed_section_lines.append(proxy_line)

            if duplicate_found:
                src_utils.error("Psiphon proxy is already configured!", 
                                solution="Remove duplicate socks5 entry manually")
                return False

            new_lines.extend(processed_section_lines)
            new_lines.append(f"socks5 {socks_ip} {socks_port} #psiphon\n")
            while i < len(lines):
                new_lines.append(lines[i])
                i += 1
            break
        else:
            new_lines.append(line)
            i += 1

    if not proxylist_found:
        new_lines.append("\n[ProxyList]\n")
        new_lines.append(f"socks5 {socks_ip} {socks_port} #psiphon\n")

    backup_file = config_file + ".bak"
    try:
        shutil.copy(config_file, backup_file)
    except Exception as e:
        src_utils.error(f"Failed to create backup: {str(e)}", 
                        solution="Check write permissions and disk space")
        return False

    try:
        with open(config_file, "w") as f:
            f.writelines(new_lines)
        src_utils.success("ProxyChains successfully synced with Psiphon", 
                          details=f"Configured: socks5 {socks_ip}:{socks_port}")
    except Exception as e:
        src_utils.error(f"Failed to update ProxyChains config: {str(e)}", 
                        solution="Check file permissions and try again")
        return False

    return True












def add_proxy_to_chain(ip=None, port=None):

    config_file = "/etc/proxychains.conf"

    # Check if the configuration file exists
    if not src_utils.file_exists(config_file):
        src_utils.error("ProxyChains configuration file not found!", 
                    solution="Verify the file exists at /etc/proxychains.conf")
        return False

    # Read the entire configuration file
    try:
        content = src_utils.read_file(config_file)
    except Exception as e:
        src_utils.error(f"Failed to read ProxyChains config: {str(e)}", 
                    solution="Check file permissions")
        return False

    # Check if an active [ProxyList] section exists
    active_proxylist = any(
        line.strip().startswith("[ProxyList]") and not line.strip().startswith("#")
        for line in content.splitlines()
    )
    if not active_proxylist:
        src_utils.error("ProxyList section not found or inactive in config!", 
                    solution="Add/enable the [ProxyList] section in proxychains.conf")
        return False

    # Prompt for proxy IP and Port using validators
    if not ip:
        # Loop until valid IP is entered
        while True:
            ip = src_utils.prompt_for_ip("Enter Proxy IP: ")
            if ip is not None:
                break
            src_utils.warning("Please re-enter a valid IP address...")

    if not port:
        # Loop until valid Port is entered
        while True:
            port = src_utils.prompt_for_port("Enter Proxy Port: ")
            if port is not None:
                break
            src_utils.warning("Please re-enter a valid port number...")

    # Check for duplicate proxy in [ProxyList] section
    proxy_section_lines = []
    in_proxylist = False
    for line in content.splitlines():
        if line.strip() == "[ProxyList]":
            in_proxylist = True
            continue
        if in_proxylist:
            if line.strip() == "" or line.strip().startswith('['):
                break
            proxy_section_lines.append(line.strip())

    for line in proxy_section_lines:
        tokens = line.split()
        if len(tokens) >= 3:
            if tokens[1] == ip and tokens[2] == str(port):
                src_utils.error("This Proxy already exists in configuration!", 
                            solution="Remove the duplicate entry first")
                return False

    # Authentication details
    add_auth = src_utils.get_confirmation("Do you want to add username and password for this proxy? (Y/n): ")
    username = ""
    password = ""
    if add_auth:
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

    # Proxy type selection
    print("\nChoose Proxy Type:")
    print("1. SOCKS4")
    print("2. SOCKS5")
    print("3. HTTP")
    ptype = src_utils.get_user_input("Select type [1-3]: ", 
                                     validator=lambda x, _: x in ['1', '2', '3'])
    proxy_types = {'1': 'socks4', '2': 'socks5', '3': 'http'}
    ptype_str = proxy_types[ptype]

    # Construct the proxy line: if username and password are provided include them
    if username and password:
        proxy_line = f"{ptype_str} {ip} {port} {username} {password}\n"
    else:
        proxy_line = f"{ptype_str} {ip} {port}\n"


    # Insert proxy line into [ProxyList] section
    new_lines = []
    inserted = False
    in_proxylist = False
    for line in content.splitlines(keepends=True):
        if line.strip() == "[ProxyList]":
            in_proxylist = True
            new_lines.append(line)
            continue
        if in_proxylist and not inserted:
            if line.strip() == "" or line.strip().startswith('['):
                new_lines.append(proxy_line)
                inserted = True
            new_lines.append(line)
        else:
            new_lines.append(line)
    if in_proxylist and not inserted:
        new_lines.append(proxy_line)

    # Write to file
    try:
        with open(config_file, "w") as f:
            f.writelines(new_lines)
        src_utils.success("Proxy added to ProxyChains configuration", 
                      details=f"Proxy: {proxy_line.strip()}")
        return True
    except Exception as e:
        src_utils.error(f"Failed to update ProxyChains config: {str(e)}", 
                    solution="Check write permissions and disk space")
                    
        return False






def setup_proxychains_tor():
    src_utils.clear_screen()
    print("Setting up Proxychains + Tor...")

    confirm_deletion = src_utils.get_confirmation(
        f"\n{src_utils.YELLOW}This will remove existing Tor and Proxychains installations.{src_utils.RESET}"
        f"\n{src_utils.YELLOW}Do you want to proceed?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel): ")
    if not confirm_deletion:
        src_utils.warning("Setup aborted by user. Returning to main menu.")
        input("Press Enter to return to the Auto Install menu...")
        return

    try:
        print(f"\n{src_utils.YELLOW}Trying To Update repositories{src_utils.RESET}\n")
        if not src_utils.run_apt_update("sudo apt update", timeout=300):
            src_utils.error("Apt Update failed.", solution="Check package repositories")
            input("Press Enter to return to the Auto Setup menu...")
            return

        src_remover.remove_tor()
        src_remover.remove_proxychains()

        # Install ProxyChains
        if not src_installer.install_proxychains():
            src_utils.error("ProxyChains installation failed. Cleaning up...",
                            solution="Check dependencies or try reinstalling later")
            src_remover.remove_proxychains()
            input("\nPress Enter to return to the Auto Install menu...")
            return

        # Install Tor
        tor_installed = False
        try:
            socks_ip, socks_port, dns_ip, dns_port = src_installer.install_tor()
            tor_installed = True
        except Exception as e:
            src_utils.error(f"Tor installation failed: {str(e)}",
                            solution="Check Tor repository access and system architecture")
            src_remover.remove_proxychains()
            src_remover.remove_tor()
            input("\nPress Enter to return to the Auto Install menu...")
            return

        # Configure Proxychains
        try:
            configure_proxychains(socks_ip, socks_port)
        except Exception as e:
            src_utils.error("Proxychains configuration failed",
                            solution=f"Check parameters: socks_ip={socks_ip}, socks_port={socks_port}")
            src_remover.remove_proxychains()
            src_remover.remove_tor()
            input("\nPress Enter to return to the Auto Install menu...")
            return

        # Cleanup temporary files
        if not src_utils.run_command("rm -rf proxychains-ng-4.17.tar.xz",
                                      "Failed to Remove proxychains-ng-4.17.tar.xz"):
            src_utils.warning("Temporary file cleanup failed",
                              details="Manual deletion may be required")

    except KeyboardInterrupt:
        src_utils.warning("User interrupted installation! Rolling back changes...")
        src_remover.remove_tor()
        src_remover.remove_proxychains()
        src_utils.success("Cleanup completed. Exiting...", details="Resources restored to initial state")
        input("\nPress Enter to return to the Auto Install menu...")
        return


    src_utils.success("Proxychains + Tor setup completed successfully",
                      details=f"Tor and Proxychains configured with:\n"
                              f"  • SOCKS IP: {socks_ip}:{socks_port}\n"
                              f"  • DNS IP: {dns_ip}:{dns_port}")

    src_utils.warning("Wait for the Tor connection to be established",
                      details=f"{src_utils.YELLOW}Check the {src_utils.RESET}{src_utils.CYAN}Connection status{src_utils.RESET}{src_utils.YELLOW} in the Proxychains Status menu before using.{src_utils.RESET}\n")

    src_utils.success(f"You can use the {src_utils.CYAN}'nyx'{src_utils.RESET} {src_utils.GREEN}command to monitor Tor more precisely.{src_utils.RESET}\n")

    input("\nPress Enter to return to the Auto Install menu...")

 
 