#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_utils
from src import src_remover
from src import src_installer
from src import src_tor
from src import src_menus
from src import src_status
from src import src_proxyson
from src import src_dnsson

#modules >
import os
import re
import time
import subprocess



# -------------------- Socksify Manager --------------------






def setup_dante_tor():
    src_utils.clear_screen()
    src_utils.info("Setting up Socksify + Tor...")

    confirm_deletion = src_utils.get_confirmation(
        f"{src_utils.YELLOW}This will remove existing Tor, Socksify , Dnsson, and Proxyson installations. {src_utils.RESET}\n"
        f"{src_utils.YELLOW}Do you want to proceed?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel): ")
    if not confirm_deletion:
        src_utils.warning("Setup aborted by user. Returning to main menu.")
        input("Press Enter to return to the Auto Setup menu...")
        return

    try:
        with src_utils.temporary_dns() as success:
            if not success:
                src_utils.error("Skipping Tor installation due to repository connectivity issues.", 
                            solution="Check network connectivity and DNS resolution")
                input("Press Enter to Return...")
                return


            print(f"\n{src_utils.YELLOW}Trying To Update repositories{src_utils.RESET}\n")
            if not src_utils.run_apt_update("sudo apt update", timeout=300):
                src_utils.error("Apt Update failed.", 
                            solution="Check package repositories")
                input("Press Enter to return to the Auto Setup menu...")
                return

            src_utils.info("Removing existing installations...")
            src_remover.remove_dante()
            src_remover.remove_tor()
            src_remover.remove_dnsson_proxyson()

            if not src_installer.install_dante():
                src_utils.error("Socksify installation failed.", 
                            solution="Check package repositories and dependencies")
                src_utils.warning("Rolling back changes due to  failures")
                src_remover.remove_dante()
                src_remover.remove_tor()
                src_remover.remove_dnsson_proxyson()
                input("Press Enter to return to the Auto Setup menu...")
                return

            try:
                socks_ip, socks_port, dns_ip, dns_port = src_installer.install_tor()
            except Exception as e:
                src_utils.error(f"Tor installation failed: {str(e)}", 
                            solution="Check Tor repository access and system architecture")
                src_utils.warning("Rolling back changes due to  failures")
                src_remover.remove_dante()
                src_remover.remove_tor()
                src_remover.remove_dnsson_proxyson()
                input("Press Enter to return to the Auto Setup menu...")
                return

            src_utils.info("Configuring Socksify with Tor settings...")
            try:
                configure_dante(socks_ip, socks_port, dns_protocol="fake")
            except Exception as e:
                src_utils.error(f"Failed to configure Socksify: {str(e)}", 
                            solution="Verify Socksify configuration syntax")
                src_utils.warning("Rolling back changes due to  failures")
                src_remover.remove_dante()
                src_remover.remove_tor()
                src_remover.remove_dnsson_proxyson()
                input("Press Enter to return to the Auto Setup menu...")
                return

            src_utils.info("Restarting Tor service...")
            src_tor.restart_tor()

            src_utils.info("Installing and syncing Proxyson +  Dnsson...")
            try:
                src_proxyson.create_proxyson_script(
                    dns_ip=dns_ip, 
                    dns_port=dns_port, 
                    base_command="socksify"
                )
                src_dnsson.create_dnsson_script(dns_ip, dns_port)
            except Exception as e:
                src_utils.error(f"Failed to create proxy scripts: {str(e)}", 
                            solution="Check DNS format and script permissions")
                src_utils.warning("Rolling back changes due to  failures")
                src_remover.remove_dante()
                src_remover.remove_tor()
                src_remover.remove_dnsson_proxyson()
                input("Press Enter to return to the Auto Setup menu...")
                return

    except KeyboardInterrupt:
        src_utils.warning("User interrupted installation! Rolling back changes...")
        src_remover.remove_dante()
        src_remover.remove_tor()
        src_remover.remove_dnsson_proxyson()
        src_utils.success("Cleanup completed", details="All components restored to previous state")
        input("Press Enter to return to the Auto Setup menu...")
        return

    src_utils.success("Socksify + Tor setup completed successfully",
                  details="Dependencies and components installed/updated")

    print("\n——————————————— Attention ———————————————")
    src_utils.warning(f"It is Recommended to {src_utils.CYAN}reboot{src_utils.RESET}{src_utils.YELLOW} the server.{src_utils.RESET}\n")
    src_utils.warning(f"Also run this command: {src_utils.CYAN}source ~/.bashrc{src_utils.RESET}\n")
    src_utils.warning("Wait for the Tor connection to be established",
                    details=f"{src_utils.YELLOW}Check the {src_utils.RESET}{src_utils.CYAN}Connection status{src_utils.RESET}{src_utils.YELLOW} in the Socksify And Proxyson Status menu before using.{src_utils.RESET}\n")
    src_utils.success(f"You can use the {src_utils.CYAN}'nyx'{src_utils.RESET} {src_utils.GREEN}command to monitor Tor more precisely.{src_utils.RESET}\n")

    input("Press Enter to return to the Auto Setup menu...")






def handle_dante_menu():
    while True:
        src_menus.display_dante_menu()
        choice = input("\nSelect an option [0-8]: ").strip()

        if choice == '0':
            break



        elif choice == '1':
            src_status.dante_status()
            input("\nPress Enter to Return...")  # Preserve menu navigation



        elif choice == '2':
            try:
                src_utils.clear_screen()
                print("═" * 40)  
                print("🧦 Socksify INSTALLATION".center(40))  
                print("═" * 40)
                if not src_utils.get_confirmation(f"{src_utils.YELLOW}it will be removed for a clean installation, \nDo you confirm?{src_utils.RESET} (Press Enter for confirmation, or type 'n' or 'no' to cancel): "):
                    continue
                try:
                    with src_utils.temporary_dns() as success:
                        if not success:
                            src_utils.error("Repository connection failed!", 
                                        solution="Check network connectivity and DNS resolution")
                            input("Press Enter to Return...")
                            continue


                        print(f"\n{src_utils.YELLOW}Trying To Update repositories{src_utils.RESET}\n")
                        if not src_utils.run_apt_update("sudo apt update", timeout=300):
                            src_utils.error("Apt Update failed.", 
                                        solution="Check package repositories")
                            input("Press Enter to return to the Auto Setup menu...")
                            return

                        if src_utils.is_installed("dante-client"):
                            src_utils.info("Removing existing installation...")
                            src_remover.remove_dante()


                        if not src_installer.install_dante():
                            raise Exception("Main installation failed")
                        # Sync with Tor
                        if src_utils.get_confirmation(f"\n{src_utils.YELLOW}Sync with Tor settings? (Y/n): {src_utils.RESET}"):
                            if not src_utils.is_installed("tor"):
                                src_utils.warning("Tor not installed! Switching to manual configuration.", 
                                              solution="Install Tor first for full integration")

                                while True:
                                    socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                                    if socks_ip is not None:
                                        break
                                    src_utils.warning("Please re-enter a valid IP address...")
                                while True:
                                    socks_port = src_utils.prompt_for_port("Enter SOCKS Port: ")
                                    if socks_port is not None:
                                        break
                                    src_utils.warning("Please re-enter a valid port number...")
                                configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                src_utils.success("Manual configuration applied", 
                                              details="Configuration done without Tor integration")
                            else:
                                socks_ip, socks_port = src_tor.get_tor_socks_info()
                                if socks_ip in (None, "TORRC_NOT_FOUND") or socks_port in (None, "TORRC_NOT_FOUND"):
                                    src_utils.warning("Invalid Tor configuration detected! Switching to manual configuration.", 
                                                  solution="Check Tor's torrc file for SOCKS settings")

                                    while True:
                                        socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                                        if socks_ip is not None:
                                            break
                                        src_utils.warning("Please re-enter a valid IP address...")
                                    while True:
                                        socks_port = src_utils.prompt_for_port("Enter SOCKS Port (1-65535): ")
                                        if socks_port is not None:
                                            break
                                        src_utils.warning("Please re-enter a valid port number...")
                                    configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                    src_utils.success("Manual configuration applied", 
                                                  details="Fallback configuration used")
                                else:
                                    configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                    src_utils.success("Successfully synced with Tor settings", 
                                                  details=f"SOCKS: {socks_ip}:{socks_port}")
                        else:
                            src_utils.info("Manual configuration:")

                            while True:
                                socks_ip = src_utils.prompt_for_ip("Enter SOCKS IP: ")
                                if socks_ip is not None:
                                    break
                                src_utils.warning("Please re-enter a valid IP address...")
                            while True:
                                socks_port = src_utils.prompt_for_port("Enter SOCKS Port (1-65535): ")
                                if socks_port is not None:
                                    break
                                src_utils.warning("Please re-enter a valid port number...")
                            configure_dante(socks_ip, socks_port, dns_protocol="fake")
                            src_utils.success("Manual configuration applied", 
                                          details=f"Manual settings: {socks_ip}:{socks_port}")
                except KeyboardInterrupt:
                    src_utils.warning("User interrupted installation! Rolling back changes...")
                    src_remover.remove_dante()
                    src_utils.success("Cleanup completed. Exiting...", context="Installation aborted")
                    input("\nPress Enter to Return...")
                    continue
            except Exception as e:
                src_utils.error(f"Critical Error: {str(e)}", 
                            solution="Check package repositories and system permissions")
                src_utils.warning("Performing rollback...", solution="System will revert to previous state")
                src_remover.remove_dante()
                src_utils.success("System restored to previous state", 
                              details="All partially installed components removed")
                input("\nPress Enter to Return...")
                continue
            src_utils.success("Installation completed", 
                          details="Dependencies and Socksify installed successfully")

            print("\n——————————————— Attention ———————————————")
            src_utils.warning(f"It is Recommended to {src_utils.CYAN}reboot{src_utils.RESET} {src_utils.YELLOW}the server.{src_utils.RESET}\n")
            src_utils.warning(f"Also run this command: {src_utils.CYAN}source ~/.bashrc{src_utils.RESET}\n")

            input("\nPress Enter to Return...")




        elif choice == '3':
            src_utils.clear_screen()
            print("═" * 40)  # Preserve menu structure
            print("📝 EDIT CONFIGURATION FILE".center(40))
            print("═" * 40)

            if not src_utils.is_installed("dante-client"):
                src_utils.error("Socksify not installed!", solution="Install Socksify first before editing configuration")
            elif not src_utils.file_exists("/etc/socks.conf"):
                src_utils.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
            else:
                backup_name = f"/etc/socks.conf.bak-{int(time.time())}"
                src_utils.run_command(f"sudo cp /etc/socks.conf {backup_name}", "Backup failed")
                os.system("sudo nano /etc/socks.conf")
                config_content = src_utils.read_file("/etc/socks.conf")

                if "route {" not in config_content:
                    src_utils.error("Invalid configuration! Restoring backup...", 
                                solution="Check syntax of 'route' section in configuration")
                    src_utils.run_command(f"sudo mv {backup_name} /etc/socks.conf", "Restore failed")
                    src_utils.success("Configuration restored from backup", details=f"Backup: {backup_name}")
                else:
                    src_utils.success("Changes saved successfully", 
                                  details=f"New configuration written to /etc/socks.conf")
                    src_utils.run_command(f"sudo rm {backup_name}", "Cleanup failed")
            input("\nPress Enter to Return...")




        elif choice == '4':
            src_utils.clear_screen()
            print("═" * 40)  
            print("🔧 CHANGE SOCKS SETTINGS".center(40))
            print("═" * 40)
            if not src_utils.is_installed("dante-client"):
                src_utils.error("Socksify not installed!", solution="Install Socksify first before changing settings")
            elif not src_utils.file_exists("/etc/socks.conf"):
                src_utils.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
            else:

                while True:
                    new_ip = src_utils.prompt_for_ip("Enter new SOCKS IP: ")
                    if new_ip is not None:
                        break
                    src_utils.warning("Please re-enter a valid IP address...")
                while True:
                    new_port = src_utils.prompt_for_port("Enter new SOCKS Port (1-65535): ")
                    if new_port is not None:
                        break
                    src_utils.warning("Please re-enter a valid port number...")
                if update_dante_config(socks_ip=new_ip, socks_port=new_port):
                    src_utils.success("SOCKS settings updated", details=f"New settings: {new_ip}:{new_port}")
                else:
                    src_utils.error("Failed to update SOCKS settings", 
                                solution="Check IP format and port availability")
            input("\nPress Enter to Return...")



        elif choice == '5':
            src_utils.clear_screen()
            print("═" * 40)  # Preserve menu structure
            print("🔗 CONFIGURE DNS PROTOCOL".center(40))
            print("═" * 40)

            if not src_utils.is_installed("dante-client"):
                src_utils.error("Socksify not installed!", solution="Install Socksify first before configuring DNS")
            elif not src_utils.file_exists("/etc/socks.conf"):
                src_utils.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
            else:
                print("\nAvailable DNS Protocols:")  # Preserve user input flow
                print("1. fake (default - recommended)")
                print("2. tcp (for DNS-over-TCP)")

                proto = src_utils.get_user_input(
                    "Select protocol [1/2]: ",
                    validator=lambda x, _: x in ['1', '2']
                )
                new_proto = "fake" if proto == '1' else "tcp"

                if update_dante_config(dns_protocol=new_proto):
                    src_utils.success(f"DNS protocol set to {new_proto.upper()}", 
                                  details=f"Updated configuration: {new_proto}")
                else:
                    src_utils.error("Failed to update DNS protocol", 
                                solution="Check DNS protocol syntax in configuration file")

            input("\nPress Enter to Return...")



        elif choice == '6':
            change_socks_proxyprotocol()



        elif choice == '7':
            src_utils.clear_screen()
            print("═" * 40)  # Preserve menu structure
            print("🔄 SYNC WITH TOR SETTINGS".center(40))
            print("═" * 40)

            requirements = {
                "Socksify": src_utils.is_installed("dante-client"),
                "socks.conf": src_utils.file_exists("/etc/socks.conf"),
                "Tor": src_utils.is_installed("tor"),
                "torrc": src_utils.file_exists("/etc/tor/torrc")
            }
            missing = [k for k, v in requirements.items() if not v]

            if missing:
                print("❌ Missing requirements:")
                for item in missing:
                    print(f"▸ {item}")

            else:
                socks_ip, socks_port = src_tor.get_tor_socks_info()

                if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
                    print("❌ Tor configuration file not found!")
                                                                               
                    print("  ├─ Path: /etc/tor/torrc")
                    print("  ╰─ Install Tor first or restore configuration")
                elif socks_ip is None or socks_port is None:
                    print("❌ Invalid SocksPort configuration detected!")
                    print("  ├─ Check these settings in torrc:")
                    print("  ╰─ Format: SocksPort <IP>:<PORT>")
                else:
                    if update_dante_config(socks_ip, socks_port):
                        src_utils.success(f"Successfully synced with Tor Socks: {socks_ip}:{socks_port}", 
                                      details="Socksify configuration updated")
                    else:
                        src_utils.error("Failed to update Socksify configuration", 
                                    solution="Check Socksify's socks.conf syntax")

            input("\nPress Enter to Return...")

        elif choice == '8':
            src_utils.clear_screen()
            print("═" * 40)  # Preserve menu structure
            print("🗑️ REMOVE Socksify COMPLETELY".center(40))
            print("═" * 40)

            if src_utils.get_confirmation("This will remove all Socksify components. Continue? (Y/n): "):
                if src_remover.remove_dante():
                    src_utils.success("Socksify removed successfully", 
                                  details="All configuration files and logs deleted")
                else:
                    src_utils.warning("Partial removal detected", 
                                  solution="Check logs for incomplete removal issues")
            else:
                src_utils.info("Operation cancelled", details="No changes made to Socksify installation")

            input("\nPress Enter to Return...")

        else:
            src_utils.error("Invalid choice", solution="Enter a number between 0-8")
            input("Press Enter to try again...")






def update_dante_config(socks_ip=None, socks_port=None, dns_protocol=None):

    file_path = "/etc/socks.conf"
    if not src_utils.file_exists(file_path):
        src_utils.error("Socksify config file not found!", 
                    solution="Verify the file exists at /etc/socks.conf")
        return False

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:

            if socks_ip and socks_port and "via:" in line.lower():
                new_line = re.sub(
                    r'via:\s*\d{1,3}(?:\.\d{1,3}){3}\s*port\s*=\s*\d{1,5}',
                    f"via: {socks_ip} port = {socks_port}",
                    line,
                    flags=re.IGNORECASE
                )
                new_lines.append(new_line)

            elif dns_protocol and "resolveprotocol:" in line.lower():
                new_line = re.sub(
                    r'resolveprotocol:\s*\w+',
                    f"resolveprotocol: {dns_protocol}",
                    line,
                    flags=re.IGNORECASE
                )
                new_lines.append(new_line)
            else:
                new_lines.append(line)

        with open(file_path, "w") as f:
            f.writelines(new_lines)

        src_utils.success("Socksify configuration updated successfully", 
                      details=f"File: {file_path} | SOCKS: {socks_ip or 'UNCHANGED'}:{socks_port or 'UNCHANGED'} | DNS Protocol: {dns_protocol or 'UNCHANGED'}")
        return True

    except Exception as e:
        src_utils.error(f"Error updating Socksify configuration: {str(e)}",
                    solution="Check file permissions and syntax in socks.conf")
        return False





def change_socks_proxyprotocol():
    socks_conf = "/etc/socks.conf"
    
    if not src_utils.is_installed("dante-client"):
        src_utils.error("Socksify not installed!", solution="Install Socksify first before changing proxy protocol")
        input("\nPress Enter to return...")
        return

    if not src_utils.file_exists(socks_conf):
        src_utils.error("Config file not found!", solution=f"Verify file exists at {socks_conf}")
        input("\nPress Enter to return...")
        return

    src_utils.clear_screen()
    print("═" * 40)
    print("🔧 CHANGE SOCKS PROXY PROTOCOL".center(40))
    print("═" * 40)

    print("\nAvailable Protocol Options:")
    print(" 1) socks_v5")
    print(" 2) socks_v4")
    print(" 3) socks_v4 socks_v5 (Both)")

    valid_choices = {"1": "socks_v5", "2": "socks_v4", "3": "socks_v4 socks_v5"}

    while True:
        choice = input("\nSelect Proxy Protocol [1-3]: ").strip()
        if choice in valid_choices:
            selected_protocol = valid_choices[choice]
            break
        else:
            src_utils.error("Invalid selection", solution="Choose 1, 2 or 3")

    # حالا فایل رو می‌خونیم و بخش proxyprotocol رو تغییر میدیم
    try:
        with open(socks_conf, "r") as f:
            lines = f.readlines()

        new_lines = []
        changed = False
        for line in lines:
            if line.strip().startswith("proxyprotocol:"):
                new_lines.append(f"    proxyprotocol: {selected_protocol}\n")
                changed = True
            else:
                new_lines.append(line)

        if not changed:
            src_utils.error("proxyprotocol not found in config!", solution="Manually verify /etc/socks.conf")
            input("\nPress Enter to return...")
            return

        # فایل جدیدو ذخیره کن
        with open(socks_conf, "w") as f:
            f.writelines(new_lines)

        src_utils.success(f"Proxy Protocol updated to: {selected_protocol}")
    except Exception as e:
        src_utils.error("Failed to update proxy protocol", details=str(e))

    input("\nPress Enter to Return...")









def configure_dante(socks_ip, socks_port, dns_protocol="fake"):
    """Configure Dante Client."""
    config_file = "/etc/socks.conf"
    config_content = f"""# Logging configuration
errorlog: /var/log/dante/socks.errlog
logoutput: /var/log/dante/socks.log
debug: 1
# DNS resolution
resolveprotocol: {dns_protocol}
# Route all other traffic through Tor SOCKS (port {socks_port})
route {{
    from: 0.0.0.0/0  to: 0.0.0.0/0
    via: {socks_ip} port = {socks_port}
    proxyprotocol: socks_v5
    method: none
}}
"""
    try:
        with open(config_file, "w") as dante_conf:
            dante_conf.write(config_content)
        src_utils.run_command("sudo mkdir -p /var/log/dante", "Failed to create dante log directory.")
        src_utils.run_command("sudo touch /var/log/dante/socks.errlog", "Failed to create /var/log/dante/socks.errlog.")
        src_utils.run_command("sudo touch /var/log/dante/socks.log", "Failed to create /var/log/dante/socks.log.")
        src_utils.run_command("sudo chmod 660 /var/log/dante/socks.errlog", "Failed to set permissions for /var/log/dante/socks.errlog.")
        src_utils.run_command("sudo chmod 660 /var/log/dante/socks.log", "Failed to set permissions for /var/log/dante/socks.log.")
        src_utils.run_command(f"echo 'export SOCKS_CONF={config_file}' | sudo tee -a ~/.bashrc", "Failed to add SOCKS_CONF to ~/.bashrc")
        src_utils.run_command(f"echo 'SOCKS_CONF={config_file}' | sudo tee -a /etc/environment", "Failed to add SOCKS_CONF to /etc/environment")
        src_utils.run_command("bash -c 'source ~/.bashrc'", "Applying changes")
        src_utils.run_command("source ~/.bashrc", "2nd Applying changes")
        src_utils.run_command("set -a; source /etc/environment; set +a", "Applying system-wide changes")

        # Log configuration success
        src_utils.success("Socksify  configured successfully", 
                      details=f"Configuration file: {config_file} | DNS Protocol: {dns_protocol}")

        # Setup logrotate (this function already uses Logger internally)
        setup_dante_logrotate()


        return True

    except Exception as e:
        src_utils.error(f"Configuration failed: {str(e)}",
                     solution="Verify permissions for /etc/socks.conf and log directories")
        return False









def setup_dante_logrotate():

    logrotate_config = "/etc/logrotate.d/dante"
    
    if os.path.exists(logrotate_config):
        src_utils.info("Socksify logrotate configuration already exists. Skipping creation.")
        return

    logrotate_config_content = """\
/var/log/dante/socks.errlog /var/log/dante/socks.log {
    size 100M
    rotate 0
    missingok
    notifempty
    copytruncate
    create 660 root adm
}
"""
    try:
        with open(logrotate_config, "w") as f:
            f.write(logrotate_config_content)
        src_utils.run_command(f"sudo chmod 644 {logrotate_config}", "Failed to set permissions for logrotate config.")
        src_utils.success("Socksify logrotate configuration created", details=f"Path: {logrotate_config}")
    except Exception as e:
        src_utils.error(f"Error creating logrotate config: {str(e)}", solution="Check write permissions and disk space")


    service_file = "/etc/systemd/system/logrotate-dante.service"
    service_content = """\
[Unit]
Description=Run logrotate for Dante logs

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate -f /etc/logrotate.d/dante
"""
    try:
        with open(service_file, "w") as f:
            f.write(service_content)
        src_utils.run_command(f"sudo chmod 644 {service_file}", "Failed to set permissions for logrotate service.")
        src_utils.success("logrotate-dante.service created", details=f"Service file: {service_file}")
    except Exception as e:
        src_utils.error(f"Error creating service file: {str(e)}", solution="Verify systemd service syntax and permissions")


    timer_file = "/etc/systemd/system/logrotate-dante.timer"
    timer_content = """\
[Unit]
Description=Run logrotate for Dante logs every 6 hours

[Timer]
OnCalendar=*:0/6
Persistent=true

[Install]
WantedBy=timers.target
"""
    try:
        with open(timer_file, "w") as f:
            f.write(timer_content)
        src_utils.run_command(f"sudo chmod 644 {timer_file}", "Failed to set permissions for logrotate timer.")
        src_utils.success("logrotate-dante.timer created", details=f"Timer file: {timer_file}")

    except Exception as e:
        src_utils.error(f"Error creating timer file: {str(e)}", solution="Check systemd timer syntax and file permissions")


    src_utils.run_command("sudo systemctl enable logrotate-dante.timer", "Failed to enable logrotate-dante timer.")
    src_utils.run_command("sudo systemctl start logrotate-dante.timer", "Failed to start logrotate-dante timer.")
    src_utils.success("logrotate-dante timer enabled and started", details="Systemd timer configured successfully")


    src_utils.run_command("sudo logrotate -f /etc/logrotate.d/dante", "Failed to run logrotate for Dante logs.")
    src_utils.success("Dante logs rotated immediately", details="Manual rotation completed successfully")
    
    return True

