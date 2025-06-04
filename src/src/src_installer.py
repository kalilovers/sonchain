#!/usr/bin/env python3

# -*- coding: utf-8 -*-


#src_ > >>>
from src import src_tor
from src import src_remover
from src import src_utils
from src import src_psiphon
#modules >
import os
import subprocess
import tempfile
import re
import shutil


# -------------------- Installer --------------------




def install_dante():
    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}Installing Socksify...{src_utils.RESET}".center(40))
    print("\n")

    src_remover.fix_apt_issues()

    src_utils.manage_resolv_conf("start_backup")

    try:
        if not src_utils.run_apt_command("sudo apt-get install -y dante-client", timeout=300):
            return False
    finally:
        src_utils.manage_resolv_conf("end_backup")

    return True






def install_proxychains():
    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}Installing ProxyChains...{src_utils.RESET}".center(40))
    print("\n")

    src_remover.fix_apt_issues()


    prereq_cmd = "sudo apt install -y tar build-essential git automake autoconf libtool libproxychains4"

    src_utils.manage_resolv_conf("start_backup")
    try:
        if not src_utils.run_apt_command(prereq_cmd, timeout=300):
            return False
    finally:
        src_utils.manage_resolv_conf("end_backup")


    try:

        with tempfile.NamedTemporaryFile(suffix=".tar.xz", delete=False) as tmp_file:
            tarball_path = tmp_file.name


        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as log_file:
            wget_log_path = log_file.name

        download_url = "https://github.com/kalilovers/proxychains-ng/releases/download/v4.17/proxychains-ng-4.17.tar.xz"
        if not src_utils.run_command(
            f"sudo wget --output-file={wget_log_path} {download_url} -O {tarball_path}",
            "Failed to download ProxyChains tarball."
        ):
            os.unlink(tarball_path)
            os.unlink(wget_log_path)
            return False

        if not src_utils.run_command(
            f"sudo tar -xf {tarball_path} -C /usr/local/src",
            "Failed to extract ProxyChains tarball into /usr/local/src."
        ):
            os.unlink(tarball_path)
            os.unlink(wget_log_path)
            return False


        os.unlink(tarball_path)
        os.unlink(wget_log_path)

    except Exception as e:
        src_utils.error(f"Exception during download/extraction: {e}", 
                    solution="Check network connectivity or file permissions")
        return False

    extracted_dir = "/usr/local/src/proxychains-ng-4.17"
    if not os.path.isdir(extracted_dir):
        src_utils.error("Extracted directory /usr/local/src/proxychains-ng-4.17 not found.", 
                    solution="Verify tarball extraction path")
        return False

    current_dir = os.getcwd()
    try:
        os.chdir(extracted_dir)
        build_cmd = "./configure --prefix=/usr --sysconfdir=/etc && make clean && make && sudo make install && sudo make install-config"
        if not src_utils.run_command(build_cmd, "Failed to build and install ProxyChains."):
            return False
    finally:
        os.chdir(current_dir)

    if not src_utils.run_command("sudo rm -f /usr/local/bin/proxyresolv", "Failed to remove existing proxyresolv file."):
        return False


    proxyresolv_url = "https://raw.githubusercontent.com/kalilovers/proxychains-ng/master/src/proxyresolv"
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as proxyresolv_log_file:
        proxyresolv_log_path = proxyresolv_log_file.name

        if not src_utils.run_command(
            f"sudo wget --output-file={proxyresolv_log_path} {proxyresolv_url} -O /usr/local/bin/proxyresolv",
            "Failed to download proxyresolv."
        ):
            os.unlink(proxyresolv_log_path)
            return False


        os.unlink(proxyresolv_log_path)

    if not src_utils.run_command("sudo chmod 750 /usr/local/bin/proxyresolv", "Failed to set executable permission on proxyresolv."):
        return False

    src_utils.success("ProxyChains installed successfully", 
                  details="Source: kalilovers/proxychains-ng v4.17")

    return True






def install_tor_from_repo():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}Trying to Install Tor From Tor'Repository...{src_utils.RESET}".center(40))
    print("\n")

    src_remover.fix_apt_issues()

    if not src_tor.check_tor_repo_access():
        src_utils.warning("Tor repository appears unreachable (possibly due to censorship)", 
                      solution="Check network connectivity or try later")
        return False


    try:
        arch = subprocess.check_output("dpkg --print-architecture", shell=True, text=True).strip()
        if arch == "armhf":
            src_utils.warning(f"Architecture '{arch}' not supported by official repository", 
                          solution="Use fallback installation method")
            return False
        if arch not in ["amd64", "arm64", "i386"]:
            src_utils.warning(f"Architecture '{arch}' not recognized for official repository installation", 
                          solution="Verify system architecture compatibility")
            return False
    except Exception as e:
        src_utils.error(f"Error checking architecture: {str(e)}", 
                    solution="Check 'dpkg --print-architecture' command output")
        return False


    if not src_utils.run_apt_command("sudo apt-get install -y apt-transport-https", timeout=300):
        src_utils.warning("Failed to install apt-transport-https. Falling back to default installation", 
                      solution="Check package availability")
        return False


    try:
        distro = subprocess.check_output("lsb_release -c -s", shell=True, text=True).strip()
    except Exception as e:
        src_utils.error(f"Error determining distribution codename: {str(e)}", 
                    solution="Verify 'lsb_release' command functionality")
        return False


    repo_content = f"""deb [arch={arch} signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org {distro} main
deb-src [arch={arch} signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org {distro} main
"""
    repo_file = "/etc/apt/sources.list.d/tor.list"
    try:
        with open(repo_file, "w") as f:
            f.write(repo_content)
        src_utils.success("Tor repository file created successfully", 
                      details=f"Path: {repo_file}")
    except Exception as e:
        src_utils.error(f"Error creating {repo_file}: {str(e)}", 
                    solution="Check write permissions and disk space")
        return False


    key_cmd = ("wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | "
               "gpg --dearmor | sudo tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null")
    if not src_utils.run_command(key_cmd, "Failed to add Tor Project GPG key"):
        src_utils.warning("GPG key addition failed. Falling back to default installation", 
                      solution="Verify network access to Tor keyserver")
        return False


    src_utils.info("Updating package lists from Tor repository...")

    src_utils.info("Installing Tor from the official repository...")
    if not src_utils.run_apt_command("sudo apt-get install -y tor tor-geoipdb nyx deb.torproject.org-keyring", timeout=300):
        src_utils.error("Tor installation failed from official repository", 
                    solution="Check package dependencies and repository access")
        return False

    src_tor.setup_tor_logrotate()

    src_utils.success("Tor installed successfully from official repository", 
                  details="Packages: tor, tor-geoipdb, nyx, deb.torproject.org-keyring")


    return True







def install_tor():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}Installing Tor...{src_utils.RESET}".center(40))
    print("\n")

    src_remover.fix_apt_issues()

    socks_ip, socks_port, dns_ip, dns_port = None, None, None, None
    exclude_ports = []


    while True:
        socks_ip_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter the Local IP for Tor Socks5{src_utils.RESET} (OR press Enter for a random available IP): ", default=None
        )
        if socks_ip_input:

            if src_utils.validate_ip(socks_ip_input, is_dns_port=True):
                socks_ip = socks_ip_input
                break
            else:
                src_utils.warning("Invalid IP. Please try again...")
        else:

            success, result = src_utils.get_random_ip()
            if success:
                socks_ip = result
                break
            else:
                src_utils.warning(f"Random IP generation failed: {result}. Please enter the IP manually.")


    while True:
        socks_port_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter the PORT for Tor Socks5{src_utils.RESET} (OR press Enter for a random available port): ", default=None
        )
        if socks_port_input:
            if src_utils.validate_socks_port(socks_ip, socks_port_input, exclude_ports):
                socks_port = int(socks_port_input)
                exclude_ports.append(socks_port)
                break
            else:
                src_utils.warning("Invalid Socks port. Please try again...")
        else:
            success, ip_returned, port, _ = src_utils.get_random_available_socks_port(ip=socks_ip, exclude_ports=exclude_ports)
            if success and port:
                socks_ip = ip_returned
                socks_port = port
                exclude_ports.append(socks_port)
                break
            else:
                src_utils.warning(f"No available SocksPort found: {port if port is None else ''}. Please specify the port manually.")


    while True:
        dns_ip_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter the Local IP for Tor DNS {src_utils.RESET}(OR press Enter for a random available IP): ", default=None
        )
        if dns_ip_input:
            if src_utils.validate_ip(dns_ip_input, is_dns_port=True):
                dns_ip = dns_ip_input
                break
            else:
                src_utils.warning("Invalid IP. Please try again...")
        else:
            success, result = src_utils.get_random_ip()
            if success:
                dns_ip = result
                break
            else:
                src_utils.warning(f"Random IP generation for DNS failed: {result}. Please enter the IP manually.")


    while True:
        dns_port_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter the PORT for Tor DNS {src_utils.RESET}(OR press Enter for a random available port): ", default=None
        )
        if dns_port_input:
            if src_utils.validate_dns_port(dns_ip, dns_port_input, exclude_ports):
                dns_port = int(dns_port_input)
                if dns_port == socks_port:
                    src_utils.warning("DNSPort cannot match SocksPort. Choose a different port.")
                else:
                    break
            else:
                src_utils.warning("Invalid DNS port. Please try again...")
        else:
            success, ip_returned, port, _ = src_utils.get_random_available_dns_port(ip=dns_ip, exclude_ports=exclude_ports)
            if success and port:
                if port == socks_port:
                    src_utils.warning("Randomly selected DNSPort matches SocksPort, retrying to find another port...")
                    continue
                dns_ip = ip_returned
                dns_port = port
                break
            else:
                src_utils.warning("No available DNSPort found. Please specify the port manually.")


    virtual_addr_candidates = ["10.192.0.0/10", "172.128.0.0/10", "100.64.0.0/10"]
    selected_virtual_addr = None
    for cidr in virtual_addr_candidates:
        if not src_utils.is_range_in_use(cidr):
            selected_virtual_addr = cidr
            break
    if selected_virtual_addr is None:
        src_utils.error("All standard VirtualAddrNetworkIPv4 ranges are in use", 
                     solution="Free up the ranges")
        return False


    if install_tor_from_repo():
        src_utils.success("Tor installed successfully from official repository", 
                       details="Using recommended repository configuration")
    else:
        src_utils.warning("Official repository installation failed\n")
        print(f"{src_utils.GREEN}Installing from default system repositories...{src_utils.RESET}\n")
        repo_file = "/etc/apt/sources.list.d/tor.list"
        if src_utils.file_exists(repo_file):
            os.remove(repo_file)
            src_utils.info("Removed failed repository configuration")

        if not src_utils.run_apt_command("sudo apt-get install -y tor tor-geoipdb nyx", timeout=300):
            src_utils.error("Tor installation failed via fallback method", 
                         solution="Check package availability and network connectivity")
            return False


    torrc_path = "/etc/tor/torrc"
    with open(torrc_path, "w") as torrc:
        torrc.write(f"SocksPort {socks_ip}:{socks_port}\n")
        torrc.write(f"DNSPort {dns_ip}:{dns_port}\n")
        torrc.write("RunAsDaemon 1\n")
        torrc.write("AutomapHostsOnResolve 1\n")
        torrc.write(f"VirtualAddrNetworkIPv4 {selected_virtual_addr}\n")
        torrc.write("Log notice file /var/log/tor/notice.log\n")

    src_tor.validate_and_clean_torrc(torrc_path)


    src_utils.run_command("sudo mkdir -p /var/log/tor", "Failed to create Tor log directory.")
    src_utils.run_command("sudo touch /var/log/tor/notice.log", "Failed to create Tor log file.")
    src_utils.run_command("sudo chown debian-tor:debian-tor /var/log/tor /var/log/tor/notice.log", 
                           "Failed to set ownership for Tor log file.")
    src_utils.run_command("sudo chmod 660 /var/log/tor/notice.log", "Failed to set permissions for Tor log file.")

    if not src_tor.restart_tor():
        src_utils.error("Tor service restart failed", solution="Check systemd service status")

    src_utils.run_command("sudo systemctl enable tor", "Failed to enable Tor service.")
    src_utils.run_command("sudo systemctl enable tor@default", "Failed to enable Tor@default service.")

    src_tor.setup_tor_logrotate()

    print("\n" + "─"*40)
    src_utils.success("Tor configuration written", 
                   details=f"VirtualAddrNetworkIPv4 set to: {selected_virtual_addr}")

    src_utils.success("Tor configured and enabled", 
                   details=f"Socks: {socks_ip}:{socks_port} | DNS: {dns_ip}:{dns_port}")


    return socks_ip, socks_port, dns_ip, dns_port




def install_psiphon():
    """
    Installs Psiphon with user-configurable parameters.

    Returns:
    --------
    bool
        True on successful installation, False on failure

    Example:
    --------
    >>> if install_psiphon():
    ...     print("Installation succeeded")
    ... else:
    ...     print("Installation failed")
    """
    src_utils.clear_screen()
    src_utils.info("Starting Psiphon installation...")

    if src_psiphon.is_psiphon_installed():
        src_utils.warning("Existing Psiphon installation detected")
        if src_utils.get_confirmation("Remove existing installation before proceeding? (y/n): "):
            if not src_remover.remove_psiphon():
                src_utils.warning("Failed to clean up existing installation. Continuing anyway...")
        else:
            src_utils.info("Installation cancelled by user.")
            return False


    architecture = src_psiphon.get_system_architecture()
    if not architecture:
        src_utils.error("Architecture check failed or unsupported architecture", solution="Only x86_64 is supported")
        return False
    if architecture != "x86_64":
        src_utils.error(f"Unsupported architecture: {architecture}", solution="Only x86_64 is supported")
        return False
    src_utils.success("System architecture verified: x86_64", newline=False)

    REGIONS = src_psiphon.REGIONS
    items_per_row = 5
    region_items = list(REGIONS.items())

    print("\n===============================================")

    src_utils.info("Optional : Location Configuration\n")

    for i in range(0, len(region_items), items_per_row):
        row = region_items[i:i+items_per_row]
        row_text = "   ".join([f"{key.rjust(2)}) {value.ljust(2)}" for key, value in row])
        print(f"{src_utils.GREEN}{row_text}{src_utils.RESET}")

    while True:
        final_server_choice = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Press Enter to 'auto' OR Select region {src_utils.RESET}\n[number in list OR Country'code]:",
            default=""
        ).strip().upper()

        if final_server_choice == "":
            EgressRegion = ""
            src_utils.success("Selected region: auto", newline=False)
            break
        elif final_server_choice in REGIONS:
            EgressRegion = REGIONS[final_server_choice]
            src_utils.success(f"Selected region: {EgressRegion}", newline=False)
            break
        elif len(final_server_choice) == 2 and final_server_choice.isalpha():
            EgressRegion = final_server_choice
            src_utils.success(f"Selected region: {EgressRegion} (custom)", newline=False)
            break
        else:
            src_utils.error("Invalid input! Please enter a number from the list or a valid 2-letter region code.")

    print("\n===============================================")

    socks_ip = "127.0.0.1"
    socks_port = None
    default_socks_port = 1081
    while True:
        port_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter SOCKS port{src_utils.RESET} [Press Enter/y to default: {default_socks_port}]: ",
            default=str(default_socks_port)
        )
        if port_input.lower() in ("", "y"):
            port_input = str(default_socks_port)
        
        if not port_input.isdigit():
            src_utils.warning("Invalid input. Please try again.", newline=False)
            continue
        
        port_input_int = int(port_input)
        if src_utils.is_port_in_use(socks_ip, port_input_int):
            src_utils.warning(f"Port {port_input_int} is already in use, please choose another port.", newline=False)
            continue
        
        socks_port = port_input_int
        break
    src_utils.success(f"Selected SOCKS port: {socks_port}", newline=False)

    http_ip = "127.0.0.1"
    http_port = None
    default_http_port = 8081

    while True:
        port_input = src_utils.get_user_input(
            f"\n{src_utils.YELLOW}Enter HTTP port{src_utils.RESET} [Press Enter/y to default: {default_http_port}]: ",
            default=str(default_http_port)
        )
        if port_input.lower() in ("", "y"):
            port_input = str(default_http_port)
        
        if not port_input.isdigit():
            src_utils.warning("Invalid input. Please try again.")
            continue
        
        port_input_int = int(port_input)
        if port_input_int == socks_port:
            src_utils.warning("HTTP port cannot be the same as SOCKS port. Please choose a different port.", newline=False)
            continue
        
        if src_utils.is_port_in_use(http_ip, port_input_int):
            src_utils.warning(f"Port {port_input_int} is already in use, please choose another port.", newline=False)
            continue
        
        http_port = port_input_int
        break
    src_utils.success(f"Selected HTTP port: {http_port}", newline=False)


    print("\n===============================================")

    default_server_url = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
    server_url = src_utils.get_user_input(
        f"\n{src_utils.YELLOW}Enter ServerList Url{src_utils.RESET} [Press Enter/y To default]: ",
        default=default_server_url
    )
    if server_url.lower() in ("", "y"):
        server_url = default_server_url
    src_utils.success(f"RemoteServerListUrl set to: \n{server_url}", newline=False)

    print("\n===============================================")

    PSIPHON_BINARY = src_psiphon.PSIPHON_BINARY
    PSIPHON_DOWNLOAD_URL_X86_64 = src_psiphon.PSIPHON_DOWNLOAD_URL_X86_64
    try:
        src_utils.info("Downloading Psiphon binary...")
        os.makedirs(os.path.dirname(PSIPHON_BINARY), exist_ok=True)

        download_result = src_utils.run_command(f"wget -O {PSIPHON_BINARY} {PSIPHON_DOWNLOAD_URL_X86_64}")
        if not download_result:
            src_utils.error("❌ Failed to download Psiphon binary")
            if os.path.exists(PSIPHON_BINARY):
                try:
                    os.remove(PSIPHON_BINARY)
                    src_remover.remove_psiphon()
                    src_utils.warning("⚠️ Downloaded file removed due to failure")
                except Exception as e:
                    src_utils.error(f"❌ Failed to remove partial download: {str(e)}")
            return False
        src_utils.success("Binary file downloaded successfully", newline=False)

        if not os.path.exists(PSIPHON_BINARY):
            src_utils.error("❌ Downloaded file not found")
            return False

        src_utils.run_command(f"chmod +x {PSIPHON_BINARY}")
        src_utils.success("Binary file made executable", newline=False)

        print("\n===============================================")

        if not src_psiphon.create_systemd_service():
            src_remover.remove_psiphon()
            return False

        if not src_psiphon.generate_psiphon_config(EgressRegion, socks_port, http_port, remote_server_list_url=server_url):
            src_remover.remove_psiphon()
            return False

        print("\n================================================")
        src_utils.info("Configuration Summary:")
        src_utils.success(f"- Server Location : {EgressRegion}", newline=False)
        src_utils.success(f"- SOCKS Port      : {socks_port}", newline=False)
        src_utils.success(f"- HTTP Port       : {http_port}", newline=False)
        src_utils.success(f"- ServerList Url  : \n{server_url}", newline=False)
        print("\n================================================\n")

        src_utils.success("🎉 Psiphon installed successfully!")
        return True

    except KeyboardInterrupt:
        src_utils.warning("User interrupted installation! Rolling back changes...",
                          solution="Installation aborted by user (Ctrl+C)")
        src_remover.remove_psiphon()
        src_utils.success("Cleanup completed", details="Aborted installation rolled back")
        return False