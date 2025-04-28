#!/usr/bin/env python3

# -*- coding: utf-8 -*-


#src_ > >>>
from src import src_tor
from src import src_remover
from src import src_utils

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

    if not src_utils.run_apt_command("sudo apt-get install -y dante-client", timeout=300):
        src_utils.manage_resolv_conf("end_backup")
        return False

    src_utils.manage_resolv_conf("end_backup")

    return True





def install_proxychains():
    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}Installing ProxyChains...{src_utils.RESET}".center(40))
    print("\n")

    src_remover.fix_apt_issues()

    prereq_cmd = "sudo apt install -y tar build-essential git automake autoconf libtool libproxychains4"
    if not src_utils.run_apt_command(prereq_cmd, timeout=300):
        return False

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