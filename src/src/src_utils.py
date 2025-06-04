#!/usr/bin/env python3

# -*- coding: utf-8 -*-




#src_ > >>>
#nothing

#modules >
import os
import subprocess
import shutil
import socket
import random
import time
import re
import json
from contextlib import contextmanager
import select
import ipaddress

##get_connection_status
import requests
from urllib.parse import urlparse




# -------------------- color --------------------


##----------General tools
HEADER     = '\033[95m'
BLUE       = '\033[94m'
CYAN       = '\033[96m'
GREEN      = '\033[92m'
YELLOW     = '\033[93m'
RED        = '\033[91m'
GRAY       = '\033[90m'
BOLD       = '\033[1m'
UNDERLINE  = '\033[4m'
RESET      = '\033[0m'

##----------General tools
BORDER_COLOR  = GREEN
HEADER_COLOR  = GREEN
ITEM_COLOR    = RESET
VERSION_COLOR = CYAN
EXIT_STYLE    = GREEN
ENTER_COLOR   = CYAN







# -------------------- Logger --------------------



##----------General tools
THEMES = {
    'success': {'color': '\033[92m', 'icon': '✅'},
    'info':    {'color': '\033[96m', 'icon': '💬'},
    'warning': {'color': '\033[93m', 'icon': '⚠️'},
    'error':   {'color': '\033[91m', 'icon': '❌'},
    'critical':{'color': '\033[91m', 'icon': '🔥'}
}


##----------General tools
def log(message, level='info', newline=True, **kwargs):
    theme = THEMES.get(level, THEMES['info'])
    icon = kwargs.get('icon', theme['icon'])
    color = kwargs.get('color', theme['color'])

    prefix = "\n" if newline else ""

    log_msg = (
        f"{prefix}{color}"# [{time.strftime('%H:%M:%S')}]
        f"{icon} {message}\033[0m"
    )

    if 'details' in kwargs:
        log_msg += f"\n  📝 {kwargs['details']}"
    if 'solution' in kwargs:
        log_msg += f"\n  🔧 {kwargs['solution']}"
    
    print(log_msg)


##----------General tools
def success(message, **kwargs):
    log(message, level='success', **kwargs)

##----------General tools
def info(message, **kwargs):
    log(message, level='info', **kwargs)

##----------General tools
def warning(message, **kwargs):
    log(message, level='warning', **kwargs)

##----------General tools
def error(message, **kwargs):
    log(message, level='error', **kwargs)








# -------------------- System Utilities --------------------







##----------General tools
def clear_screen():
    try:
        subprocess.run(["clear"], check=True)
    except subprocess.CalledProcessError:
        print("⚠️ Failed to clear screen")






##----------General tools
def is_installed(package):

    timeout_sec = 2


    if shutil.which(package):
        return True


    try:
        dpkg_check = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package],
            capture_output=True, text=True, timeout=timeout_sec
        )
        if "install ok installed" in dpkg_check.stdout:
            return True
    except subprocess.TimeoutExpired:
        pass


    try:
        apt_check = subprocess.run(
            ["apt-cache", "policy", package],
            capture_output=True, text=True, timeout=timeout_sec
        )
        installed_match = re.search(r"Installed: (.+)", apt_check.stdout)
        if installed_match and installed_match.group(1) != "(none)":
            return True
    except subprocess.TimeoutExpired:
        pass


    if package in ["tor"]:

        if shutil.which("systemctl"):
            try:
                service_check = subprocess.run(
                    ["systemctl", "is-active", "--quiet", package],
                    timeout=timeout_sec
                )
                if service_check.returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                pass

        elif shutil.which("service"):
            try:
                service_check = subprocess.run(
                    ["service", package, "status"],
                    capture_output=True, text=True, timeout=timeout_sec
                )
                if "active (running)" in service_check.stdout:
                    return True
            except subprocess.TimeoutExpired:
                pass

    return False





##----------General tools
def file_exists(file_path):
    return os.path.exists(file_path)




##----------General tools
def read_file(file_path):
    if not file_exists(file_path):
        return ""
    try:
        with open(file_path, "r") as file:
            return file.read()
    except PermissionError:
        print(f"Error: Permission denied to read {file_path}")
        return ""
    except Exception as e:
        print(f"Error reading {file_path}: {str(e)}")
        return ""



##----------General tools
def get_connection_status(proxy_ip="127.0.0.1", proxy_port=None, protocol="socks5h", timeout=5):
    """
    pip install requests[socks]

    import socket
    import requests
    import json
    from urllib.parse import urlparse
    """
    
    """
    Checks internet connectivity via a proxy and returns structured status with region/IP.

    Parameters:
        proxy_ip (str): Proxy IP address (default: 127.0.0.1)
        proxy_port (int): Proxy port number (required)
        protocol (str): Proxy protocol (socks4, socks5, socks5h, http, https)
        timeout (int): Connection timeout in seconds (default: 5)

    Returns:
        dict: {
            "status": "connected"|"disconnected"|"error",
            "service": str|None,          # Test service used
            "ip": str|None,               # External IP
            "region": str,                # Region code (e.g., FR)
            "protocol": str,              # Protocol used
            "message": str,               # Status message
            "error": str|None             # Error details (if any)
        }

    Example:
        >>> get_connection_status(proxy_port=1080, protocol="socks5h")
        {'status': 'connected', 'ip': '172.232.62.186', 'region': 'FR', ...}
    """
    if not proxy_port:
        return {
            "status": "error",
            "reason": "Missing proxy port",
            "message": "Proxy port is required"
        }


    valid_protocols = ["socks4", "socks5", "socks5h", "http", "https"]
    if protocol.lower() not in valid_protocols:
        return {
            "status": "error",
            "reason": "Invalid protocol",
            "message": f"Protocol must be one of {valid_protocols}"
        }


    test_services = [
        {
            "url": "https://ip-api.com/json/", 
            "name": "ip-api_com",
            "extract_region": lambda r: r.get("countryCode", "unknown").upper()
        },
        {
            "url": "https://ipapi.co/json/", 
            "name": "ipapi_co",
            "extract_region": lambda r: r.get("country", "unknown").upper()
        },
        {
            "url": "https://api.ipify.org?format=json",
            "name": "ipify",
            "extract_region": lambda _: "unknown"
        }
    ]


    healthy_services = []

    for service in test_services:
        try:
            parsed_url = urlparse(service["url"])
            socket.gethostbyname_ex(parsed_url.hostname)
            healthy_services.append(service)
        except (socket.gaierror, Exception):
            continue

    if not healthy_services:
        return {
            "status": "error",
            "reason": "No healthy test services",
            "message": "All external test services are unreachable"
        }


    proxies = {
        "http": f"{protocol}://{proxy_ip}:{proxy_port}",
        "https": f"{protocol}://{proxy_ip}:{proxy_port}"
    }


    result = {
        "status": "disconnected",
        "service": None,
        "ip": None,
        "region": "unknown",
        "protocol": protocol,
        "message": "Connection failed"
    }

    for service in healthy_services:
        try:
            headers = {"User-Agent": "Psiphon-Connection-Checker"}
            response = requests.get(service["url"], proxies=proxies, timeout=timeout, headers=headers)
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    ip = json_response.get("query") or json_response.get("ip") or "unknown"
                    region = service["extract_region"](json_response)
                    result.update({
                        "status": "connected",
                        "service": service["name"],
                        "ip": ip,
                        "region": region,
                        "protocol": protocol,
                        "message": "Successfully connected through proxy"
                    })
                    break
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            result["error"] = str(e)
            continue

    return result






##----------General tools
def run_command(command, error_message="An error occurred", shell=True):
    try:
        result = subprocess.run(
            command,
            shell=shell,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.stdout:
            print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        err_output = e.stderr.strip() if e.stderr else ""
        
        ignorable_errors = [
            "resolvconf",
            "dpkg --configure",
            "--force-help",
            "apt does not have a stable CLI interface"
        ]
        
        if any(err in err_output for err in ignorable_errors):
            print(f"⚠️ Ignored non-critical error: {err_output}")
            return True
        
        print(f"{error_message}: {err_output}")
        return False





##----------General tools
def run_apt_command(command, timeout=600):

    print(f"Executing: {command}")

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    start_time = time.time()
    last_output_time = start_time
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    poll_interval = 1.0



    while process.poll() is None:

        ready, _, _ = select.select([stdout_fd, stderr_fd], [], [], poll_interval)
        if ready:
            for fd in ready:
                if fd == stdout_fd:
                    line = process.stdout.readline()
                    if line:
                        print(line.strip())
                        last_output_time = time.time()
                elif fd == stderr_fd:
                    err_line = process.stderr.readline()
                    if err_line:
                        print(err_line.strip())
                        last_output_time = time.time()
        else:

            time.sleep(poll_interval)
        

        if time.time() - last_output_time > 300:
            print("❌ No activity detected for 5 minutes. Killing process.")
            process.kill()
            return False


        if time.time() - start_time > timeout:
            print("❌ Command took too long. Killing process.")
            process.kill()
            return False

    return process.returncode == 0





##----------General tools
def run_apt_update(cmd, timeout=300):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False

    output = proc.stdout + proc.stderr

    if "Temporary failure resolving" in output or "Could not resolve" in output:
        return False


    if "Hit:" in output or "Get:" in output:
        return True


    return False








def manage_resolv_conf(action):
    RESOLV_CONF = "/etc/resolv.conf"

    BACKUP_NAME_PATH = "/tmp/resolv_conf_backup_filename.txt"
    
    if action == "start_backup":

        if not os.path.exists(RESOLV_CONF):
            print(f"{RESOLV_CONF} does not exist. Skipping start_backup.")
            return
        

        unique_backup = f"/tmp/resolv_conf_backup_{int(time.time())}_{os.getpid()}.json"
        
        backup_info = {}
        if os.path.islink(RESOLV_CONF):
            backup_info["is_symlink"] = True
            backup_info["symlink_target"] = os.readlink(RESOLV_CONF)
            backup_info["immutable"] = False
        else:
            backup_info["is_symlink"] = False
            try:
                lsattr_output = subprocess.check_output(["lsattr", RESOLV_CONF]).decode()
                attrs = lsattr_output.split()[0]
                backup_info["immutable"] = "i" in attrs
            except Exception:
                backup_info["immutable"] = False
            with open(RESOLV_CONF, "r") as f:
                backup_info["content"] = f.read()
        

        with open(unique_backup, "w") as f:
            json.dump(backup_info, f)
        

        with open(BACKUP_NAME_PATH, "w") as f:
            f.write(unique_backup)
        

        if backup_info.get("immutable", False):
            subprocess.call(["sudo", "chattr", "-i", RESOLV_CONF])
        
        os.remove(RESOLV_CONF)
        

        new_content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        with open(RESOLV_CONF, "w") as f:
            f.write(new_content)
        os.chmod(RESOLV_CONF, 0o644)
        print("\nBackup taken and new /etc/resolv.conf created.\n")
    
    elif action == "end_backup":

        if not os.path.exists(BACKUP_NAME_PATH):
            print("No backup information found. Skipping end_backup.")
            return
        
        with open(BACKUP_NAME_PATH, "r") as f:
            unique_backup = f.read().strip()
        
        if not os.path.exists(unique_backup):
            print("Backup file not found. Skipping end_backup.")
            os.remove(BACKUP_NAME_PATH)
            return
        
        try:
            with open(unique_backup, "r") as f:
                backup_info = json.load(f)
            
            if os.path.exists(RESOLV_CONF):
                os.remove(RESOLV_CONF)
            
            if backup_info.get("is_symlink", False):
                target = backup_info.get("symlink_target", "")
                os.symlink(target, RESOLV_CONF)
            else:
                content = backup_info.get("content", "")
                with open(RESOLV_CONF, "w") as f:
                    f.write(content)
                os.chmod(RESOLV_CONF, 0o644)
            
            if backup_info.get("immutable", False):
                subprocess.call(["sudo", "chattr", "+i", RESOLV_CONF])
            
            os.remove(unique_backup)
            os.remove(BACKUP_NAME_PATH)
            print("\nOriginal /etc/resolv.conf has been restored.\n")
        except Exception as e:
            print(f"Error during end_backup: {e}")
            if os.path.exists(BACKUP_NAME_PATH):
                os.remove(BACKUP_NAME_PATH)
    else:
        print("Invalid action. Use 'start_backup' or 'end_backup'.")




# -------------------- Network Utilities --------------------






##----------General tools
@contextmanager
def temporary_dns():

    resolv_conf_path = "/etc/resolv.conf"
    state = {
        "original_lines": [],
        "was_read_only": False,
        "created_temp_file": False,
        "temp_dns_applied": False,
        "success": None
    }
    
    def can_connect(domain):

        return subprocess.run(
            f'timeout 3 bash -c "exec 3<>/dev/tcp/{domain}/80"', 
            shell=True
        ).returncode == 0


    if can_connect("google.com") or can_connect("cloudflare.com"):
        print("✅ General internet connection is fine.")


    if can_connect("archive.ubuntu.com") or can_connect("deb.debian.org"):
        print("✅ Connection to repositories is working fine.")
        state["success"] = True

        try:
            yield state["success"]
        finally:

            pass
        return

    print("⚠️ Unable to connect to repositories! Possible DNS issue detected. Temporarily changing DNS settings...")


    if os.path.exists(resolv_conf_path):
        if not os.access(resolv_conf_path, os.W_OK):
            os.system(f"sudo chmod +w {resolv_conf_path}")
            state["was_read_only"] = True
        with open(resolv_conf_path, "r") as file:
            state["original_lines"] = file.readlines()
    else:
        print("⚠️ /etc/resolv.conf not found! Creating a temporary one.")
        state["original_lines"] = []
        state["created_temp_file"] = True


    if len(state["original_lines"]) == 0:
        new_resolv_conf = ["nameserver 8.8.8.8\n", "nameserver 1.1.1.1\n"]
    else:
        new_resolv_conf = [f"#-- {line}" if "nameserver" in line else line for line in state["original_lines"]]
        new_resolv_conf += ["nameserver 8.8.8.8\n", "nameserver 1.1.1.1\n"]
    with open(resolv_conf_path, "w") as file:
        file.writelines(new_resolv_conf)
    time.sleep(2)
    state["temp_dns_applied"] = True


    if can_connect("archive.ubuntu.com") or can_connect("deb.debian.org"):
        print("✅ Connection restored successfully!")
        state["success"] = True
    else:
        print("❌ Even after changing DNS, the repositories are still unreachable.")
        state["success"] = False

    try:
        yield state["success"]
    finally:
        print("🔄 Restoring original DNS settings...")
        with open(resolv_conf_path, "w") as file:
            file.writelines(state["original_lines"])
        if state["was_read_only"]:
            os.system(f"sudo chmod -w {resolv_conf_path}")
        if state["created_temp_file"]:
            os.remove(resolv_conf_path)
        print("✅ DNS settings restored.")









##----------General tools
def is_port_in_use(ip, port):
    tcp_in_use = False
    udp_in_use = False


    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
            tcp_sock.settimeout(1)
            if tcp_sock.connect_ex((ip, port)) == 0:
                tcp_in_use = True
    except Exception as e:
        print(f"TCP check error: {e}")


    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
            udp_sock.settimeout(1)

            udp_sock.bind((ip, port))
    except OSError:
        udp_in_use = True
    except Exception as e:
        print(f"UDP check error: {e}")

    return tcp_in_use or udp_in_use







def ensure_iproute2():

    try:
        result = subprocess.run("dpkg -s iproute2", shell=True, capture_output=True, text=True)
        if "Status: install ok installed" in result.stdout:
            return True

        print("⚠️ 'iproute2' package is not installed. Installing now...")
        if not run_apt_command("sudo apt-get install -y iproute2", timeout=300):
            print("❌ Failed to install iproute2. Cannot proceed with network range check.")
            return False
        return True
    except Exception as e:
        print(f"❌ Unexpected error while checking iproute2: {e}")
        return False




##----------General tools
def is_range_in_use(cidr):

    if not ensure_iproute2():
        return False

    result = subprocess.run(f"ip route | grep '{cidr.split('/')[0]}'", shell=True, capture_output=True, text=True)
    return result.returncode == 0




##----------General tools
def get_random_ip(max_attempts=20):

    reserved_ips = {"127.0.0.1", "127.0.0.53"}
    for _ in range(max_attempts):

        ip_int = random.randint(0x7F000001, 0x7FFFFFEF)
        ip = str(ipaddress.IPv4Address(ip_int))
        if ip not in reserved_ips:
            return (True, ip)
    return (False, "Failed to generate IP after 20 attempts")






def get_random_available_socks_port(ip=None, exclude_ports=None):
    if ip is None:
        success, ip = get_random_ip()
        if not success:
            return (False, "IP generation failed", None, None)
            
    for _ in range(20):
        port = random.randint(1050, 9050)
        if (str(port)[-2:] != "53" and 
            (exclude_ports is None or port not in exclude_ports) and 
            not is_port_in_use(ip, port)):
            return (True, ip, port, None)
    return (False, "No available port", ip, None)





def get_random_available_dns_port(ip=None, exclude_ports=None):
    if ip is None:
        success, ip = get_random_ip()
        if not success:
            return (False, "IP generation failed", None, None)
            
    for _ in range(20):
        port = random.randint(1053, 9053)
        if ((exclude_ports is None or port not in exclude_ports) and 
            not is_port_in_use(ip, port)):
            return (True, ip, port, None)
    return (False, "No available port", ip, None)



# -------------------- Input Utilities --------------------





##----------General tools
def get_user_input(prompt, default=None, validator=None, exclude_values=None):
    while True:
        user_input = input(prompt).strip()
        if not user_input and default is not None:
            return default
        if validator:
            if validator(user_input, exclude_values):
                return user_input
        else:
            return user_input
        print("Invalid input. Please try again.")





##----------General tools
def get_confirmation(prompt, default=True, language="en"):

    yes_variants = {
        "en": ["y", "yes"],
        "fa": ["بله", "آره", "بلی", "غ"],
        "fr": ["oui", "o"]
    }
    no_variants = {
        "en": ["n", "no"],
        "fa": ["نه", "خیر", "د"],
        "fr": ["non"]
    }

    yes_options = yes_variants.get(language, yes_variants["en"])
    no_options = no_variants.get(language, no_variants["en"])

    while True:
        choice = input(prompt).strip().lower()

        if choice == "":
            return default

        if choice in yes_options:
            return True
        elif choice in no_options:
            return False
        else:
            print("❌ Invalid input. Please enter a valid response.")






# -------------------- Validator --------------------




##----------General tools
def prompt_for_ip(prompt):
    ip = input(prompt).strip()
    try:

        socket.inet_aton(ip)
        parts = ip.split('.')
        if len(parts) != 4 or any(not part.isdigit() or not 0 <= int(part) <= 255 for part in parts):
             
            raise ValueError
        return ip
    except (socket.error, ValueError):
        error(f"Invalid IP address: {ip}", 
                     solution="Enter valid IPv4 address (e.g., 127.0.0.1 or 8.8.8.8)", 
                     details="Format: xxx.xxx.xxx.xxx (0-255 for each octet)")
        return None




##----------General tools
def prompt_for_port(prompt):
    reserved_ports = {22, 80, 443, 9001}
    port_str = input(prompt).strip()
    if not port_str.isdigit():
        error("Non-numeric port input detected", 
                     solution="Enter a number between 1-65535")
        return None
    port = int(port_str)
    if 1 <= port <= 65535 and port not in reserved_ports:
        return port
    else:
        reserved_ports_str = ", ".join(map(str, sorted(reserved_ports)))
        error(f"Port '{port}' is invalid", 
                     solution=f"Choose port between 1-65535 excluding: {reserved_ports_str}")
                                                                             
        return None





def validate_ip(ip, is_dns_port=False):

    ip_pattern = re.compile(
        r"^127\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
        r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
        r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
    )
    if not ip_pattern.match(ip):
        error(f"Invalid IP address: {ip}", 
                     solution="Must be in 127.x.x.x range (e.g., 127.0.0.2)", 
                     details="First octet must be exactly 127")
        return False
    
    if is_dns_port and ip in ["127.0.0.1", "127.0.0.53"]:
        error(f"Reserved DNS IP detected: '{ip}'", 
                     solution="Use different local IP (e.g., 127.0.0.2)", 
                     details="127.0.0.1 and 127.0.0.53 are system-reserved")
        return False

    return True






def validate_socks_port(ip, port, exclude_ports=None):
    try:
        port_number = int(port)

        if not (1050 <= port_number <= 9050):
            error(f"Port '{port_number}' out of range", 
                         solution="Must be between 1050-9050", 
                         details="Tor SocksPort requires this range for security")
            return False

        if port_number % 100 == 53:
            error(f"Port '{port_number}' ends with 53", 
                         solution="Avoid ports ending with 53 to prevent DNS conflicts", 
                         details="This helps avoid port number misunderstandings")
            return False

        if exclude_ports and port_number in exclude_ports:
            error(f"Port '{port_number}' already excluded", 
                         solution="Choose another port outside exclusion list", 
                         details=f"Excluded ports: {exclude_ports}")
            return False

        if is_port_in_use(ip, port_number):
            error(f"Port '{port_number}' is in use for IP '{ip}'", 
                         solution="Select an available port", 
                         details=f"Port check failed for {ip}:{port_number}")
            return False
        return True
    except ValueError:
        error(f"Invalid port format: {port}", 
                     solution="Enter numeric value (e.g., 9050)", 
                     details="Port must be integer string")
        return False





def validate_dns_port(ip, port, exclude_ports=None):
    try:
        port_number = int(port)

        if not (1053 <= port_number <= 9053):
            error(f"Port '{port_number}' out of range", 
                         solution="Must be between 1053-9053", 
                         details="Tor DNSPort requires this range for security")
            return False

        if exclude_ports and port_number in exclude_ports:
            error(f"Port '{port_number}' already excluded", 
                         solution="Choose another port outside exclusion list", 
                         details=f"Excluded ports: {exclude_ports}")
            return False

        if is_port_in_use(ip, port_number):
            error(f"Port '{port_number}' is in use for IP '{ip}'", 
                         solution="Select an available port", 
                         details=f"Port check failed for {ip}:{port_number}")
            return False
        return True
    except ValueError:
        error(f"Invalid port format: {port}", 
                     solution="Enter numeric value (e.g., 5353)", 
                     details="Port must be integer string")
        return False

