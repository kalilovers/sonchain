#!/usr/bin/env python3

# -*- coding: utf-8 -*-


############################################# Bugs:







"""
Copyright (c) 2025 Kalilovers (https://github.com/kalilovers)

This file is part of [Sonchain]. It is licensed under the MIT License.
You may not remove or alter the above copyright notice.
Any modifications or redistributions must retain the original author's credit.
For more details, please refer to the LICENSE file in the project root.
"""







import os
import subprocess
import sys
import time
import re
import random
import socket
import shutil
import uuid
import tempfile
import ipaddress
from contextlib import contextmanager
import select
import threading




# -------------------- color --------------------
class color:


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
    

    BORDER_COLOR  = GREEN
    HEADER_COLOR  = GREEN
    ITEM_COLOR    = RESET
    VERSION_COLOR = CYAN
    EXIT_STYLE    = GREEN
    ENTER_COLOR   = CYAN







# -------------------- Logger --------------------
class Logger:




    THEMES = {
        'success': {'color': '\033[92m', 'icon': '✅'},
        'info':    {'color': '\033[96m', 'icon': '💬'},
        'warning': {'color': '\033[93m', 'icon': '⚠️'},
        'error':   {'color': '\033[91m', 'icon': '❌'},
        'critical':{'color': '\033[91m', 'icon': '🔥'}
    }






    @staticmethod
    def log(message, level='info', **kwargs):
        theme = Logger.THEMES.get(level, Logger.THEMES['info'])
        icon = kwargs.get('icon', theme['icon'])
        color = kwargs.get('color', theme['color'])
        

        log_msg = (
            f"\n{color}[{time.strftime('%H:%M:%S')}] "
            f"{icon} {message}\033[0m"
        )
        

        if 'details' in kwargs:
            log_msg += f"\n  📝 {kwargs['details']}"
        if 'solution' in kwargs:
            log_msg += f"\n  🔧 {kwargs['solution']}"
        
        print(log_msg)


    @staticmethod
    def success(message, **kwargs):
        Logger.log(message, level='success', **kwargs)
    
    @staticmethod
    def info(message, **kwargs):
        Logger.log(message, level='info', **kwargs)
    
    @staticmethod
    def warning(message, **kwargs):
        Logger.log(message, level='warning', **kwargs)
    
    @staticmethod
    def error(message, **kwargs):
        Logger.log(message, level='error', **kwargs)








# -------------------- System Utilities --------------------
class SystemUtils:
    





    @staticmethod
    def clear_screen():
        try:
            subprocess.run(["clear"], check=True)
        except subprocess.CalledProcessError:
            print("⚠️ Failed to clear screen")






    @staticmethod
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





    @staticmethod
    def file_exists(file_path):
        return os.path.exists(file_path)




    @staticmethod
    def read_file(file_path):
        if not SystemUtils.file_exists(file_path):
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






    
    @staticmethod
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
            print(f"{error_message}: {err_output}")
            return False




    @staticmethod
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



# -------------------- Network Utilities --------------------
class NetworkUtils:





    @staticmethod
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









    @staticmethod
    def is_port_in_use(ip, port):
        tcp_in_use = False
        udp_in_use = False

        # بررسی وضعیت TCP
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






    @staticmethod
    def ensure_iproute2():

        try:
            result = subprocess.run("dpkg -s iproute2", shell=True, capture_output=True, text=True)
            if "Status: install ok installed" in result.stdout:
                return True  # بسته نصب شده است

            print("⚠️ 'iproute2' package is not installed. Installing now...")
            if not SystemUtils.run_apt_command("sudo apt-get install -y iproute2", timeout=300):
                print("❌ Failed to install iproute2. Cannot proceed with network range check.")
                return False
            return True
        except Exception as e:
            print(f"❌ Unexpected error while checking iproute2: {e}")
            return False




    @staticmethod
    def is_range_in_use(cidr):

        if not NetworkUtils.ensure_iproute2():
            return False

        result = subprocess.run(f"ip route | grep '{cidr.split('/')[0]}'", shell=True, capture_output=True, text=True)
        return result.returncode == 0





    def get_random_ip(max_attempts=20):

        reserved_ips = {"127.0.0.1", "127.0.0.53"}
        for _ in range(max_attempts):

            ip_int = random.randint(0x7F000001, 0x7FFFFFEF)
            ip = str(ipaddress.IPv4Address(ip_int))
            if ip not in reserved_ips:
                return (True, ip)
        return (False, "Failed to generate IP after 20 attempts")





    @staticmethod
    def get_random_available_socks_port(ip=None, exclude_ports=None):
        if ip is None:
            success, ip = NetworkUtils.get_random_ip()
            if not success:
                return (False, "IP generation failed", None, None)
                
        for _ in range(20):
            port = random.randint(1050, 9050)
            if (str(port)[-2:] != "53" and 
                (exclude_ports is None or port not in exclude_ports) and 
                not NetworkUtils.is_port_in_use(ip, port)):
                return (True, ip, port, None)
        return (False, "No available port", ip, None)




    @staticmethod
    def get_random_available_dns_port(ip=None, exclude_ports=None):
        if ip is None:
            success, ip = NetworkUtils.get_random_ip()
            if not success:
                return (False, "IP generation failed", None, None)
                
        for _ in range(20):
            port = random.randint(1053, 9053)
            if ((exclude_ports is None or port not in exclude_ports) and 
                not NetworkUtils.is_port_in_use(ip, port)):
                return (True, ip, port, None)
        return (False, "No available port", ip, None)



# -------------------- Input Utilities --------------------
class InputUtils:




    @staticmethod
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





    @staticmethod
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
class Validator:



    @staticmethod
    def prompt_for_ip(prompt):
        ip = input(prompt).strip()
        try:

            socket.inet_aton(ip)
            parts = ip.split('.')
            if len(parts) != 4 or any(not part.isdigit() or not 0 <= int(part) <= 255 for part in parts):
                 
                raise ValueError
            return ip
        except (socket.error, ValueError):
            Logger.error(f"Invalid IP address: {ip}", 
                         solution="Enter valid IPv4 address (e.g., 127.0.0.1 or 8.8.8.8)", 
                         details="Format: xxx.xxx.xxx.xxx (0-255 for each octet)")
            return None




    @staticmethod
    def prompt_for_port(prompt):
        reserved_ports = {22, 80, 443, 9001}
        port_str = input(prompt).strip()
        if not port_str.isdigit():
            Logger.error("Non-numeric port input detected", 
                         solution="Enter a number between 1-65535")
            return None
        port = int(port_str)
        if 1 <= port <= 65535 and port not in reserved_ports:
            return port
        else:
            reserved_ports_str = ", ".join(map(str, sorted(reserved_ports)))
            Logger.error(f"Port '{port}' is invalid", 
                         solution=f"Choose port between 1-65535 excluding: {reserved_ports_str}")
                                                                                 
            return None




    @staticmethod
    def validate_ip(ip, is_dns_port=False):

        ip_pattern = re.compile(
            r"^127\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
            r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
            r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
        )
        if not ip_pattern.match(ip):
            Logger.error(f"Invalid IP address: {ip}", 
                         solution="Must be in 127.x.x.x range (e.g., 127.0.0.2)", 
                         details="First octet must be exactly 127")
            return False
        
        if is_dns_port and ip in ["127.0.0.1", "127.0.0.53"]:
            Logger.error(f"Reserved DNS IP detected: '{ip}'", 
                         solution="Use different local IP (e.g., 127.0.0.2)", 
                         details="127.0.0.1 and 127.0.0.53 are system-reserved")
            return False

        return True





    @staticmethod
    def validate_socks_port(ip, port, exclude_ports=None):
        try:
            port_number = int(port)

            if not (1050 <= port_number <= 9050):
                Logger.error(f"Port '{port_number}' out of range", 
                             solution="Must be between 1050-9050", 
                             details="Tor SocksPort requires this range for security")
                return False

            if port_number % 100 == 53:
                Logger.error(f"Port '{port_number}' ends with 53", 
                             solution="Avoid ports ending with 53 to prevent DNS conflicts", 
                             details="This helps avoid port number misunderstandings")
                return False

            if exclude_ports and port_number in exclude_ports:
                Logger.error(f"Port '{port_number}' already excluded", 
                             solution="Choose another port outside exclusion list", 
                             details=f"Excluded ports: {exclude_ports}")
                return False

            if NetworkUtils.is_port_in_use(ip, port_number):
                Logger.error(f"Port '{port_number}' is in use for IP '{ip}'", 
                             solution="Select an available port", 
                             details=f"Port check failed for {ip}:{port_number}")
                return False
            return True
        except ValueError:
            Logger.error(f"Invalid port format: {port}", 
                         solution="Enter numeric value (e.g., 9050)", 
                         details="Port must be integer string")
            return False




    @staticmethod
    def validate_dns_port(ip, port, exclude_ports=None):
        try:
            port_number = int(port)

            if not (1053 <= port_number <= 9053):
                Logger.error(f"Port '{port_number}' out of range", 
                             solution="Must be between 1053-9053", 
                             details="Tor DNSPort requires this range for security")
                return False

            if exclude_ports and port_number in exclude_ports:
                Logger.error(f"Port '{port_number}' already excluded", 
                             solution="Choose another port outside exclusion list", 
                             details=f"Excluded ports: {exclude_ports}")
                return False

            if NetworkUtils.is_port_in_use(ip, port_number):
                Logger.error(f"Port '{port_number}' is in use for IP '{ip}'", 
                             solution="Select an available port", 
                             details=f"Port check failed for {ip}:{port_number}")
                return False
            return True
        except ValueError:
            Logger.error(f"Invalid port format: {port}", 
                         solution="Enter numeric value (e.g., 5353)", 
                         details="Port must be integer string")
            return False







# -------------------- Remover --------------------
class Remover:




    @staticmethod
    def fix_apt_issues():

        Logger.info("Checking APT Issues | Preparing system...")


        SystemUtils.run_command("sudo pkill -SIGTERM -f 'apt|dpkg'", "Terminating APT/DPKG processes")
        time.sleep(2)


        SystemUtils.run_command("sudo pkill -SIGKILL -f 'apt|dpkg'", "Forcibly terminating APT/DPKG processes")


        locks = [
            "/var/lib/apt/lists/lock",
            "/var/lib/dpkg/lock",
            "/var/lib/dpkg/lock-frontend",
            "/var/cache/apt/archives/lock"
        ]

        for lock in locks:
            if SystemUtils.file_exists(lock):
                SystemUtils.run_command(f"sudo rm -f {lock}", f"Removing lock file {lock}")


        SystemUtils.run_command("sudo dpkg --configure -a", "Fixing broken packages")







    @staticmethod
    def execute_step(cmd, desc, critical=False):

        Logger.info(f"{desc}...", end="", flush=True)
        result = SystemUtils.run_command(cmd, "")
        if result:
            Logger.success("Done")
        else:
            Logger.warning("Warning") if not critical else Logger.error("Failed")
        return not critical or result







    @staticmethod
    def uninstall_script():

        try:

            paths = [
                "/opt/sonchain",
                "/usr/local/bin/sonchain",
                "/etc/sonchain",
                "/var/log/sonchain.log"
            ]
            
            print("\n" + "="*40)
            print("⚠️CAUTION: FULL UNINSTALL⚠️".center(40))
            print("="*40)
            

            existing = [p for p in paths if os.path.exists(p)]
            if not existing:
                print("ℹ️ No installation found!")
                return True
                
            for p in existing:
                print(f"• {p}")
            

            confirm = input("\nDelete ALL? (y/N): ").strip().lower()
            if confirm != 'y':
                print("🚫 Cancelled!")
                return False
            

            for path in existing:
                try:
                    if os.path.islink(path):
                        os.unlink(path)
                    elif os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                    print(f"✓ {path}")
                except Exception as e:
                    print(f"✗ {path} - {str(e)}")
                    sys.exit(1)
            
            Logger.success("Successfully removed!", details="Re Install :")
            print("\nbash <(curl -fsSL https://raw.githubusercontent.com/kalilovers/sonchain/main/install.sh)")
            return True
            
        except Exception as e:
            Logger.warning(f"Error: {str(e)}")
            sys.exit(1)







    @staticmethod
    def remove_proxychains():

        print("\n" + "─"*40)
        print("🗑️ REMOVING PROXYCHAINS".center(40))
        print("─"*40)
        
        Remover.fix_apt_issues()
        
        success = True
        success &= Remover.execute_step(
            "sudo apt autoremove --purge -y proxychains4 proxychains-ng proxychains libproxychains4",
            " Removing packages",
            critical=True
        )
        
        cleanup_steps = [
            ("sudo rm -rf /etc/proxychains* /etc/proxychains.conf", "Cleaning configs"),
            ("sudo rm -rf /usr/local/bin/proxyresolv /usr/local/bin/proxychains*", "Removing binaries"),
            ("sudo rm -rf /usr/local/src/proxychains-ng-4.17 /root/proxychains-ng-4.17.tar.xz /etc/proxychains-ng-4.17.tar.xz /etc/proxychains4 /etc/proxychains /usr/local/bin/proxychains /usr/local/bin/proxychains4 /usr/local/bin/proxychains.conf /usr/local/bin/proxychains4.conf /usr/local/bin/proxychains4-daemon /usr/local/etc/proxychains /usr/local/etc/proxychains4 /usr/local/etc/proxychains4.conf /usr/local/etc/proxychains4-daemon /usr/bin/proxychains4-daemon /usr/bin/proxychains4 /usr/bin/proxychains /root/proxychains-ng-4.17", "Cleaning sources")
        ]
        
        for cmd, desc in cleanup_steps:
            success &= Remover.execute_step(cmd, desc)

        if success:
            Logger.success("Complete", details="ProxyChains removal successful")
        else:
            Logger.warning("Partial Success", details="Some cleanup steps failed")
        
        print("\n" + "─"*40)

        return success






    @staticmethod
    def remove_tor():

        print("\n" + "─"*40)
        print("🗑️ REMOVING TOR".center(40))
        print("─"*40)
        
        Remover.fix_apt_issues()
        
        success = True
        Remover.execute_step(
            "sudo systemctl stop tor tor@default && killall tor || true",
            "Stopping services"
        )
        
        success &= Remover.execute_step(
            "sudo apt autoremove --purge -y tor tor-geoipdb nyx",
            "Removing packages",
            critical=True
        )
        
        cleanup_steps = [
            ("sudo rm -rf /etc/tor /var/lib/tor /var/log/tor", "Cleaning files"),
            ("sudo rm -rf ~/.torrc ~/.config/tor", "User data"),
            # حذف تنظیمات logrotate مربوط به تور
            ("sudo rm -rf /etc/logrotate.d/tor", "Removing Tor logrotate configuration"),
            ("sudo systemctl stop logrotate-tor.timer", "Stopping Tor logrotate timer"),
            ("sudo systemctl disable logrotate-tor.timer", "Disabling Tor logrotate timer"),
            ("sudo rm -rf /etc/systemd/system/logrotate-tor.timer", "Removing Tor logrotate timer file"),
            ("sudo rm -rf /etc/systemd/system/logrotate-tor.service", "Removing Tor logrotate service file"),
            ("sudo systemctl daemon-reload", "Reloading systemd daemon")
        ]
        
        for cmd, desc in cleanup_steps:
            success &= Remover.execute_step(cmd, desc)

        if success:
            Logger.success("Complete", details="Tor removal successful")
        else:
            Logger.warning("Partial Success", details="Tor cleanup incomplete")
        
        print("\n" + "─"*40)

        return success






    @staticmethod
    def remove_dante():
        print("\n" + "─"*40)
        print("🗑️ REMOVING DANTE".center(40))
        print("─"*40)
        
        Remover.fix_apt_issues()
        
        success = True
        success &= Remover.execute_step(
            "sudo apt autoremove --purge -y dante-client",
            "Removing package",
            critical=True
        )
        
        cleanup_steps = [
            ("sudo rm -rf /etc/socks.conf /var/log/dante", "Cleaning Dante configs and logs"),
            ("sudo rm -rf /usr/bin/socksify /usr/local/etc/socks.conf /usr/local/bin/socksify", "Removing Dante binaries and extras"),
            ("sed -i '/SOCKS_CONF=/d' ~/.bashrc", "Updating bashrc"),
            ("sed -i '/SOCKS_CONF=/d' /etc/environment", "Updating global environment"),
            ("bash -c 'source ~/.bashrc'", "Applying environment changes."),
            ("unset SOCKS_CONF", "Removing SOCKS_CONF from current session"),
            ("set -a; source /etc/environment; set +a", "Applying system-wide changes"),
            ("source ~/.bashrc", "2nd Applying changes :0 "),
            # حذف فایل پیکربندی logrotate مربوط به Dante
            ("sudo rm -rf /etc/logrotate.d/dante", "Removing Dante logrotate configuration"),
            # متوقف کردن و غیرفعال کردن timer مربوط به logrotate دنت
            ("sudo systemctl stop logrotate-dante.timer", "Stopping Dante logrotate timer"),
            ("sudo systemctl disable logrotate-dante.timer", "Disabling Dante logrotate timer"),
            ("sudo rm -rf /etc/systemd/system/logrotate-dante.timer", "Removing Dante logrotate timer file"),
            ("sudo rm -rf /etc/systemd/system/logrotate-dante.service", "Removing Dante logrotate service file"),
            ("sudo systemctl daemon-reload", "Daemon-Reload")
        ]
        
        for cmd, desc in cleanup_steps:
            success &= Remover.execute_step(cmd, desc)
        


        if success:
            Logger.success("Complete", details="Socksify removal successful")
        else:
            Logger.warning("Partial Success", details="Socksify cleanup incomplete")
        
        print("\n" + "─"*40)

        return success





    @staticmethod
    def remove_dnsson():

        print("\n" + "─"*40)
        print("🗑️ REMOVING DNSSON".center(40))
        print("─"*40)

        result = SystemUtils.run_command("sudo rm -rf /usr/local/bin/dnsson", "")
        if result:
            Logger.success("DnsSon Script removed successfully")
        else:
            Logger.error("Failed to remove DnsSon script")

        print("\n" + "─"*40)

        return result






    @staticmethod
    def remove_proxyson():

        print("\n" + "─"*40)
        print("🗑️ REMOVING PROXYSON".center(40))
        print("─"*40)


        result = SystemUtils.run_command("sudo rm -rf /usr/local/bin/proxyson", "")
        if result:
            Logger.success("Script removed successfully")
        else:
            Logger.error("Failed to remove ProxySon script")

        print("\n" + "─"*40)

        return result






    @staticmethod
    def remove_dnsson_proxyson():

        print("\n" + "─"*40)
        print("Removing ProxySon & Dnsson".center(40))
        print("─"*40)


        SystemUtils.run_command("sudo rm -rf /usr/local/bin/dnsson", "Removing Dnsson script")
        SystemUtils.run_command("sudo rm -rf /usr/local/bin/proxyson", "Removing ProxySon script")
        Logger.success("Dnsson and ProxySon scripts removed successfully")
        
        print("\n" + "─"*40)








# -------------------- Installer --------------------
class Installer:
    




    @staticmethod
    def install_dante():

        Remover.fix_apt_issues()
        print("\n" + "─"*40)
        Logger.info("Installing Socksify...")
        print("\n" + "─"*40)

        if not SystemUtils.run_apt_command("sudo apt-get install -y dante-client", timeout=300):
            return False

        print("\n" + "─"*40)

        return True






    @staticmethod
    def install_proxychains():
        Remover.fix_apt_issues()

        print("\n" + "─"*40)
        Logger.info("Installing ProxyChains...")
        print("\n" + "─"*40)


        if not SystemUtils.run_apt_command("sudo apt update", timeout=300):
            return False
        prereq_cmd = "sudo apt install -y tar build-essential git automake autoconf libtool libproxychains4"
        if not SystemUtils.run_apt_command(prereq_cmd, timeout=300):
            return False


        try:
            with tempfile.NamedTemporaryFile(suffix=".tar.xz", delete=False) as tmp_file:
                tarball_path = tmp_file.name
            download_url = "https://github.com/kalilovers/proxychains-ng/releases/download/v4.17/proxychains-ng-4.17.tar.xz"
            if not SystemUtils.run_command(f"sudo wget {download_url} -O {tarball_path}", "Failed to download ProxyChains tarball."):
                os.unlink(tarball_path)
                return False


            if not SystemUtils.run_command(f"sudo tar -xf {tarball_path} -C /usr/local/src", "Failed to extract ProxyChains tarball into /usr/local/src."):
                os.unlink(tarball_path)
                return False


            os.unlink(tarball_path)
        except Exception as e:
            Logger.error(f"Exception during download/extraction: {e}", 
                        solution="Check network connectivity or file permissions")
            return False


        extracted_dir = "/usr/local/src/proxychains-ng-4.17"
        if not os.path.isdir(extracted_dir):
            Logger.error("Extracted directory /usr/local/src/proxychains-ng-4.17 not found.", 
                        solution="Verify tarball extraction path")
            return False

        current_dir = os.getcwd()
        try:
            os.chdir(extracted_dir)
            build_cmd = "./configure --prefix=/usr --sysconfdir=/etc && make clean && make && sudo make install && sudo make install-config"
            if not SystemUtils.run_command(build_cmd, "Failed to build and install ProxyChains."):
                return False
        finally:
            os.chdir(current_dir)


        if not SystemUtils.run_command("sudo rm -f /usr/local/bin/proxyresolv", "Failed to remove existing proxyresolv file."):
            return False
        proxyresolv_url = "https://raw.githubusercontent.com/kalilovers/proxychains-ng/master/src/proxyresolv"
        if not SystemUtils.run_command(f"sudo wget {proxyresolv_url} -O /usr/local/bin/proxyresolv", "Failed to download proxyresolv."):
            return False
        if not SystemUtils.run_command("sudo chmod 750 /usr/local/bin/proxyresolv", "Failed to set executable permission on proxyresolv."):
            return False

        Logger.success("ProxyChains installed successfully", 
                      details="Source: kalilovers/proxychains-ng v4.17")

        print("\n" + "─"*40)

        return True


 



    def install_tor_from_repo():
        Remover.fix_apt_issues()

        print("\nTrying to Install Tor From Tor'Repository...")



        if not TorManager.check_tor_repo_access():
            Logger.warning("Tor repository appears unreachable (possibly due to censorship)", 
                          solution="Check network connectivity or try later")
            return False


        try:
            arch = subprocess.check_output("dpkg --print-architecture", shell=True, text=True).strip()
            if arch == "armhf":
                Logger.warning(f"Architecture '{arch}' not supported by official repository", 
                              solution="Use fallback installation method")
                return False
            if arch not in ["amd64", "arm64", "i386"]:
                Logger.warning(f"Architecture '{arch}' not recognized for official repository installation", 
                              solution="Verify system architecture compatibility")
                return False
        except Exception as e:
            Logger.error(f"Error checking architecture: {str(e)}", 
                        solution="Check 'dpkg --print-architecture' command output")
            return False


        if not SystemUtils.run_apt_command("sudo apt-get install -y apt-transport-https", timeout=300):
            Logger.warning("Failed to install apt-transport-https. Falling back to default installation", 
                          solution="Check package availability")
            return False


        try:
            distro = subprocess.check_output("lsb_release -c -s", shell=True, text=True).strip()
        except Exception as e:
            Logger.error(f"Error determining distribution codename: {str(e)}", 
                        solution="Verify 'lsb_release' command functionality")
            return False


        repo_content = f"""deb [arch={arch} signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org {distro} main
    deb-src [arch={arch} signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg] https://deb.torproject.org/torproject.org {distro} main
    """
        repo_file = "/etc/apt/sources.list.d/tor.list"
        try:
            with open(repo_file, "w") as f:
                f.write(repo_content)
            Logger.success("Tor repository file created successfully", 
                          details=f"Path: {repo_file}")
        except Exception as e:
            Logger.error(f"Error creating {repo_file}: {str(e)}", 
                        solution="Check write permissions and disk space")
            return False


        key_cmd = ("wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | "
                   "gpg --dearmor | sudo tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null")
        if not SystemUtils.run_command(key_cmd, "Failed to add Tor Project GPG key"):
            Logger.warning("GPG key addition failed. Falling back to default installation", 
                          solution="Verify network access to Tor keyserver")
            return False


        Logger.info("Updating package lists from Tor repository...")
        if not SystemUtils.run_apt_command("sudo apt-get update", timeout=300):
            Logger.error("APT update failed", 
                        solution="Check repository configuration and network connection")
            return False


        Logger.info("Installing Tor from the official repository...")
        if not SystemUtils.run_apt_command("sudo apt-get install -y tor tor-geoipdb nyx deb.torproject.org-keyring", timeout=300):
            Logger.error("Tor installation failed from official repository", 
                        solution="Check package dependencies and repository access")
            return False

        TorManager.setup_tor_logrotate()

        Logger.success("Tor installed successfully from official repository", 
                      details="Packages: tor, tor-geoipdb, nyx, deb.torproject.org-keyring")

        print("\n" + "─"*40)

        return True






    @staticmethod
    def install_tor():
        
        print("\n" + "─"*40)
        Logger.info("Installing Tor...")
        print("\n" + "─"*40)

        Remover.fix_apt_issues()

        socks_ip, socks_port, dns_ip, dns_port = None, None, None, None
        exclude_ports = []


        while True:
            socks_ip_input = InputUtils.get_user_input(
                "\nEnter the IP for Tor Socks5 (press Enter for a random available IP): ", default=None
            )
            if socks_ip_input:

                if Validator.validate_ip(socks_ip_input, is_dns_port=True):
                    socks_ip = socks_ip_input
                    break
                else:
                    Logger.warning("Invalid IP. Please try again...")
            else:

                success, result = NetworkUtils.get_random_ip()
                if success:
                    socks_ip = result
                    break
                else:
                    Logger.warning(f"Random IP generation failed: {result}. Please enter the IP manually.")


        while True:
            socks_port_input = InputUtils.get_user_input(
                "\nEnter the port for Tor Socks5 (press Enter for a random available port): ", default=None
            )
            if socks_port_input:
                if Validator.validate_socks_port(socks_ip, socks_port_input, exclude_ports):
                    socks_port = int(socks_port_input)
                    exclude_ports.append(socks_port)
                    break
                else:
                    Logger.warning("Invalid Socks port. Please try again...")
            else:
                success, ip_returned, port, _ = NetworkUtils.get_random_available_socks_port(ip=socks_ip, exclude_ports=exclude_ports)
                if success and port:
                    socks_ip = ip_returned
                    socks_port = port
                    exclude_ports.append(socks_port)
                    break
                else:
                    Logger.warning(f"No available SocksPort found: {port if port is None else ''}. Please specify the port manually.")


        while True:
            dns_ip_input = InputUtils.get_user_input(
                "\nEnter the IP for Tor DNS (press Enter for a random available IP): ", default=None
            )
            if dns_ip_input:
                if Validator.validate_ip(dns_ip_input, is_dns_port=True):
                    dns_ip = dns_ip_input
                    break
                else:
                    Logger.warning("Invalid IP. Please try again...")
            else:
                success, result = NetworkUtils.get_random_ip()
                if success:
                    dns_ip = result
                    break
                else:
                    Logger.warning(f"Random IP generation for DNS failed: {result}. Please enter the IP manually.")


        while True:
            dns_port_input = InputUtils.get_user_input(
                "\nEnter the port for Tor DNS (press Enter for a random available port): ", default=None
            )
            if dns_port_input:
                if Validator.validate_dns_port(dns_ip, dns_port_input, exclude_ports):
                    dns_port = int(dns_port_input)
                    if dns_port == socks_port:
                        Logger.warning("DNSPort cannot match SocksPort. Choose a different port.")
                    else:
                        break
                else:
                    Logger.warning("Invalid DNS port. Please try again...")
            else:
                success, ip_returned, port, _ = NetworkUtils.get_random_available_dns_port(ip=dns_ip, exclude_ports=exclude_ports)
                if success and port:
                    if port == socks_port:
                        Logger.warning("Randomly selected DNSPort matches SocksPort, retrying to find another port...")
                        continue
                    dns_ip = ip_returned
                    dns_port = port
                    break
                else:
                    Logger.warning("No available DNSPort found. Please specify the port manually.")


        virtual_addr_candidates = ["10.192.0.0/10", "172.128.0.0/10", "100.64.0.0/10"]
        selected_virtual_addr = None
        for cidr in virtual_addr_candidates:
            if not NetworkUtils.is_range_in_use(cidr):
                selected_virtual_addr = cidr
                break
        if selected_virtual_addr is None:
            Logger.error("All standard VirtualAddrNetworkIPv4 ranges are in use", 
                         solution="Free up the ranges")
            return False


        if Installer.install_tor_from_repo():
            Logger.success("Tor installed successfully from official repository", 
                           details="Using recommended repository configuration")
        else:
            Logger.warning("Official repository installation failed", 
                           solution="Installing from default system repositories...")
            print("\n")
            repo_file = "/etc/apt/sources.list.d/tor.list"
            if SystemUtils.file_exists(repo_file):
                os.remove(repo_file)
                Logger.info("Removed failed repository configuration")

            if not SystemUtils.run_apt_command("sudo apt-get install -y tor tor-geoipdb nyx", timeout=300):
                Logger.error("Tor installation failed via fallback method", 
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

        TorManager.validate_and_clean_torrc(torrc_path)


        SystemUtils.run_command("sudo mkdir -p /var/log/tor", "Failed to create Tor log directory.")
        SystemUtils.run_command("sudo touch /var/log/tor/notice.log", "Failed to create Tor log file.")
        SystemUtils.run_command("sudo chown debian-tor:debian-tor /var/log/tor /var/log/tor/notice.log", 
                               "Failed to set ownership for Tor log file.")
        SystemUtils.run_command("sudo chmod 660 /var/log/tor/notice.log", "Failed to set permissions for Tor log file.")

        if not TorManager.restart_tor():
            Logger.error("Tor service restart failed", solution="Check systemd service status")

        SystemUtils.run_command("sudo systemctl enable tor", "Failed to enable Tor service.")
        SystemUtils.run_command("sudo systemctl enable tor@default", "Failed to enable Tor@default service.")

        TorManager.setup_tor_logrotate()

        print("\n" + "─"*40)
        Logger.success("Tor configuration written", 
                       details=f"VirtualAddrNetworkIPv4 set to: {selected_virtual_addr}")

        Logger.success("Tor configured and enabled", 
                       details=f"Socks: {socks_ip}:{socks_port} | DNS: {dns_ip}:{dns_port}")

        print("\n" + "─"*40)

        return socks_ip, socks_port, dns_ip, dns_port







# -------------------- Status Manager --------------------
class StatusManager:
    
    
    
    
    
    @staticmethod
    def tor_status():
        SystemUtils.clear_screen()
        status_data = {
            'service': " 🔍Tor Service",
            'config': "⚙️Tor Configuration",
        }
        


        print(f"{color.BORDER_COLOR}╔{'═'*42}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{'🧦TOR STATUS'.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*42}╣{color.RESET}")


        if not SystemUtils.is_installed("tor"):
            print(f"\n{status_data['service']}: ❌Not Installed")
            return
        
        if not SystemUtils.file_exists("/etc/tor/torrc"):
            print(f"\n{status_data['config']}: ❌Missing torrc file")
            return
        

        service_check = subprocess.run("systemctl is-active tor", shell=True, capture_output=True, text=True)
        print(f"\n{status_data['service']}: {'✅Running' if service_check.returncode == 0 else '❌Not Running'}")



        socks_ip, socks_port = TorManager.get_tor_socks_info()
        if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
            print(f"{color.BORDER_COLOR}  │{color.RESET}SOCKS Proxy: ❌torrc file not found!")
        elif socks_ip is None or socks_port is None:
            print(f"{color.BORDER_COLOR}  │{color.RESET}SOCKS Proxy: ❌Invalid configuration")
        else:
            print(f"\n SOCKS Proxy Settings:")
            print(f"{color.BORDER_COLOR}  │{color.RESET}▸ SOCKS IP: {socks_ip}")
            print(f"{color.BORDER_COLOR}  │{color.RESET}▸ SOCKS Port: {socks_port}")


        dns_ip, dns_port = TorManager.get_tor_dns_info()
        if dns_ip == "TORRC_NOT_FOUND" or dns_port == "TORRC_NOT_FOUND":
            print(f"{color.BORDER_COLOR}  │{color.RESET}DNS Proxy: ❌torrc file not found!")
        elif dns_ip is None or dns_port is None:
            print(f"{color.BORDER_COLOR}  │{color.RESET}DNS Proxy: ❌Invalid configuration")
        else:
            print(f"\n DNS Proxy Settings:")
            print(f"{color.BORDER_COLOR}  │{color.RESET}▸ DNS IP: {dns_ip}")
            print(f"{color.BORDER_COLOR}  │{color.RESET}▸ DNS Port: {dns_port}")



        tor_config = SystemUtils.read_file("/etc/tor/torrc")
        automap_status = "✅Active" if "AutomapHostsOnResolve 1" in tor_config else "❌Inactive"
        VirtualAddrNetworkIPv4_status = "✅Active" if "VirtualAddrNetworkIPv4" in tor_config else "❌Inactive"
        lognotice_status = "✅Active /var/log/tor/notice.log" if "Log notice file /var/log/tor/notice.log" in tor_config else "📋Inactive Or Other Path"
        print(f"\n General Settings:")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ VirtualAddrNetworkIPv4 : {VirtualAddrNetworkIPv4_status}")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ AutomapHosts: {automap_status}")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ Log : {lognotice_status}")
        

        if SystemUtils.file_exists("/var/log/tor/notice.log"):
            log_content = SystemUtils.read_file("/var/log/tor/notice.log")
            if "Error" in log_content or "Failed" in log_content:
                print("\n⚠️ Recent Errors in Tor Logs:")
                errors = [line for line in log_content.split('\n') if "Error" in line or "Failed" in line][-3:]
                for err in errors:
                    print(f"▸ {err[:60]}...")

        print(f"\n{color.BORDER_COLOR}╚{'═'*42}╝{color.RESET}")




    @staticmethod
    def dnsson_status():
        SystemUtils.clear_screen()


        print(f"{color.BORDER_COLOR}╔{'═'*42}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{'🧦DNSSON STATUS'.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*42}╣{color.RESET}")




        script_path = "/usr/local/bin/dnsson"
        if not SystemUtils.file_exists(script_path):
            print("\n❌ Not Installed")
            return
        
        content = SystemUtils.read_file(script_path)
        dest_match = re.search(r'--to-destination\s+([\d\.]+:\d+)', content)
        ns_match = re.search(r'nameserver\s+([\d\.]+)', content)
        
        print("\n ✅Installed | Settings:")
        print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Destination: {dest_match.group(1) if dest_match else '❌Not found'}")
        print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Nameserver: {ns_match.group(1) if ns_match else '❌Not found'}")
        

        iptables_check = subprocess.run(
            "sudo iptables -t nat -L OUTPUT | grep DNAT",
            shell=True,
            capture_output=True,
            text=True
        )
        if "DNAT" in iptables_check.stdout:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ IPTables Rules: ✅Active-In Use")
        else:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ IPTables Rules: 🔌Not Active")


        print(f"\n{color.BORDER_COLOR}╚{'═'*42}╝{color.RESET}")






    @staticmethod
    def proxyson_status():
        SystemUtils.clear_screen()


        print(f"{color.BORDER_COLOR}╔{'═'*42}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{'🧦PROXYSON STATUS'.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*42}╣{color.RESET}")


        script_path = "/usr/local/bin/proxyson"
        if not SystemUtils.file_exists(script_path):
            print("\n❌ Not Installed")
            return
        
        content = SystemUtils.read_file(script_path)
        dest_match = re.search(r'--to-destination\s+([\d\.]+:\d+)', content)
        cmd_match = re.search(r'exec\s+(\S+)\s+"\$@"', content)
        
        print("\n ✅Installed | Settings:")
        print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Destination: {dest_match.group(1) if dest_match else '❌Not found'}")
        print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Command: {cmd_match.group(1) if cmd_match else '❌Not found'}")  # نمایش دستور فعلی
        

        iptables_check = subprocess.run(
            "sudo iptables -t nat -L OUTPUT | grep DNAT",
            shell=True,
            capture_output=True,
            text=True
        )
        print(f"{color.BORDER_COLOR}   │{color.RESET}▸ IPTables Rules:","✅Active-In Use" if "DNAT" in iptables_check.stdout else "🔌Not Active")

        print(f"\n{color.BORDER_COLOR}╚{'═'*42}╝{color.RESET}")






    @staticmethod
    def dante_status():
        SystemUtils.clear_screen()

        print(f"{color.BORDER_COLOR}╔{'═'*42}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{'🧦Socksify STATUS'.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*42}╣{color.RESET}")
        

        if not SystemUtils.is_installed("dante-client"):
            print("❌ Not Installed")
            return
            


        config_path = "/etc/socks.conf"
        if SystemUtils.file_exists(config_path):
            print(f"\n 🔍Config File Path: /etc/socks.conf")
        else:
            print(" ⚠️Missing Configuration File")

            
        config_content = SystemUtils.read_file(config_path)
        

        via_match = re.search(r'via:\s+([\d\.]+)\s+port\s*=\s*(\d+)', config_content, re.IGNORECASE)
        proto_match = re.search(r'resolveprotocol:\s+(\w+)', config_content, re.IGNORECASE)
        logging_match = re.search(r'logoutput:\s+(\S+)', config_content)
        
        print("\n SOCKS Settings:")
        if via_match:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Address: {via_match.group(1)}")
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Port: {via_match.group(2)}")
        else:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ ❌Invalid Configuration!")
        
        print("\n DNS Settings:")
        if proto_match:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Protocol: {proto_match.group(1).upper()}")
        else:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ ❌Protocol not specified!")
        
        print("\n Logging:")
        if logging_match:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ Output: {logging_match.group(1)}")
        else:
            print(f"{color.BORDER_COLOR}   │{color.RESET}▸ ❌Logging disabled!")

        print(f"\n{color.BORDER_COLOR}╚{'═'*42}╝{color.RESET}")




    @staticmethod
    def proxychains_status():
        SystemUtils.clear_screen()

        print(f"{color.BORDER_COLOR}╔{'═'*42}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{'🔗PROXYCHAINS STATUS'.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*42}╣{color.RESET}")


        config_path = "/etc/proxychains.conf"
        if not SystemUtils.file_exists(config_path):
            print("❌ ProxyChains configuration file not found!")
            return


        config = SystemUtils.read_file(config_path)
        

        chain_types = {
            "dynamic_chain": "🔗Dynamic",
            "strict_chain": "⛓ Strict",
            "random_chain": "🎲Random",
            "round_robin_chain": "🔄Round-Robin"
        }
        
        active_chains = []
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                if stripped in chain_types:
                    active_chains.append(stripped)

        
        if len(active_chains) == 1:
            chain_type = chain_types[active_chains[0]]
        elif len(active_chains) > 1:
            chain_type = "🚫Multiple | Invalid"
        else:
            chain_type = "❌Disabled"



        dns_pattern = re.compile(r"^(proxy_dns(?:_old|_daemon)?)\b", re.IGNORECASE)
        active_dns = set()
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                match = dns_pattern.search(stripped)
                if match:
                    active_dns.add(match.group(1).lower())
        if len(active_dns) == 1:
            dns_status = f"✅Enabled [{list(active_dns)[0]}]"
        elif len(active_dns) > 1:
            dns_status = f"⚠️Multiple settings active: {', '.join(active_dns)}"
        else:
            dns_status = "❌Disabled"


        quiet_pattern = re.compile(r"^(quiet_mode)\b", re.IGNORECASE)
        quiet_mode_active = False
        for line in config.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                if quiet_pattern.search(stripped):
                    quiet_mode_active = True
                    break
        quiet_status = "✅Enabled" if quiet_mode_active else "❌Disabled"

        proxy_pattern = re.compile(
            r'^\s*(socks4|socks5|http)\s+'
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
            r'(\d{1,5})'
            r'(?:\s+([^\s#]+)\s+([^\s#]+))?'
            r'(?:\s*#.*)?$',
            re.IGNORECASE
        )

        proxies = []
        in_proxy_section = False

        for line in config.splitlines():
            line = line.strip()
            
            if line == "[ProxyList]":
                in_proxy_section = True
                continue
                
            if in_proxy_section and line.startswith('['):
                break
                
            if in_proxy_section and line:
                match = proxy_pattern.match(line)
                if match:
                    ptype = match.group(1).upper()
                    ip = match.group(2)
                    port = match.group(3)
                    auth = ""
                    if match.group(4) and match.group(5):
                        auth = f"user: {match.group(4)} pass: {match.group(5)}"
                    proxy_line = f"{ptype} {ip}:{port}"
                    if auth:
                        proxy_line += f" ({auth})"
                    proxies.append(proxy_line)


        proxy_count = len(proxies)


        print(f"\n 🔍Config File Path: {config_path}")
        print(f"\n General Settings: ")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ Chain Type Mode: {chain_type}")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ DNS Proxy Mode: {dns_status}")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ Quiet Mode: {quiet_status}")
        print(f"{color.BORDER_COLOR}  │{color.RESET}▸ Active Proxies: {proxy_count}")



        if proxies:
            print("\n Recent Proxies:")
            for proxy in proxies[-5:]:
                print(f"{color.BORDER_COLOR}  │{color.RESET}▸ {proxy}")
        else:
            print(f"{color.BORDER_COLOR}  │{color.RESET}🧦No proxies configured in [ProxyList]")

        print("\n Connection Status:")
        sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET}⏳Testing connectivity to 1.1.1.1:80...\n")
        sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET}⏳Please Wait afew second...")
        sys.stdout.flush()

        def run_test():
            test_result = subprocess.run("proxychains4 nc -z -v -w3 1.1.1.1 80", shell=True, capture_output=True, text=True)

            sys.stdout.write("\033[1A")
            sys.stdout.write("\r\033[K")
            sys.stdout.write("\033[B\r\033[K")
            if test_result.returncode == 0:
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET}✅Connection succeeded to 1.1.1.1:80\n")
            else:
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET}❌Connection failed to 1.1.1.1:80\n")
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET}Possible reasons:\n")
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET} - Invalid proxy configuration\n")
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET} - Network connectivity issues\n")
                sys.stdout.write(f"{color.BORDER_COLOR}  │{color.RESET} - Target server unreachable\n")
            sys.stdout.flush()

        t = threading.Thread(target=run_test)
        t.start()
        t.join()

        print(f"\n{color.BORDER_COLOR}╚{'═'*42}╝{color.RESET}")





# -------------------- Tor Manager --------------------
class TorManager:








    @staticmethod
    def handle_tor_setup():

        while True:
            MenuManager.display_setup_tor_menu()
            tor_choice = input("\nEnter your choice: ").strip()

            if tor_choice == '0':
                break  # Return to main menu

            elif tor_choice == '1':  # Tor Status
                SystemUtils.clear_screen()
                StatusManager.tor_status()
                input("Press Enter to return to Tor Setup menu...")  # Preserve navigation

            elif tor_choice == '2':  # Install Tor
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Installing Tor ")               # Preserve title
                print("=========================================\n")

                confirm_tor_install = InputUtils.get_confirmation(
                    "Warning: Installing Tor will remove any previous Tor installation and its settings.\n"
                    "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
                )
                if not confirm_tor_install:
                    Logger.warning("Installation aborted by user", solution="Re-run setup to try again")
                    input("Press Enter to Return...")
                    continue

                try:
                    with NetworkUtils.temporary_dns() as success:
                        if not success:
                            Logger.error("Repository connectivity issues detected", 
                                        solution="Check internet connection and DNS resolution",
                                        details="Skipping Tor installation")
                            continue

                        Logger.info("Preparing for fresh installation...")
                        Remover.remove_tor()
                        time.sleep(2)


                        try:
                            socks_ip, socks_port, dns_ip, dns_port = Installer.install_tor()
                        except Exception as e:
                            Logger.error(f"Tor installation failed: {str(e)}", 
                                        solution="Check dependencies and system permissions")
                            Logger.warning("Rolling back partial installation...", 
                                          solution="System will revert changes")
                            Remover.remove_tor()
                            input("Press Enter to return to Tor Setup menu...")
                            continue

                except KeyboardInterrupt:
                    Logger.warning("User interrupted installation! Rolling back changes...", 
                                  solution="Installation aborted")
                    Remover.remove_tor()
                    Logger.success("Cleanup completed", details="Aborted installation rolled back")
                    input("\nPress Enter to return to Tor Setup menu...")
                    return

                input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation



            elif tor_choice == '3':  # Manual Configuration (with partial sync)
                SystemUtils.clear_screen()
                print("=========================================")
                print("            Manual Tor Configuration")
                print("=========================================\n")
                
                # 1. Check prerequisites
                if not SystemUtils.is_installed("tor") or not SystemUtils.file_exists("/etc/tor/torrc"):
                    Logger.error("[Critical] Tor or torrc file not found!", 
                                 solution="Install Tor first from main menu", 
                                 details="Path Checked: /etc/tor/torrc")
                    input("\nPress Enter to return...")
                    continue

                # 2. Create unique backup using UUID
                backup_uuid = str(uuid.uuid4())[:8]
                backup_path = f"/etc/tor/torrc.backup_{backup_uuid}"
                try:
                    shutil.copyfile("/etc/tor/torrc", backup_path)
                    Logger.success("Backup created", details=f"Path: {backup_path}")
                except Exception as e:
                    Logger.error(f"Failed to create backup: {str(e)}", 
                                solution="Check disk space and file permissions")
                    input("\nPress Enter to return...")
                    continue

                # 3. Edit torrc file
                Logger.info("Editing torrc configuration file in nano editor...", 
                           details="Opening with sudo nano")
                edit_result = os.system("sudo nano /etc/tor/torrc")
                
                # 4. Extract and validate new settings
                socks_ip, socks_port = TorManager.get_tor_socks_info()
                dns_ip, dns_port = TorManager.get_tor_dns_info()

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
                    restore_choice = InputUtils.get_confirmation("⚠️ Restore original configuration from backup? (Y/n): ")
                    if restore_choice:
                        try:
                            shutil.copyfile(backup_path, "/etc/tor/torrc")
                            Logger.success("Configuration restored from backup", 
                                          details=f"Restored from: {backup_path}")
                        except Exception as e:
                            Logger.error(f"Failed to restore backup: {str(e)}", 
                                        solution="Manually copy backup file")
                    else:
                        Logger.warning("Keeping modified configuration", 
                                      solution="This may cause system instability")

                    # Final cleanup
                    try:
                        os.remove(backup_path)
                        Logger.info("Backup removed", details=f"Path: {backup_path}")
                    except Exception as e:
                        Logger.warning(f"Failed to remove backup: {str(e)}", 
                                      solution="Delete manually if needed")

                    # Attempt Tor restart with current config
                    print("\n🔁 Attempting Tor restart...")
                    restart_ok = TorManager.restart_tor()
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
                if InputUtils.get_confirmation("\n🔗 Sync DnsSon with new DNS settings? (Y/n): "):
                    if SystemUtils.file_exists("/usr/local/bin/dnsson"):
                        try:
                            if DnssonManager.sync_dnsson(dns_ip, dns_port):
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
                if InputUtils.get_confirmation("\n🔗 Sync ProxySon with new DNS settings? (Y/n): "):
                    if SystemUtils.file_exists("/usr/local/bin/proxyson"):
                        try:
                            if ProxysonManager.sync_proxyson(dns_ip, dns_port):
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
                if InputUtils.get_confirmation("\n🔗 Sync Socksify with new SOCKS settings? (Y/n): "):
                    if SystemUtils.file_exists("/etc/socks.conf"):
                        try:
                            if DanteManager.update_dante_config(socks_ip, socks_port):
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
                    Logger.success("Backup removed", details=f"Path: {backup_path}")
                except Exception as e:
                    Logger.warning(f"Failed to remove backup: {str(e)}", 
                                  solution="Delete manually if needed")

                Logger.info("Final Tor restart...", context="Post-synchronization")
                restart_ok = TorManager.restart_tor()
                if restart_ok:
                    print("✅ Tor service restarted successfully")
                else:
                    print("❌ Tor restart failed! Check:")
                    print("  ├─ sudo systemctl status tor")
                    print("  ╰─ journalctl -u tor -n 50 --no-pager")

                input("\nPress Enter to return to menu...")



            elif tor_choice == '4':  # Stop Tor
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Stopping Tor")
                print("=========================================\n")
                TorManager.stop_tor()  # Core functionality preserved
                input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation





            elif tor_choice == '5':  # Restart Tor
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Restarting Tor")
                print("=========================================\n")
                Logger.info("Restarting Tor service...", context="Initiating restart sequence")
                TorManager.restart_tor()

                input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation





            elif tor_choice == '6':  # Remove Tor
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Remove Tor")
                print("=========================================\n")

                confirm_remove = InputUtils.get_confirmation(
                    "Warning: This will completely remove Tor and its configurations.\n"
                    "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
                )
                if not confirm_remove:
                    Logger.warning("Removal aborted by user", solution="Re-run setup to try again")
                    input("Press Enter to Return...")
                    continue

                Logger.info("Removing Tor...", context="Starting uninstall process")
                Remover.remove_tor()
                Logger.success("Tor removed successfully", 
                              details="All components and configurations deleted")
                input("\nPress Enter to return to Tor Setup menu...")  # Preserve navigation

            else:
                Logger.error("Invalid menu choice", 
                            solution=f"Select 0-{len(MenuManager.display_setup_tor_menu().menu_items)}", 
                            details=f"Received: {tor_choice}")
                input("Press Enter to try again...")








    @staticmethod
    def parse_torrc(torrc_path="/etc/tor/torrc"):

        result = {
            "socks_ip": None,
            "socks_port": None,
            "dns_ip": None,
            "dns_port": None,
            "exists": False
        }

        if not SystemUtils.file_exists(torrc_path):
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








    @staticmethod
    def get_tor_socks_info():

        TORRC_NOT_FOUND = ("TORRC_NOT_FOUND", "TORRC_NOT_FOUND")
        
        config = TorManager.parse_torrc("/etc/tor/torrc")
        if not config.get("exists", False):
            Logger.warning("Tor configuration file not found", 
                          solution="Verify /etc/tor/torrc exists", 
                          details="Path: /etc/tor/torrc")
            return TORRC_NOT_FOUND

        socks_ip = config.get("socks_ip")
        socks_port = config.get("socks_port")

        if not socks_port:
            Logger.warning("SocksPort port not specified in torrc", 
                          solution="Add 'SocksPort <IP>:<PORT>' to configuration")
            return None, None

        if not socks_port.isdigit() or not (1 <= int(socks_port) <= 65535):
            Logger.warning("Invalid SocksPort port specified", 
                          solution="Port must be between 1-65535")
            return None, None

        if not socks_ip:
            socks_ip = "127.0.0.1"
        else:
            try:
                socket.inet_aton(socks_ip)
                parts = socks_ip.split('.')
                if parts[0] != "127":
                    Logger.warning("SocksPort IP must be internal (127.x.x.x)", 
                                  solution="Update IP to local interface format")
                    return None, None
            except socket.error:
                Logger.warning("Invalid SocksPort IP format", 
                              solution="Use valid IPv4 address (e.g., 127.0.0.5)")
                return None, None

        return socks_ip, socks_port







    @staticmethod
    def get_tor_dns_info():

        TORRC_NOT_FOUND = ("TORRC_NOT_FOUND", "TORRC_NOT_FOUND")
        
        config = TorManager.parse_torrc("/etc/tor/torrc")
        if not config.get("exists", False):
            Logger.warning("Tor configuration file not found", 
                          solution="Verify /etc/tor/torrc exists", 
                          details="Path: /etc/tor/torrc")
            return TORRC_NOT_FOUND

        dns_ip = config.get("dns_ip")
        dns_port = config.get("dns_port")

        if not dns_port:
            Logger.warning("DNSPort port not specified in torrc", 
                          solution="Add 'DNSPort <IP>:<PORT>' to configuration")
            return None, None

        if not dns_port.isdigit() or not (1 <= int(dns_port) <= 65535):
            Logger.warning("Invalid DNSPort port specified", 
                          solution="Port must be between 1-65535")
            return None, None

        if not dns_ip:
            dns_ip = "127.0.0.1"
        else:
            try:
                socket.inet_aton(dns_ip)
                parts = dns_ip.split('.')
                if parts[0] != "127":
                    Logger.warning("DNSPort IP must be internal (127.x.x.x)", 
                                  solution="Update IP to local interface format")
                    return None, None
            except socket.error:
                Logger.warning("Invalid DNSPort IP format", 
                              solution="Use valid IPv4 address (e.g., 127.0.0.5)")
                return None, None

        return dns_ip, dns_port







    ### 1. `check_tor_repo_access()` ###
    @staticmethod
    def check_tor_repo_access():

        repo_domain = "deb.torproject.org"
        
        Logger.info("Checking direct connectivity to the Tor repository (port 443)...")
        
        connectivity_test = subprocess.run(
            'timeout 3 bash -c "</dev/tcp/deb.torproject.org/443"',
            shell=True, capture_output=True
        )

        if connectivity_test.returncode == 0:
            Logger.success("Tor repository is accessible")
            return True
        else:
            Logger.error("Tor repository is unreachable", solution="Check network connectivity or try later")
            return False






    ### 2. `validate_and_clean_torrc()` ###
    @staticmethod
    def validate_and_clean_torrc(torrc_path):

        valid_lines = []
        with open(torrc_path, "r") as torrc:
            for line in torrc:
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"):
                    valid_lines.append(line)
        with open(torrc_path, "w") as torrc:
            torrc.writelines(valid_lines)
        Logger.success("torrc file validated and cleaned", details=f"Path: {torrc_path}")





    ### 3. `stop_tor()` ###
    @staticmethod
    def stop_tor():

        Logger.info("Stopping Tor service...")
        
        SystemUtils.run_command("sudo systemctl stop tor", "Failed to stop Tor service.")
        SystemUtils.run_command("sudo systemctl stop tor@default", "Failed to stop Tor@default service.")
        SystemUtils.run_command("sudo killall tor", "Failed to kill Tor processes with 'killall'.")
        SystemUtils.run_command("sudo pkill tor", "Failed to kill Tor processes with 'pkill'.")
        SystemUtils.run_command("sudo pkill -9 tor", "Failed to force kill Tor processes with 'pkill -9'.")
        SystemUtils.run_command("sudo systemctl daemon-reexec", "Failed to re-execute systemd daemon.")
        
        Logger.success("Tor stopped successfully", details="All services and processes terminated")






    ### 4. `restart_tor()` ###
    @staticmethod
    def restart_tor():
        if not SystemUtils.is_installed("tor") or not SystemUtils.file_exists("/etc/tor/torrc"):
            Logger.error("Tor service not installed or torrc missing", solution="Install Tor first")
            return True

        Logger.info("Stopping Tor services...")
        SystemUtils.run_command("sudo systemctl stop tor", "Failed to stop Tor service.")
        SystemUtils.run_command("sudo systemctl stop tor@default", "Failed to stop Tor@default service.")
        SystemUtils.run_command("sudo killall tor", "Failed to kill Tor processes with 'killall'.")
        SystemUtils.run_command("sudo pkill tor", "Failed to kill Tor processes with 'pkill'.")
        SystemUtils.run_command("sudo pkill -9 tor", "Failed to force kill Tor processes with 'pkill -9'.")
        SystemUtils.run_command("sudo systemctl daemon-reexec", "Failed to re-execute systemd daemon.")
        time.sleep(2)

        Logger.info("Starting Tor services...")
        SystemUtils.run_command("sudo systemctl start tor", "Failed to start Tor service.")
        SystemUtils.run_command("sudo systemctl start tor@default", "Failed to start Tor@default service.")
        time.sleep(2)

        socks_ip, socks_port = TorManager.get_tor_socks_info()
        if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
            Logger.warning("torrc file not found during restart", solution="Verify /etc/tor/torrc exists")
        elif socks_ip is None or socks_port is None:
            Logger.warning("Invalid SocksPort configuration in torrc", 
                          details="Check SocksPort format in configuration file")
        else:
            Logger.success("Configuration validated ' Restarted successfully", 
                       details=f"Tor is listening on port {socks_port} at {socks_ip}")

        Logger.info("Checking tor Service Activation")
        if not SystemUtils.run_command("sudo systemctl is-active tor", "Tor service is not active."):
            Logger.warning("Tor service may not be active after restart", 
                          solution="Check service status with 'systemctl status tor'")
        Logger.info("Checking tor@default Service Activation")
        if not SystemUtils.run_command("sudo systemctl is-active tor@default", "❌ Tor@default service is Inactive"):
            Logger.warning("Tor@default service may not be active after restart", 
                          solution="Check service status with 'systemctl status tor@default'")
        
        return True






    @staticmethod
    def setup_tor_logrotate():

        logrotate_config = "/etc/logrotate.d/tor"

        if os.path.exists(logrotate_config):
            Logger.info("Tor logrotate configuration already exists. Skipping creation.", 
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
            SystemUtils.run_command(f"sudo chmod 644 {logrotate_config}", 
                                   "Failed to set permissions for Tor logrotate config.")
            Logger.success("Tor logrotate configuration created", 
                          details=f"Config file: {logrotate_config}")
        except Exception as e:
            Logger.error(f"Failed to create Tor logrotate configuration: {str(e)}", 
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
            SystemUtils.run_command(f"sudo chmod 644 {service_file}", 
                                   "Failed to set permissions for Tor logrotate service file.")
            Logger.success("logrotate-tor.service created", 
                          details=f"Service file: {service_file}")
        except Exception as e:
            Logger.error(f"Failed to create Tor logrotate service: {str(e)}", 
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
            SystemUtils.run_command(f"sudo chmod 644 {timer_file}", 
                                   "Failed to set permissions for Tor logrotate timer file.")
            Logger.success("logrotate-tor.timer created", 
                          details=f"Timer file: {timer_file}")
        except Exception as e:
            Logger.error(f"Failed to create Tor logrotate timer: {str(e)}", 
                        solution="Check systemd timer syntax and file permissions")

        SystemUtils.run_command("sudo systemctl enable logrotate-tor.timer", 
                               "Failed to enable logrotate-tor timer.")
        SystemUtils.run_command("sudo systemctl start logrotate-tor.timer", 
                               "Failed to start logrotate-tor timer.")
        Logger.success("logrotate-tor timer operational", 
                      details="Systemd timer enabled and started")

        SystemUtils.run_command("sudo logrotate -f /etc/logrotate.d/tor", 
                               "Failed to run logrotate for Tor logs.")
        Logger.success("Tor logs manually rotated", 
                      details="Immediate rotation test completed successfully")








# -------------------- Dante Manager --------------------
class DanteManager:




    @staticmethod
    def setup_dante_tor():
        SystemUtils.clear_screen()
        Logger.info("Setting up Socksify + Tor...")

        confirm_deletion = InputUtils.get_confirmation(
            "This will remove existing Tor, Socksify , Dnsson, and Proxyson installations. "
            "Do you want to proceed? \n(Press Enter for confirmation, or type 'n' or 'no' to cancel): ")
        if not confirm_deletion:
            Logger.warning("Setup aborted by user. Returning to main menu.")
            input("Press Enter to return to the Auto Setup menu...")
            return

        try:
            with NetworkUtils.temporary_dns() as success:
                if not success:
                    Logger.error("Skipping Tor installation due to repository connectivity issues.", 
                                solution="Check network connectivity and DNS resolution")
                    return

                Logger.info("Removing existing installations...")
                Remover.remove_dante()
                Remover.remove_tor()
                Remover.remove_dnsson_proxyson()



                if not Installer.install_dante():
                    Logger.error("Socksify installation failed.", 
                                solution="Check package repositories and dependencies")
                    Logger.warning("Rolling back changes due to  failures")
                    Remover.remove_dante()
                    Remover.remove_tor()
                    Remover.remove_dnsson_proxyson()
                    input("Press Enter to return to the Auto Setup menu...")
                    return

                try:
                    socks_ip, socks_port, dns_ip, dns_port = Installer.install_tor()
                except Exception as e:
                    Logger.error(f"Tor installation failed: {str(e)}", 
                                solution="Check Tor repository access and system architecture")
                    Logger.warning("Rolling back changes due to  failures")
                    Remover.remove_dante()
                    Remover.remove_tor()
                    Remover.remove_dnsson_proxyson()
                    input("Press Enter to return to the Auto Setup menu...")
                    return

                Logger.info("Configuring Socksify with Tor settings...")
                try:
                    DanteManager.configure_dante(socks_ip, socks_port, dns_protocol="fake")
                except Exception as e:
                    Logger.error(f"Failed to configure Socksify: {str(e)}", 
                                solution="Verify Socksify configuration syntax")
                    Logger.warning("Rolling back changes due to  failures")
                    Remover.remove_dante()
                    Remover.remove_tor()
                    Remover.remove_dnsson_proxyson()
                    input("Press Enter to return to the Auto Setup menu...")
                    return

                Logger.info("Restarting Tor service...")
                TorManager.restart_tor()

                Logger.info("Creating  proxy wrapper scripts...")
                try:
                    ProxysonManager.create_proxyson_script(
                        dns_ip=dns_ip, 
                        dns_port=dns_port, 
                        base_command="socksify"
                    )
                    DnssonManager.create_dnsson_script(dns_ip, dns_port)
                except Exception as e:
                    Logger.error(f"Failed to create proxy scripts: {str(e)}", 
                                solution="Check DNS format and script permissions")
                    Logger.warning("Rolling back changes due to  failures")
                    Remover.remove_dante()
                    Remover.remove_tor()
                    Remover.remove_dnsson_proxyson()
                    input("Press Enter to return to the Auto Setup menu...")
                    return

        except KeyboardInterrupt:
            Logger.warning("User interrupted installation! Rolling back changes...")
            Remover.remove_dante()
            Remover.remove_tor()
            Remover.remove_dnsson_proxyson()
            Logger.success("Cleanup completed", details="All components restored to previous state")
            input("Press Enter to return to the Auto Setup menu...")
            return

        Logger.success("Dante + Tor setup completed successfully",
                      details="Dependencies and components installed/updated")

        input("Press Enter to return to the Auto Setup menu...")





    @staticmethod
    def handle_dante_menu():
        while True:
            MenuManager.display_dante_menu()
            choice = input("\nSelect an option [0-7]: ").strip()

            if choice == '0':
                break



            elif choice == '1':
                StatusManager.dante_status()
                input("\nPress Enter to Return...")  # Preserve menu navigation



            elif choice == '2':
                try:
                    SystemUtils.clear_screen()
                    print("═" * 40)  
                    print("🧦 Socksify INSTALLATION".center(40))  
                    print("═" * 40)
                    if not InputUtils.get_confirmation("This will install Socksify. Continue? (Y/n): "):
                        continue
                    try:
                        with NetworkUtils.temporary_dns() as success:
                            if not success:
                                Logger.error("Repository connection failed!", 
                                            solution="Check network connectivity and DNS resolution")
                                continue
                            if SystemUtils.is_installed("dante-client"):
                                Logger.info("Removing existing installation...")
                                Remover.remove_dante()


                            if not Installer.install_dante():
                                raise Exception("Main installation failed")
                            # Sync with Tor
                            if InputUtils.get_confirmation("Sync with Tor? (Y/n): "):
                                if not SystemUtils.is_installed("tor"):
                                    Logger.warning("Tor not installed! Switching to manual configuration.", 
                                                  solution="Install Tor first for full integration")

                                    while True:
                                        socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                        if socks_ip is not None:
                                            break
                                        Logger.warning("Please re-enter a valid IP address...")
                                    while True:
                                        socks_port = Validator.prompt_for_port("Enter SOCKS Port: ")
                                        if socks_port is not None:
                                            break
                                        Logger.warning("Please re-enter a valid port number...")
                                    DanteManager.configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                    Logger.success("Manual configuration applied", 
                                                  details="Configuration done without Tor integration")
                                else:
                                    socks_ip, socks_port = TorManager.get_tor_socks_info()
                                    if socks_ip in (None, "TORRC_NOT_FOUND") or socks_port in (None, "TORRC_NOT_FOUND"):
                                        Logger.warning("Invalid Tor configuration detected! Switching to manual configuration.", 
                                                      solution="Check Tor's torrc file for SOCKS settings")

                                        while True:
                                            socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                            if socks_ip is not None:
                                                break
                                            Logger.warning("Please re-enter a valid IP address...")
                                        while True:
                                            socks_port = Validator.prompt_for_port("Enter SOCKS Port (1-65535): ")
                                            if socks_port is not None:
                                                break
                                            Logger.warning("Please re-enter a valid port number...")
                                        DanteManager.configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                        Logger.success("Manual configuration applied", 
                                                      details="Fallback configuration used")
                                    else:
                                        DanteManager.configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                        Logger.success("Successfully synced with Tor settings", 
                                                      details=f"SOCKS: {socks_ip}:{socks_port}")
                            else:
                                Logger.info("Manual configuration:")

                                while True:
                                    socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                    if socks_ip is not None:
                                        break
                                    Logger.warning("Please re-enter a valid IP address...")
                                while True:
                                    socks_port = Validator.prompt_for_port("Enter SOCKS Port (1-65535): ")
                                    if socks_port is not None:
                                        break
                                    Logger.warning("Please re-enter a valid port number...")
                                DanteManager.configure_dante(socks_ip, socks_port, dns_protocol="fake")
                                Logger.success("Manual configuration applied", 
                                              details=f"Manual settings: {socks_ip}:{socks_port}")
                    except KeyboardInterrupt:
                        Logger.warning("User interrupted installation! Rolling back changes...")
                        Remover.remove_dante()
                        Logger.success("Cleanup completed. Exiting...", context="Installation aborted")
                        input("\nPress Enter to Return...")
                        continue
                except Exception as e:
                    Logger.error(f"Critical Error: {str(e)}", 
                                solution="Check package repositories and system permissions")
                    Logger.warning("Performing rollback...", solution="System will revert to previous state")
                    Remover.remove_dante()
                    Logger.success("System restored to previous state", 
                                  details="All partially installed components removed")
                    input("\nPress Enter to Return...")
                    continue
                Logger.success("Installation completed", 
                              details="Dependencies and Socksify installed successfully")
                input("\nPress Enter to Return...")




            elif choice == '3':
                SystemUtils.clear_screen()
                print("═" * 40)  # Preserve menu structure
                print("📝 EDIT CONFIGURATION FILE".center(40))
                print("═" * 40)

                if not SystemUtils.is_installed("dante-client"):
                    Logger.error("Socksify not installed!", solution="Install Socksify first before editing configuration")
                elif not SystemUtils.file_exists("/etc/socks.conf"):
                    Logger.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
                else:
                    backup_name = f"/etc/socks.conf.bak-{int(time.time())}"
                    SystemUtils.run_command(f"sudo cp /etc/socks.conf {backup_name}", "Backup failed")
                    os.system("sudo nano /etc/socks.conf")
                    config_content = SystemUtils.read_file("/etc/socks.conf")

                    if "route {" not in config_content:
                        Logger.error("Invalid configuration! Restoring backup...", 
                                    solution="Check syntax of 'route' section in configuration")
                        SystemUtils.run_command(f"sudo mv {backup_name} /etc/socks.conf", "Restore failed")
                        Logger.success("Configuration restored from backup", details=f"Backup: {backup_name}")
                    else:
                        Logger.success("Changes saved successfully", 
                                      details=f"New configuration written to /etc/socks.conf")
                        SystemUtils.run_command(f"sudo rm {backup_name}", "Cleanup failed")
                input("\nPress Enter to Return...")




            elif choice == '4':
                SystemUtils.clear_screen()
                print("═" * 40)  
                print("🔧 CHANGE SOCKS SETTINGS".center(40))
                print("═" * 40)
                if not SystemUtils.is_installed("dante-client"):
                    Logger.error("Socksify not installed!", solution="Install Socksify first before changing settings")
                elif not SystemUtils.file_exists("/etc/socks.conf"):
                    Logger.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
                else:

                    while True:
                        new_ip = Validator.prompt_for_ip("Enter new SOCKS IP: ")
                        if new_ip is not None:
                            break
                        Logger.warning("Please re-enter a valid IP address...")
                    while True:
                        new_port = Validator.prompt_for_port("Enter new SOCKS Port (1-65535): ")
                        if new_port is not None:
                            break
                        Logger.warning("Please re-enter a valid port number...")
                    if DanteManager.update_dante_config(socks_ip=new_ip, socks_port=new_port):
                        Logger.success("SOCKS settings updated", details=f"New settings: {new_ip}:{new_port}")
                    else:
                        Logger.error("Failed to update SOCKS settings", 
                                    solution="Check IP format and port availability")
                input("\nPress Enter to Return...")



            elif choice == '5':
                SystemUtils.clear_screen()
                print("═" * 40)  # Preserve menu structure
                print("🔗 CONFIGURE DNS PROTOCOL".center(40))
                print("═" * 40)

                if not SystemUtils.is_installed("dante-client"):
                    Logger.error("Socksify not installed!", solution="Install Socksify first before configuring DNS")
                elif not SystemUtils.file_exists("/etc/socks.conf"):
                    Logger.error("Config file not found!", solution="Verify file exists at /etc/socks.conf")
                else:
                    print("\nAvailable DNS Protocols:")  # Preserve user input flow
                    print("1. fake (default - recommended)")
                    print("2. tcp (for DNS-over-TCP)")

                    proto = InputUtils.get_user_input(
                        "Select protocol [1/2]: ",
                        validator=lambda x, _: x in ['1', '2']
                    )
                    new_proto = "fake" if proto == '1' else "tcp"

                    if DanteManager.update_dante_config(dns_protocol=new_proto):
                        Logger.success(f"DNS protocol set to {new_proto.upper()}", 
                                      details=f"Updated configuration: {new_proto}")
                    else:
                        Logger.error("Failed to update DNS protocol", 
                                    solution="Check DNS protocol syntax in configuration file")

                input("\nPress Enter to Return...")

            elif choice == '6':
                SystemUtils.clear_screen()
                print("═" * 40)  # Preserve menu structure
                print("🔄 SYNC WITH TOR SETTINGS".center(40))
                print("═" * 40)

                requirements = {
                    "Socksify": SystemUtils.is_installed("dante-client"),
                    "socks.conf": SystemUtils.file_exists("/etc/socks.conf"),
                    "Tor": SystemUtils.is_installed("tor"),
                    "torrc": SystemUtils.file_exists("/etc/tor/torrc")
                }
                missing = [k for k, v in requirements.items() if not v]

                if missing:
                    print("❌ Missing requirements:")
                    for item in missing:
                        print(f"▸ {item}")

                else:
                    socks_ip, socks_port = TorManager.get_tor_socks_info()

                    if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
                        print("❌ Tor configuration file not found!")
                                                                                   
                        print("  ├─ Path: /etc/tor/torrc")
                        print("  ╰─ Install Tor first or restore configuration")
                    elif socks_ip is None or socks_port is None:
                        print("❌ Invalid SocksPort configuration detected!")
                        print("  ├─ Check these settings in torrc:")
                        print("  ╰─ Format: SocksPort <IP>:<PORT>")
                    else:
                        if DanteManager.update_dante_config(socks_ip, socks_port):
                            Logger.success(f"Successfully synced with Tor Socks: {socks_ip}:{socks_port}", 
                                          details="Socksify configuration updated")
                        else:
                            Logger.error("Failed to update Socksify configuration", 
                                        solution="Check Socksify's socks.conf syntax")

                input("\nPress Enter to Return...")

            elif choice == '7':
                SystemUtils.clear_screen()
                print("═" * 40)  # Preserve menu structure
                print("🗑️ REMOVE Socksify COMPLETELY".center(40))
                print("═" * 40)

                if InputUtils.get_confirmation("This will remove all Socksify components. Continue? (Y/n): "):
                    if Remover.remove_dante():
                        Logger.success("Socksify removed successfully", 
                                      details="All configuration files and logs deleted")
                    else:
                        Logger.warning("Partial removal detected", 
                                      solution="Check logs for incomplete removal issues")
                else:
                    Logger.info("Operation cancelled", details="No changes made to Socksify installation")

                input("\nPress Enter to Return...")

            else:
                Logger.error("Invalid choice", solution="Enter a number between 0-7")
                input("Press Enter to try again...")





    @staticmethod
    def update_dante_config(socks_ip=None, socks_port=None, dns_protocol=None):

        file_path = "/etc/socks.conf"
        if not SystemUtils.file_exists(file_path):
            Logger.error("Socksify config file not found!", 
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

            Logger.success("Socksify configuration updated successfully", 
                          details=f"File: {file_path} | SOCKS: {socks_ip or 'UNCHANGED'}:{socks_port or 'UNCHANGED'} | DNS Protocol: {dns_protocol or 'UNCHANGED'}")
            return True

        except Exception as e:
            Logger.error(f"Error updating Socksify configuration: {str(e)}",
                        solution="Check file permissions and syntax in socks.conf")
            return False







    @staticmethod
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
            SystemUtils.run_command("sudo mkdir -p /var/log/dante", "Failed to create dante log directory.")
            SystemUtils.run_command("sudo touch /var/log/dante/socks.errlog", "Failed to create /var/log/dante/socks.errlog.")
            SystemUtils.run_command("sudo touch /var/log/dante/socks.log", "Failed to create /var/log/dante/socks.log.")
            SystemUtils.run_command("sudo chmod 660 /var/log/dante/socks.errlog", "Failed to set permissions for /var/log/dante/socks.errlog.")
            SystemUtils.run_command("sudo chmod 660 /var/log/dante/socks.log", "Failed to set permissions for /var/log/dante/socks.log.")
            SystemUtils.run_command(f"echo 'export SOCKS_CONF={config_file}' | sudo tee -a ~/.bashrc", "Failed to add SOCKS_CONF to ~/.bashrc")
            SystemUtils.run_command(f"echo 'SOCKS_CONF={config_file}' | sudo tee -a /etc/environment", "Failed to add SOCKS_CONF to /etc/environment")
            SystemUtils.run_command("bash -c 'source ~/.bashrc'", "Applying changes")
            SystemUtils.run_command("source ~/.bashrc", "2nd Applying changes :0 ")
            SystemUtils.run_command("set -a; source /etc/environment; set +a", "Applying system-wide changes")

            # Log configuration success
            Logger.success("Socksify  configured successfully", 
                          details=f"Configuration file: {config_file} | DNS Protocol: {dns_protocol}")

            # Setup logrotate (this function already uses Logger internally)
            DanteManager.setup_dante_logrotate()


            return True

        except Exception as e:
            Logger.error(f"Configuration failed: {str(e)}",
                         solution="Verify permissions for /etc/socks.conf and log directories")
            return False








    @staticmethod
    def setup_dante_logrotate():

        logrotate_config = "/etc/logrotate.d/dante"
        
        if os.path.exists(logrotate_config):
            Logger.info("Socksify logrotate configuration already exists. Skipping creation.")
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
            SystemUtils.run_command(f"sudo chmod 644 {logrotate_config}", "Failed to set permissions for logrotate config.")
            Logger.success("Socksify logrotate configuration created", details=f"Path: {logrotate_config}")
        except Exception as e:
            Logger.error(f"Error creating logrotate config: {str(e)}", solution="Check write permissions and disk space")


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
            SystemUtils.run_command(f"sudo chmod 644 {service_file}", "Failed to set permissions for logrotate service.")
            Logger.success("logrotate-dante.service created", details=f"Service file: {service_file}")
        except Exception as e:
            Logger.error(f"Error creating service file: {str(e)}", solution="Verify systemd service syntax and permissions")


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
            SystemUtils.run_command(f"sudo chmod 644 {timer_file}", "Failed to set permissions for logrotate timer.")
            Logger.success("logrotate-dante.timer created", details=f"Timer file: {timer_file}")

        except Exception as e:
            Logger.error(f"Error creating timer file: {str(e)}", solution="Check systemd timer syntax and file permissions")


        SystemUtils.run_command("sudo systemctl enable logrotate-dante.timer", "Failed to enable logrotate-dante timer.")
        SystemUtils.run_command("sudo systemctl start logrotate-dante.timer", "Failed to start logrotate-dante timer.")
        Logger.success("logrotate-dante timer enabled and started", details="Systemd timer configured successfully")


        SystemUtils.run_command("sudo logrotate -f /etc/logrotate.d/dante", "Failed to run logrotate for Dante logs.")
        Logger.success("Dante logs rotated immediately", details="Manual rotation completed successfully")
        
        return True

 
 
# -------------------- ProxychainsManager --------------------
class ProxychainsManager:






    @staticmethod
    def handle_proxychains_menu():
        while True:
            MenuManager.display_proxychains_menu()
            choice = input("\nSelect an option [0-9]: ").strip()



            if choice == '0':
                break




            elif choice == '1':
                SystemUtils.clear_screen()
                StatusManager.proxychains_status()
                input("\nPress Enter to Return...")




            elif choice == '2':
                SystemUtils.clear_screen()
                print("═" * 40)
                print("🧦 PROXYCHAINS INSTALL".center(40))
                print("═" * 40)
                if not InputUtils.get_confirmation("This operation will remove and reinstall ProxyChains. \nDo you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel):  "):
                    continue

                try:
                    with NetworkUtils.temporary_dns() as success:
                        if not success:
                            Logger.error("Repository connection failed!", 
                                        solution="Check internet connection and DNS settings")
                            input("Press Enter to return...")
                            continue

                        if not Remover.remove_proxychains():
                            Logger.error("Critical error during removal", 
                                        solution="Verify dependencies or reinstall manually")
                            input("Press Enter to return...")
                            continue

                        if not Installer.install_proxychains():
                            Logger.error("Installation failed", 
                                        solution="Check logs for dependency issues")
                            Remover.remove_proxychains()
                            input("Press Enter to return...")
                            continue

                        if InputUtils.get_confirmation("Sync with Tor settings? (Y/n): "):
                            Logger.info("Checking Tor configuration...", icon="🔎")
                            tor_installed = SystemUtils.is_installed("tor")
                            torrc_exists = SystemUtils.file_exists("/etc/tor/torrc")

                            if not tor_installed or not torrc_exists:
                                print("❌ Tor not fully configured!")
                                print("  ├─ Installed: " + ("✅" if tor_installed else "❌"))
                                print("  ╰─ Config: " + ("✅" if torrc_exists else "❌"))
                                print("⤷ Switching to manual configuration")

                                # Loop until valid IP is entered
                                while True:
                                    socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                    if socks_ip is not None:
                                        break
                                    Logger.warning("Please re-enter a valid IP address...")

                                # Loop until valid Port is entered
                                while True:
                                    socks_port = Validator.prompt_for_port("Enter SOCKS Port: ")
                                    if socks_port is not None:
                                        break
                                    Logger.warning("Please re-enter a valid port number...")

                            else:
                                socks_ip, socks_port = TorManager.get_tor_socks_info()

                                if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
                                    Logger.error("Tor configuration file error", 
                                                solution="Fix permissions in /etc/tor/torrc")

                                    # Loop until valid IP is entered
                                    while True:
                                        socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                        if socks_ip is not None:
                                            break
                                        Logger.warning("Please re-enter a valid IP address...")

                                    # Loop until valid Port is entered
                                    while True:
                                        socks_port = Validator.prompt_for_port("Enter SOCKS Port: ")
                                        if socks_port is not None:
                                            break
                                        Logger.warning("Please re-enter a valid port number...")

                                elif socks_ip is None or socks_port is None:
                                    Logger.error("Invalid SocksPort in torrc , use manual entry", 
                                                solution="Check port settings in /etc/tor/torrc")

                                    # Loop until valid IP is entered
                                    while True:
                                        socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                        if socks_ip is not None:
                                            break
                                        Logger.warning("Please re-enter a valid IP address...")

                                    # Loop until valid Port is entered
                                    while True:
                                        socks_port = Validator.prompt_for_port("Enter SOCKS Port: ")
                                        if socks_port is not None:
                                            break
                                        Logger.warning("Please re-enter a valid port number...")

                                else:
                                    Logger.success("Tor settings detected", 
                                                  details=f"Using Tor configuration: {socks_ip}:{socks_port}")

                            if ProxychainsManager.configure_proxychains(socks_ip, socks_port):
                                Logger.success("ProxyChains configured successfully", 
                                              details=f"Proxy: {socks_ip}:{socks_port}")
                            else:
                                Logger.error("Critical configuration error", 
                                            solution="Check proxychains.conf syntax and permissions")
                                Remover.remove_proxychains()

                        else:
                            Logger.info("Manual configuration selected", icon="📝")

                            # Loop until valid IP is entered
                            while True:
                                socks_ip = Validator.prompt_for_ip("Enter SOCKS IP: ")
                                if socks_ip is not None:
                                    break
                                Logger.warning("Please re-enter a valid IP address...")

                            # Loop until valid Port is entered
                            while True:
                                socks_port = Validator.prompt_for_port("Enter SOCKS Port: ")
                                if socks_port is not None:
                                    break
                                Logger.warning("Please re-enter a valid port number...")

                            if ProxychainsManager.configure_proxychains(socks_ip, socks_port):
                                Logger.success("ProxyChains configured manually", 
                                              details=f"Proxy: {socks_ip}:{socks_port}")
                            else:
                                Logger.error("Configuration failed", 
                                            solution="Check proxy syntax and file permissions")
                                Remover.remove_proxychains()

                        input("\nPress Enter to return...")

                except KeyboardInterrupt:
                    Logger.warning("Operation cancelled by user!", 
                                  solution="Performing cleanup...")
                    Remover.remove_proxychains()
                    Logger.success("Partial installation removed", 
                                  details="ProxyChains rollback completed")
                    input("Press Enter to return...")




            elif choice == '3':
                if not SystemUtils.file_exists("/etc/proxychains.conf"):
                    Logger.error("Proxychains configuration file missing!", 
                                solution="Reinstall Proxychains , Or edit /etc/proxychains.conf manually")
                    input("\nPress Enter to Return...")
                    continue
                else:
                    backup = f"/etc/proxychains.conf.bak-{int(time.time())}"
                    try:
                        shutil.copyfile("/etc/proxychains.conf", backup)
                        os.system("sudo nano /etc/proxychains.conf")
                        
                        content = SystemUtils.read_file("/etc/proxychains.conf")
                        active_proxylist = any(
                            line.strip().startswith("[ProxyList]") and not line.strip().startswith("#")
                            for line in content.splitlines()
                        )
                        
                        if not active_proxylist:
                            Logger.error("Invalid configuration detected", 
                                        solution="Backup restored due to missing [ProxyList]")
                            shutil.copyfile(backup, "/etc/proxychains.conf")
                            Logger.warning("Backup restored", 
                                          details=f"Restored from {backup}")
                        else:
                            Logger.success("Configuration saved successfully")
                    finally:
                        if os.path.exists(backup):
                            os.remove(backup)
                    input("\nPress Enter to Return...")





            elif choice == '4':
                if not SystemUtils.file_exists("/etc/proxychains.conf"):
                    Logger.error("Proxychains configuration missing!", 
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
                    ProxychainsManager.change_chain_mode(selected_chain)
                else:
                    Logger.error("Invalid chain type selected", 
                                solution="Choose 1-4 for chain types")

                input("\nPress Enter to Return...")




            elif choice == '5':
                ProxychainsManager.change_quiet_mode()
                input("\nPress Enter to Return...")




            elif choice == '6':
                if not SystemUtils.file_exists("/etc/proxychains.conf"):
                    Logger.error("Proxychains config file missing!",
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
                    ProxychainsManager.change_proxychain_dns_mode(mode)
                else:
                    Logger.error("Invalid DNS mode selected", 
                                solution="Choose 1 for proxy_dns, 2 for proxy_dns_old, or 3 to disable both")

                input("\nPress Enter to Return...")




            elif choice == '7':
                ProxychainsManager.add_proxy_to_chain()
                input("\nPress Enter to Return...")




            elif choice == '8':
                if ProxychainsManager.sync_proxychains_with_tor():
                    Logger.success("ProxyChains synced with Tor", 
                                  details="DNS and SOCKS settings updated")




            elif choice == '9':
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Remove ProxyChains")
                print("=========================================\n")

                confirm_remove = InputUtils.get_confirmation(
                    "Warning: This will completely remove ProxyChains and its configurations.\n"
                    "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
                )
                if not confirm_remove:
                    Logger.warning("Removal aborted by user", solution="Re-run setup to try again")
                    input("Press Enter to Return...")
                    continue

                if Remover.remove_proxychains():
                    Logger.success("ProxyChains removed completely")
                else:
                    Logger.warning("Partial removal detected", 
                                  details="Some files may remain - check manually")
                input("\nPress Enter to Return...")

            else:
                Logger.error("Invalid menu choice", 
                            solution="Use 0-9 for valid options")
                input("Press Enter to try again.")





 

    @staticmethod
    def configure_proxychains(socks_ip, socks_port):

        config_file = "/etc/proxychains.conf"

        if not SystemUtils.file_exists(config_file):
            Logger.error("Proxychains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
            return False

        config_content = SystemUtils.read_file(config_file).splitlines()
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
            Logger.success("ProxyChains configuration updated successfully", 
                          details=f"Configured: socks5 {socks_ip}:{socks_port}")
            return True
        except Exception as e:
            Logger.error(f"Failed to write ProxyChains configuration: {str(e)}", 
                        solution="Check file permissions or disk space")
            return False
 




    @staticmethod
    def change_proxychain_dns_mode(mode):

        config_file = "/etc/proxychains.conf"

        if not SystemUtils.file_exists(config_file):
            Logger.error("Proxychains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
            return False

        try:
            current_config = SystemUtils.read_file(config_file)
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
                Logger.success("Proxy DNS mode set to proxy_dns", 
                              details=f"Configuration updated at: {config_file}")
            elif mode == "proxy_dns_old":
                # Enable proxy_dns_old and disable proxy_dns if exists
                if has_proxy_dns:
                    new_config = re.sub(r'(^|\n)(#?proxy_dns)(\n|$)', r'\1#proxy_dns\3', new_config)
                if has_proxy_dns_old:
                    new_config = re.sub(r'(^|\n)(#?proxy_dns_old)(\n|$)', r'\1proxy_dns_old\3', new_config)
                else:
                    new_config = "proxy_dns_old\n" + new_config.strip() + "\n"
                Logger.success("Proxy DNS mode set to proxy_dns_old", 
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
                    Logger.warning("No proxy DNS settings found to disable", 
                                  solution="Check existing settings in proxychains.conf")
                else:
                    Logger.success(f"{' and '.join(changes)} applied", 
                                  details=f"Configuration updated at: {config_file}")

            with open(config_file, "w") as f:
                f.write(new_config)
            return True

        except Exception as e:
            Logger.error(f"Failed to change Proxy DNS mode: {str(e)}", 
                        solution="Check file permissions or syntax in proxychains.conf", 
                        details=f"Mode attempted: {mode}")
            return False







    @staticmethod
    def change_quiet_mode():

        config_file = "/etc/proxychains.conf"

        if not SystemUtils.file_exists(config_file):
            Logger.error("Proxychains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
            return False

        try:
            current_config = SystemUtils.read_file(config_file)
            
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

            Logger.success(f"Quiet Mode {new_status}", 
                          details=f"New configuration written to: {config_file}")
            return True

        except Exception as e:
            Logger.error(f"Failed to toggle Quiet Mode: {str(e)}", 
                        solution="Check file permissions or syntax in proxychains.conf")
            return False




 
    @staticmethod
    def change_chain_mode(selected_mode):

        config_file = "/etc/proxychains.conf"
        supported_modes = ["dynamic_chain", "round_robin_chain", "random_chain", "strict_chain"]

        if selected_mode not in supported_modes:
            Logger.error(f"Invalid mode: {selected_mode}", 
                        solution=f"Supported modes: {', '.join(supported_modes)}")
            return False

        if not SystemUtils.file_exists(config_file):
            Logger.error("Proxychains configuration file not found!", 
                        solution="Verify file exists at /etc/proxychains.conf")
            return False

        backup_file = None
        try:
            original_config = SystemUtils.read_file(config_file)
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
                Logger.success(f"{selected_mode} mode activated successfully", 
                              details=f"Config file updated at: {config_file}")
                return True
            else:
                Logger.error(f"Failed to activate {selected_mode}", 
                            details=f"Active count: {active_count}, Expected: 1")
                return False

        except Exception as e:
            Logger.error(f"Error changing proxychains mode: {str(e)}", 
                        solution="Check file permissions or syntax in proxychains.conf",
                        details=f"Mode: {selected_mode}")

            if backup_file and os.path.exists(backup_file):
                with open(config_file, 'w') as file:  
                    with open(backup_file, 'r') as backup:
                        file.write(backup.read())
                Logger.warning("Configuration rolled back to backup", 
                              details=f"Backup file: {backup_file}")
            return False

        finally:

            if backup_file and os.path.exists(backup_file):
                os.remove(backup_file)
                Logger.success("Backup file removed", 
                              details=f"Backup: {backup_file} deleted successfully")





    @staticmethod
    def sync_proxychains_with_tor():
        config_file = "/etc/proxychains.conf"
        torrc_file = "/etc/tor/torrc"

        # Check if ProxyChains configuration file exists
        if not SystemUtils.file_exists(config_file):
            Logger.error("ProxyChains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
            input("Press Enter to return...")
            return False

        # Check if Tor is installed and Tor configuration file exists
        if not SystemUtils.is_installed("tor") or not SystemUtils.file_exists(torrc_file):
            Logger.error("Tor is not installed or Tor configuration file is missing!", 
                        solution="Install Tor and ensure /etc/tor/torrc exists")
            input("Press Enter to return...")
            return False

        socks_ip, socks_port = TorManager.get_tor_socks_info()
        if socks_ip in ("TORRC_NOT_FOUND", None) or socks_port in ("TORRC_NOT_FOUND", None):
            Logger.error("Tor Socks configuration is missing or invalid!", 
                        solution="Check SocksPort settings in /etc/tor/torrc")
            input("Press Enter to return...")
            return False

        # Read the ProxyChains configuration file
        try:
            with open(config_file, "r") as f:
                lines = f.readlines()
        except Exception as e:
            Logger.error(f"Failed to read ProxyChains config: {str(e)}", 
                        solution="Check file permissions")
            input("Press Enter to return...")
            return False

        proxylist_found = False
        new_lines = []
        i = 0
        duplicate_found = False

        # Process file line by line to find the [ProxyList] section
        while i < len(lines):
            line = lines[i]
            if line.strip() == "[ProxyList]":
                proxylist_found = True
                new_lines.append(line)
                i += 1
                section_lines = []
                # Collect all lines in the [ProxyList] section until a new section starts
                while i < len(lines) and lines[i].strip() and not lines[i].startswith("["):
                    section_lines.append(lines[i])
                    i += 1
                processed_section_lines = []
                # Process each line in the [ProxyList] section
                for proxy_line in section_lines:
                    parts = proxy_line.strip().split()
                    # Check only for socks5 lines
                    if len(parts) >= 3 and parts[0].lower() == "socks5":
                        # If the line matches the new Tor proxy details
                        if parts[1] == socks_ip and parts[2] == str(socks_port):
                            if "#tor" in proxy_line:
                                # Remove previously added Tor proxy line
                                continue
                            else:
                                # If a line with same details (without tag) exists, consider it as duplicate
                                duplicate_found = True
                        processed_section_lines.append(proxy_line)
                    else:
                        processed_section_lines.append(proxy_line)
                if duplicate_found:
                    Logger.error("Tor proxy is already configured in the file!", 
                                solution="Remove existing socks5 line manually before retrying")
                    input("Press Enter to return...")
                    return False
                # Append the processed lines of the [ProxyList] section
                new_lines.extend(processed_section_lines)
                # Append the new Tor proxy line at the end of the section
                new_lines.append(f"socks5 {socks_ip} {socks_port} #tor\n")
                # Append the rest of the file unchanged
                while i < len(lines):
                    new_lines.append(lines[i])
                    i += 1
                break  # Exit loop after processing [ProxyList]
            else:
                new_lines.append(line)
                i += 1

        # If no [ProxyList] section is found, add it at the end of the file
        if not proxylist_found:
            new_lines.append("\n[ProxyList]\n")
            new_lines.append(f"socks5 {socks_ip} {socks_port} #tor\n")

        # Create a backup of the configuration file
        backup_file = config_file + ".bak"
        try:
            shutil.copy(config_file, backup_file)
        except Exception as e:
            Logger.error(f"Failed to create backup: {str(e)}", 
                        solution="Check write permissions and disk space")
            input("Press Enter to return...")
            return False

        # Write the updated configuration back to the file safely
        try:
            with open(config_file, "w") as f:
                f.writelines(new_lines)
            Logger.success("ProxyChains successfully synced with Tor", 
                          details=f"Configured: socks5 {socks_ip}:{socks_port}")
        except Exception as e:
            Logger.error(f"Failed to update ProxyChains config: {str(e)}", 
                        solution="Check file permissions and try again")
            input("Press Enter to return...")
            return False

        input("Press Enter to return...")
        return True





    @staticmethod
    def add_proxy_to_chain(ip=None, port=None):

        config_file = "/etc/proxychains.conf"

        # Check if the configuration file exists
        if not SystemUtils.file_exists(config_file):
            Logger.error("ProxyChains configuration file not found!", 
                        solution="Verify the file exists at /etc/proxychains.conf")
            return False

        # Read the entire configuration file
        try:
            content = SystemUtils.read_file(config_file)
        except Exception as e:
            Logger.error(f"Failed to read ProxyChains config: {str(e)}", 
                        solution="Check file permissions")
            return False

        # Check if an active [ProxyList] section exists
        active_proxylist = any(
            line.strip().startswith("[ProxyList]") and not line.strip().startswith("#")
            for line in content.splitlines()
        )
        if not active_proxylist:
            Logger.error("ProxyList section not found or inactive in config!", 
                        solution="Add/enable the [ProxyList] section in proxychains.conf")
            return False

        # Prompt for proxy IP and Port using validators
        if not ip:
            # Loop until valid IP is entered
            while True:
                ip = Validator.prompt_for_ip("Enter Proxy IP: ")
                if ip is not None:
                    break
                Logger.warning("Please re-enter a valid IP address...")

        if not port:
            # Loop until valid Port is entered
            while True:
                port = Validator.prompt_for_port("Enter Proxy Port: ")
                if port is not None:
                    break
                Logger.warning("Please re-enter a valid port number...")

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
                    Logger.error("This Proxy already exists in configuration!", 
                                solution="Remove the duplicate entry first")
                    return False

        # Authentication details
        add_auth = InputUtils.get_confirmation("Do you want to add username and password for this proxy? (Y/n): ")
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
        ptype = InputUtils.get_user_input("Select type [1-3]: ", 
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
            Logger.success("Proxy added to ProxyChains configuration", 
                          details=f"Proxy: {proxy_line.strip()}")
            return True
        except Exception as e:
            Logger.error(f"Failed to update ProxyChains config: {str(e)}", 
                        solution="Check write permissions and disk space")
            return False





    @staticmethod
    def setup_proxychains_tor():
        SystemUtils.clear_screen()
        print("Setting up Proxychains + Tor...")

        confirm_deletion = InputUtils.get_confirmation(
            "\nThis will remove existing Tor and Proxychains installations."
            "\nDo you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): ")
        if not confirm_deletion:
            Logger.warning("Setup aborted by user. Returning to main menu.")
            input("Press Enter to return to the Auto Install menu...")
            return

        try:
            with NetworkUtils.temporary_dns() as success:
                if not success:
                    Logger.error("Skipping Tor installation due to repository connectivity issues.", 
                                solution="Check your internet connection and DNS settings")
                    return


                Remover.remove_tor()
                Remover.remove_proxychains()



                # Install ProxyChains
                if not Installer.install_proxychains():
                    Logger.error("ProxyChains installation failed. Cleaning up...", 
                                solution="Check dependencies or try reinstalling later")
                    Remover.remove_proxychains()
                    input("\nPress Enter to return to the Auto Install menu...")
                    return

                # Install Tor
                tor_installed = False
                try:
                    socks_ip, socks_port, dns_ip, dns_port = Installer.install_tor()
                    tor_installed = True
                except Exception as e:
                    Logger.error(f"Tor installation failed: {str(e)}", 
                                solution="Check Tor repository access and system architecture")
                    Remover.remove_proxychains()
                    Remover.remove_tor()
                    input("\nPress Enter to return to the Auto Install menu...")
                    return

                # Configure Proxychains
                try:
                    ProxychainsManager.configure_proxychains(socks_ip, socks_port)
                except Exception as e:
                    Logger.error("Proxychains configuration failed", 
                                solution=f"Check parameters: socks_ip={socks_ip}, socks_port={socks_port}")
                    Remover.remove_proxychains()
                    Remover.remove_tor()
                    input("\nPress Enter to return to the Auto Install menu...")
                    return

                # Cleanup temporary files
                if not SystemUtils.run_command("rm -rf proxychains-ng-4.17.tar.xz",
                                              "Failed to Remove proxychains-ng-4.17.tar.xz"):
                    Logger.warning("Temporary file cleanup failed", 
                                  details="Manual deletion may be required")

        except KeyboardInterrupt:
            Logger.warning("User interrupted installation! Rolling back changes...")
            Remover.remove_tor()
            Remover.remove_proxychains()
            Logger.success("Cleanup completed. Exiting...", details="Resources restored to initial state")
            input("\nPress Enter to return to the Auto Install menu...")
            return

        Logger.success("Proxychains + Tor setup completed successfully", 
                      details=f"Tor and Proxychains configured with:\n"
                              f"  • SOCKS IP: {socks_ip}:{socks_port}\n"
                              f"  • DNS IP: {dns_ip}:{dns_port}")

        input("\nPress Enter to return to the Auto Install menu...")
 
 
 
 
 

# -------------------- DnssonManager --------------------
class DnssonManager:



    @staticmethod
    def handle_dnsson_setup():
        # Dnsson Setup Handler: Manages the Dnsson setup menu and its operations.
        while True:
            MenuManager.display_dns_setup_menu()
            dns_choice = input("\nEnter your choice: ").strip()
            
            if dns_choice == '0':
                break

            elif dns_choice == '1':
                StatusManager.dnsson_status()
                input("\nPress Enter to Return...")

            elif dns_choice == '2':
                DnssonManager.install_dnsson()

            elif dns_choice == '3':
                DnssonManager.change_dnsson_destination()


            elif dns_choice == '4':
                DnssonManager.sync_dnsson_with_tor()

            elif dns_choice == '5':
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Remove DnsSon")
                print("=========================================\n")

                confirm_remove = InputUtils.get_confirmation(
                    "Warning: This will completely remove DnsSon .\n"
                    "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
                )
                if not confirm_remove:
                    Logger.warning("Removal aborted by user", solution="Re-run setup to try again")
                    input("Press Enter to Return...")
                    continue

                Remover.remove_dnsson()
                input("\nPress Enter to Return...")

            else:
                input("❌Invalid choice. Press Enter to try again.")




    @staticmethod
    def install_dnsson():
        SystemUtils.clear_screen()
        print("=========================================")
        print("         Installing DnsSon")
        print("=========================================\n")

        # Check if dnsson script already exists
        script_path = "/usr/local/bin/dnsson"
        if SystemUtils.file_exists(script_path):
            choice = InputUtils.get_confirmation(
                "DnsSon script already exists. \nDo you want to remove it before installation?" "(Press Enter for confirmation, or type 'n' or 'no' to cancel): ")
            if not choice:
                Logger.warning("Installation aborted. Existing script remains unchanged.")
                input("Press Enter to return to the menu...")
                return
            else:
                try:
                    os.remove(script_path)
                    Logger.success("Previous DnsSon script removed successfully.")
                except Exception as e:
                    Logger.error(f"Error removing previous script: {e}", 
                                solution="Check file permissions or try again with sudo")
                    input("Press Enter to return to the menu...")
                    return

        try:
            dns_ip, dns_port = None, None
            sync_choice = InputUtils.get_confirmation("🔗 Sync with Tor? (Y/n): ")
            if sync_choice:
                dns_ip, dns_port = TorManager.get_tor_dns_info()
                if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
                    Logger.warning("Invalid Tor DNS configuration. Switching to manual input.", 
                                  solution="Check Tor's torrc file for DNSPort settings")
                    sync_choice = False

            if not sync_choice:
                # Loop until valid IP is entered
                while True:
                    dns_ip = Validator.prompt_for_ip("🌐 Enter DNS IP (e.g. 127.45.67.89): ")
                    if dns_ip is not None:
                        break
                    Logger.warning("Please re-enter a valid DNS IP address...")

                # Loop until valid Port is entered
                while True:
                    dns_port = Validator.prompt_for_port("🔢 Enter DNS Port (e.g. 5353): ")
                    if dns_port is not None:
                        break
                    Logger.warning("Please re-enter a valid DNS port number...")

            try:
                DnssonManager.create_dnsson_script(dns_ip, dns_port)
                Logger.success("DnsSon installed and configured successfully", 
                              details=f"Iptables settings:\n"
                                      f"  - Destination DNAT: {dns_ip}:{dns_port}\n"
                                      f"  - Nameserver set to: {dns_ip}")
            except Exception as e:
                Logger.error(f"Error installing DnsSon: {str(e)}", 
                            solution="Check DNS format and script permissions")
                input("Press Enter to return to the menu...")
                return

        except KeyboardInterrupt:
            Logger.warning("User interrupted the installation! Rolling back changes...")
            if SystemUtils.file_exists(script_path):
                os.remove(script_path)
            Logger.success("Cleanup completed. Exiting...", context="All temporary files removed")

        input("\nPress Enter to return to the menu...")
     
 
 
 
 
 
    @staticmethod
    def sync_dnsson(dns_ip, dns_port):
        file_path = "/usr/local/bin/dnsson"
        if not SystemUtils.file_exists(file_path):
            return False

        if dns_ip is None or dns_port is None:
            Logger.warning("Invalid DNSPort configuration. Skipping DnsSon sync.", 
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







    @staticmethod
    def sync_dnsson_with_tor():
        file_path = "/usr/local/bin/dnsson"
        torrc_file = "/etc/tor/torrc"
        if not SystemUtils.file_exists(file_path):
            Logger.error("DnsSon not installed!", solution="Install DnsSon first")
            input("Press Enter to return...")
            return

        if not SystemUtils.is_installed("tor") or not SystemUtils.file_exists(torrc_file):
            Logger.error("Tor is not installed or Tor configuration missing!", 
                        solution="Install Tor and ensure torrc exists")
            input("Press Enter to return...")
            return

        dns_ip, dns_port = TorManager.get_tor_dns_info()

        if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
            Logger.error("Tor DNS configuration invalid!", 
                        solution="Check DNSPort settings in torrc")
            input("Press Enter to return...")
            return

        if DnssonManager.sync_dnsson(dns_ip, dns_port):
            Logger.success("DnsSon synchronized with Tor", 
                          details=f"DNS: {dns_ip}:{dns_port}")
        else:
            Logger.error("Synchronization failed", 
                        solution="Retry with valid DNS settings")

        input("Press the Enter button to return to the menu...")







    @staticmethod
    def change_dnsson_destination():
        if not SystemUtils.file_exists("/usr/local/bin/dnsson"):
            Logger.error("DnsSon not installed!", solution="Install DnsSon first")
            input("Press the Enter button to return to the menu...")
            return

        # Loop until valid DNS IP is entered
        dns_ip = None
        while dns_ip is None:
            dns_ip = Validator.prompt_for_ip("Enter new DNS IP: ")

        # Loop until valid DNS Port is entered
        dns_port = None
        while dns_port is None:
            dns_port = Validator.prompt_for_port("Enter new DNS Port: ")

        if DnssonManager.sync_dnsson(dns_ip, dns_port):
            Logger.success("DnsSon destination updated", 
                          details=f"New DNS: {dns_ip}:{dns_port}")
        else:
            Logger.error("Failed to update DnsSon destination", 
                        solution="Check DNS format and permissions")

        input("Press the Enter button to return to the menu...")

 
 
 
 
    @staticmethod
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
1,\$d
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

FORCE_KILL=0
handle_sigint() {{
    FORCE_KILL=$((FORCE_KILL+1))
    if [ "$FORCE_KILL" -eq 1 ]; then
         log "${{BLUE}}SIGINT received, sending SIGTERM to command group...${{RESET}}"
         kill -TERM -$CHILD_PID 2>/dev/null || true
    else
         log "${{RED}}Second SIGINT received, sending SIGKILL to command group...${{RESET}}"
         kill -KILL -$CHILD_PID 2>/dev/null || true
    fi
}}
trap handle_sigint SIGINT

log "${{BLUE}}Running Command: $*${{RESET}}"
( exec "$@" ) &
CHILD_PID=$!
wait $CHILD_PID
CMD_STATUS=$?

exit $CMD_STATUS
"""
        with open(script_path, "w") as script_file:
            script_file.write(script_content)
        SystemUtils.run_command(f"sudo chmod 750 {script_path}", "Failed to make dnsson executable.")
        print("dnsson script created and configured successfully.")
 
 
 
 
 
 
 
 
 # -------------------- ProxysonManager --------------------
class ProxysonManager:


    @staticmethod
    def handle_proxyson_setup():
        # ProxySon Setup Handler: Manages the ProxySon setup menu and its operations.
        while True:
            MenuManager.display_proxy_setup_menu()
            proxy_choice = input("\nSelect an option [0-6]: ").strip()
            
            if proxy_choice == '0':
                break
            elif proxy_choice == '1':
                StatusManager.proxyson_status()
                input("\nPress Enter to Return...")

            elif proxy_choice == '2':
                ProxysonManager.install_proxyson()
                
            elif proxy_choice == '3':
                ProxysonManager.change_proxyson_destination()
 
            elif proxy_choice == '4':
                ProxysonManager.change_proxyson_command()
                
            elif proxy_choice == '5':
                ProxysonManager.sync_proxyson_with_tor()

            elif proxy_choice == '6':
                SystemUtils.clear_screen()
                print("=========================================")  # Preserve menu borders
                print("            Remove ProxySon")
                print("=========================================\n")

                confirm_remove = InputUtils.get_confirmation(
                    "Warning: This will completely remove ProxySon .\n"
                    "Do you want to proceed? (Press Enter for confirmation, or type 'n' or 'no' to cancel): "
                )
                if not confirm_remove:
                    Logger.warning("Removal aborted by user", solution="Re-run setup to try again")
                    input("Press Enter to Return...")
                    continue

                Remover.remove_proxyson()
                input("\nPress Enter to Return...")
            else:
                input("❌Invalid choice. Press Enter to try again.")


 
 
    @staticmethod
    def install_proxyson():
        SystemUtils.clear_screen()
        print("=========================================")
        print("         INSTALL PROXYSON".center(40))
        print("=========================================\n")
        
        # Check if proxyson script already exists
        script_path = "/usr/local/bin/proxyson"
        if SystemUtils.file_exists(script_path):
            choice = InputUtils.get_confirmation("⚠️ ProxySon already exists! Overwrite? (Y/n):")
            if not choice:
                Logger.warning("Installation aborted. Existing script remains unchanged.")
                input("Press Enter to return to the menu...")
                return
            else:
                try:
                    os.remove(script_path)
                    Logger.success("Previous PROXYSON script removed successfully.")
                except Exception as e:
                    Logger.error(f"Error removing previous script: {e}")
                    input("Press Enter to return to the menu...")
                    return

        try:
            # DNS 
            dns_ip, dns_port = None, None
            sync_choice = InputUtils.get_confirmation("🔗 Sync with Tor? (Y/n): ")
            if sync_choice:
                dns_ip, dns_port = TorManager.get_tor_dns_info()
                if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
                    Logger.warning("Invalid Tor DNS configuration. Switching to manual input.")
                    sync_choice = False

            if not sync_choice:
                # Loop until valid DNS IP is entered
                dns_ip = None
                while dns_ip is None:
                    dns_ip = Validator.prompt_for_ip("🌐 Enter DNS IP (e.g. 127.45.67.89): ")

                # Loop until valid DNS Port is entered
                dns_port = None
                while dns_port is None:
                    dns_port = Validator.prompt_for_port("🔢 Enter DNS Port (e.g. 5353): ")


            base_cmd = InputUtils.get_user_input(
                "⌨️ Enter base command (default: socksify): ",
                default="socksify",
                validator=lambda x, _: bool(x.strip())
            )

            try:
                ProxysonManager.create_proxyson_script(
                    dns_ip=dns_ip,
                    dns_port=dns_port,
                    base_command=base_cmd.strip()
                )
                Logger.success("ProxySon installed successfully!", 
                              details=f"DNS: {dns_ip}:{dns_port} | Command: {base_cmd}")

            except Exception as e:
                Logger.error(f"Error installing ProxySon: {str(e)}", 
                            solution="Try again with valid DNS settings")
                input("Press Enter to return to the menu...")
                return

        except KeyboardInterrupt:
            Logger.warning("User interrupted the installation! Rolling back changes...")
            if SystemUtils.file_exists(script_path):
                os.remove(script_path)
            Logger.success("Cleanup completed. Exiting...", details="All temporary files removed")

        input("\nPress Enter to return to the menu...")







 
    @staticmethod
    def sync_proxyson(dns_ip, dns_port):
        file_path = "/usr/local/bin/proxyson"
        if not SystemUtils.file_exists(file_path):
            return False

        if dns_ip is None or dns_port is None:
            Logger.warning("Invalid DNSPort configuration. Skipping Proxyson sync.")
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





    @staticmethod
    def sync_proxyson_with_tor():
        torrc_file = "/etc/tor/torrc"
        if not SystemUtils.file_exists("/usr/local/bin/proxyson"):
            Logger.error("ProxySon not installed!")
            input("\nPress Enter to return...")
            return

        if not SystemUtils.is_installed("tor") or not SystemUtils.file_exists(torrc_file):
            Logger.error("Tor is not installed or Tor configuration file is missing!")
            input("Press Enter to return...")
            return

        dns_ip, dns_port = TorManager.get_tor_dns_info()

        if dns_ip in ("TORRC_NOT_FOUND", None) or dns_port in ("TORRC_NOT_FOUND", None):
            Logger.error("Tor DNS configuration is missing or invalid!")
            input("Press Enter to return...")
            return

        if ProxysonManager.sync_proxyson(dns_ip, dns_port):
            Logger.success("ProxySon synchronized with Tor successfully.", details=f"DNS: {dns_ip}:{dns_port}")
        else:
            Logger.error("Failed to synchronize ProxySon with Tor.")

        input("Press the Enter button to return to the menu...")






    @staticmethod
    def change_proxyson_destination():
        if not SystemUtils.file_exists("/usr/local/bin/proxyson"):
            Logger.error("ProxySon not installed!", solution="Install ProxySon first")
            input("\nPress Enter to return...")
            return

        # Loop until valid DNS IP is entered
        dns_ip = None
        while dns_ip is None:
            dns_ip = Validator.prompt_for_ip("Enter new DNS IP: ")

        # Loop until valid DNS Port is entered
        dns_port = None
        while dns_port is None:
            dns_port = Validator.prompt_for_port("Enter new DNS Port: ")

        if ProxysonManager.sync_proxyson(dns_ip, dns_port):
            Logger.success("Destination updated!", details=f"New DNS: {dns_ip}:{dns_port}")
        else:
            Logger.error("Failed to update!", solution="Check DNS format and permissions")

        input("\nPress Enter to return...")





    @staticmethod
    def change_proxyson_command():
        script_path = "/usr/local/bin/proxyson"
        if not SystemUtils.file_exists(script_path):
            Logger.error("ProxySon not installed!", solution="Install ProxySon first using the setup menu")
            input("\nPress Enter to return...")
            return

        new_cmd = InputUtils.get_user_input(
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
            r'(exec\s+)(\S+)(\s+"\$@")',
            rf'\g<1>{new_cmd}\g<3>',
            content
        )
        
        try:
            with open(script_path, "w") as f:
                f.write(content)
            Logger.success("Command updated successfully", 
            details=f"New command: {new_cmd}")
        except Exception as e:
            Logger.error(f"Failed to update command: {str(e)}", solution="Check script permissions")
            input("\nPress Enter to return...")
            return
        
        input("\nPress Enter to return...")
 
 
 
 
 
    @staticmethod
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
1,\$d
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
FORCE_KILL=0
handle_sigint() {{
    FORCE_KILL=$((FORCE_KILL+1))
    if [ "$FORCE_KILL" -eq 1 ]; then
         log "${{BLUE}}SIGINT received, sending SIGTERM to command group...${{RESET}}"
         kill -TERM -$CHILD_PID 2>/dev/null || true
    else
         log "${{RED}}Second SIGINT received, sending SIGKILL to command group...${{RESET}}"
         kill -KILL -$CHILD_PID 2>/dev/null || true
    fi
}}
trap handle_sigint SIGINT

( exec {base_command} "$@" ) &
CHILD_PID=$!
wait $CHILD_PID
CMD_STATUS=$?

exit $CMD_STATUS
"""
        with open(script_path, "w") as script_file:
            script_file.write(script_content)
        SystemUtils.run_command(f"sudo chmod 750 {script_path}", "Failed to make proxyson executable.")
        print("proxyson script created and configured successfully.")



 
 


# -------------------- Menu Manager --------------------
class MenuManager:





    @staticmethod
    def display_main_menu():
        SystemUtils.clear_screen()
        
        script_version = "v1.0 (Initial Release)"
        github_link    = "Github.com/Kalilovers"
        

        print(f"\n{color.VERSION_COLOR}Version : {script_version}{color.RESET}")
        print(f"{color.VERSION_COLOR}GitHub  : {github_link}{color.RESET}\n")
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' SONCHAIN MANAGER '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | Status",
            "2 | Auto Setup",
            "3 | Tor Setup",
            "4 | Dante'Socksify' Setup",
            "5 | ProxyChains Setup",
            "6 | DnsSon Setup",
            "7 | ProxySon Setup",
            "8 | Uninstall"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Exit'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")
       








    @staticmethod
    def display_status_menu():
        while True:
            try:
                SystemUtils.clear_screen()
                

                print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
                print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' STATUS MENU '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
                print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
                

                menu_items = [
                    "1 | Tor Status",
                    "2 | Socksify Status",
                    "3 | ProxyChains Status",
                    "4 | ProxySon Status",
                    "5 | DnsSon Status"
                ]
                
                for item in menu_items:
                    print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
                

                print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
                print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
                print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")

                choice = input("Enter your choice: ").strip()

                if choice == '0':
                    break

                elif choice == '1':
                    StatusManager.tor_status()

                    input("\nPress Enter to Return...")
                    continue

                elif choice == '2':
                    StatusManager.dante_status()
                    input("\nPress Enter to Return...")
                    continue

                elif choice == '3':
                    StatusManager.proxychains_status()
                    input("\nPress Enter to Return...")
                    continue

                elif choice == '4':
                    StatusManager.proxyson_status()
                    input("\nPress Enter to Return...")
                    continue

                elif choice == '5':
                    StatusManager.dnsson_status()
                    input("\nPress Enter to Return...")
                    continue

                else:
                    input("\n❌Invalid choice! Press 'Enter' to try again...")
                    continue

            except KeyboardInterrupt:
                print("\nCancelled by user.")
                print("Son Says GoodBye!")
                sys.exit(0)






    @staticmethod
    def display_auto_setup_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' AUTO SETUP MENU '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | Setup Dante|Socksify + Tor",
            "2 | Setup ProxyChains + Tor"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")






    @staticmethod
    def display_setup_tor_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' TOR SETUP MENU '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | Tor Status",
            "2 | Install Tor",
            "3 | Manual Configuration",
            "4 | Stop Tor",
            "5 | Restart Tor",
            "6 | Remove Tor"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Back'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")







    @staticmethod
    def display_dante_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' DANTE (SOCKSIFY) SETUP '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | Socksify Status",
            "2 | Install Socksify",
            "3 | Edit Configuration",
            "4 | Change SOCKS IP/Port",
            "5 | Change DNS Protocol",
            "6 | Sync with Tor",
            "7 | Remove Socksify"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")







    @staticmethod
    def display_proxychains_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*41}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' PROXYCHAINS SETUP '.center(41)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*41}╣{color.RESET}")
        

        menu_items = [
            "1 | Status",
            "2 | Install ProxyChains",
            "3 | Edit Configuration File",
            "4 | Change Chain Type (Strict/Dynamic)",
            "5 | Change Quiet Mode (Active/InActive)",
            "6 | Change DNS_Proxy Mode",
            "7 | Add Custom Proxy",
            "8 | Sync with Tor",
            "9 | Remove ProxyChains"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(39)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*41}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(36)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*41}╝{color.RESET}")





    @staticmethod
    def display_proxy_setup_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' PROXYSON SETUP MENU '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | ProxySon Status",
            "2 | Install ProxySon",
            "3 | Change Destination",
            "4 | Change Command",
            "5 | Sync with Tor",
            "6 | Remove ProxySon"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")





    @staticmethod
    def display_dns_setup_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' DNSSON SETUP MENU '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | DnsSon Status",
            "2 | Install DnsSon",
            "3 | Change Destination",
            "4 | Synchronize With Tor",
            "5 | Remove DnsSon"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")






    @staticmethod
    def display_uninstall_menu():
        SystemUtils.clear_screen()
        

        print(f"{color.BORDER_COLOR}╔{'═'*32}╗{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.HEADER_COLOR}{' ADVANCED UNINSTALLER '.center(32)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        

        menu_items = [
            "1 | Remove Socksify (Socksify)",
            "2 | Remove Tor",
            "3 | Remove ProxyChains",
            "4 | Remove DnsSon",
            "5 | Remove ProxySon",
            "6 | Remove Sonchain Script"
        ]
        
        for item in menu_items:
            print(f"{color.BORDER_COLOR}║ {color.ITEM_COLOR}{item.ljust(30)}{color.RESET} {color.BORDER_COLOR}║{color.RESET}")
        

        print(f"{color.BORDER_COLOR}╠{'═'*32}╣{color.RESET}")
        print(f"{color.BORDER_COLOR}║{color.RESET} 0 | {color.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{color.RESET}{color.BORDER_COLOR}║{color.RESET}")
        print(f"{color.BORDER_COLOR}╚{'═'*32}╝{color.RESET}")







    @staticmethod
    def handle_uninstall():
        while True:
            MenuManager.display_uninstall_menu()
            choice = input("\nSelect an option [0-5]: ").strip()
            results = {}
            
            if choice == '0':
                return
            elif choice == '1':
                results['Socksify'] = Remover.remove_dante()
            elif choice == '2':
                results['Tor'] = Remover.remove_tor()
            elif choice == '3':
                results['ProxyChains'] = Remover.remove_proxychains()
            elif choice == '4':
                results['DnsSon'] = Remover.remove_dnsson()
            elif choice == '5':
                results['ProxySon'] = Remover.remove_proxyson()
            elif choice == '6':
                print("\n" + "═"*40)
                success = Remover.uninstall_script()
                
                if success:
                    print("\n✅ Uninstall completed successfully!")
                    sys.exit(0)
                else:
                    print("\n⚠️ Uninstall completed with warnings!")

            else:
                input("❌Invalid choice! Press 'Enter' to continue ...")
                continue

            if results:
                print("\n" + "═"*40)
                print("🚮 REMOVAL SUMMARY".center(40))
                print("═"*40)
                for component, status in results.items():
                    icon = "✔️" if status else "❌"
                    status_text = "Successful" if status else "Completed with Warnings"
                    print(f"{icon} {component.ljust(15)}: {status_text}")
                print("═"*40)
            
            input("\nPress Enter to Return...")








    @staticmethod
    def main():
        if os.geteuid() != 0:
            print("⚠️ This script requires root access. Please run with 'sudo' .")
            sys.exit(1)

        while True:
            try:
                MenuManager.display_main_menu()
                choice = input("\nEnter your choice: ").strip()

                #----------------------------------Status-------------------------------------------
                if choice == '1':
                    MenuManager.display_status_menu()

                #----------------------------------Auto setup-------------------------------------------
                elif choice == '2':
                    while True:
                        MenuManager.display_auto_setup_menu()
                        sub_choice = input("\nEnter your choice: ").strip()
                        if sub_choice == '1':
                            DanteManager.setup_dante_tor()
                        elif sub_choice == '2':
                            ProxychainsManager.setup_proxychains_tor()
                        elif sub_choice == '0':
                            break  # Return to the main menu
                        else:
                            print("Invalid choice. Please try again.")
                            input("Press Enter to continue...")


                #----------------------------------Tor Setup-------------------------------------------
                elif choice == '3':  # Tor Setup
                    TorManager.handle_tor_setup()

                #----------------------------------Dante (Socksify) Setup-------------------------------------------
                elif choice == '4':  # Dante Setup
                    DanteManager.handle_dante_menu()

                #----------------------------------Proxychains Setup-------------------------------------------
                elif choice == '5': 
                    ProxychainsManager.handle_proxychains_menu()

                #----------------------------------DnsSon Setup-------------------------------------------
                elif choice == '6':  # DnsSon Setup
                    DnssonManager.handle_dnsson_setup()

                #----------------------------------ProxySon Setup-------------------------------------------
                elif choice == '7':  # ProxySon Setup
                    ProxysonManager.handle_proxyson_setup()

                #----------------------------------Uninstall-------------------------------------------
                elif choice == '8':
                    MenuManager.handle_uninstall()

                #----------------------------------Exit-------------------------------------------
                elif choice == '0':
                    print("Sonchain Exited...")
                    break

                else:
                    input("❌Invalid choice. Press Enter to try again.")

            except KeyboardInterrupt:
                print("\n\nSonchain says goodbye...\n")
                sys.exit(0)

if __name__ == "__main__":
    if "--uninstall" in sys.argv:
        if os.geteuid() != 0:
            print("Please run with sudo!")
            sys.exit(1)
        Remover.uninstall_script()
        sys.exit(0)
    else:
        MenuManager.main()
