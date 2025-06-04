#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_utils
from src import src_tor
from src import src_psiphon
#modules >
import os
import re
import signal
import subprocess
import sys
import threading
import time
import json
from typing import List, Dict


# -------------------- Status Manager --------------------






def test_connectivity(
    tests: List[Dict],
    require_all: bool = True,
    global_timeout: int = 30,
    kill_patterns: List[str] = None
) -> bool:
    original_sigint = signal.signal(signal.SIGINT, lambda sig, frame: None)
    results = []
    processes = []
    cancelled = threading.Event()
    lock = threading.Lock()


    with lock:
        print("\n Connection Status:")

        sys.stdout.write(f"\n{src_utils.RED}  ⛔️Warning{src_utils.RESET}\n{src_utils.YELLOW}   |Cancel While Testing may cause problems!{src_utils.RESET}  \n{src_utils.YELLOW}   |Wait for safe termination...{src_utils.RESET}\n")
        sys.stdout.flush()

        sys.stdout.write(f"\n{src_utils.BORDER_COLOR}  │{src_utils.RESET}⏳ Running {len(tests)} tests...\n")
        sys.stdout.flush()

    def run_single_test(test_config: Dict, index: int):
        nonlocal processes
        result = False
        process = None
        
        try:
            with lock:
                if cancelled.is_set():
                    return
                sys.stdout.write(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}⚡ Test {index+1}: Starting...\n")
                sys.stdout.flush()

            process = subprocess.Popen(
                test_config['cmd'],
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                preexec_fn=os.setsid
            )
            processes.append(process)
            
            output, _ = process.communicate(timeout=test_config.get('timeout', 10))
            result = test_config['success_indicator'].lower() in output.lower()

            if not cancelled.is_set():
                with lock:
                    sys.stdout.write(f"\033[1A\r\033[K{src_utils.BORDER_COLOR}  │{src_utils.RESET}⚡ Test {index+1}: ")
                    sys.stdout.write(f"✅ Succeeded\n" if result else f"❌ Failed\n")

        except subprocess.TimeoutExpired:
            if not cancelled.is_set():
                with lock:
                    sys.stdout.write(f"\033[1A\r\033[K{src_utils.BORDER_COLOR}  │{src_utils.RESET}⚡ Test {index+1}: ⏰ Timeout\n")
            result = False
        except Exception as e:
            result = False
        finally:
            if process:
                processes.remove(process)
            results.append(result)

    threads = []
    for i, test in enumerate(tests):
        t = threading.Thread(target=run_single_test, args=(test, i))
        threads.append(t)
        t.start()

    try:
        start_time = time.time()
        while time.time() - start_time < global_timeout:
            if all(not t.is_alive() for t in threads):
                break
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        if not cancelled.is_set():
            cancelled.set()
            with lock:
                sys.stdout.write(f"\n{src_utils.RED}⚠️ Warning, canceling may cause problems with the DNS , Wait Afew seconds for safe termination!...{src_utils.RESET}")
                sys.stdout.write(f"\n{src_utils.YELLOW}⚠️If a problem occurs About the DNS  > reboot the server{src_utils.RESET}\n")
                sys.stdout.flush()

            for p in processes.copy():
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGINT)
                except ProcessLookupError:
                    pass

            return False
    finally:
        signal.signal(signal.SIGINT, original_sigint)


    if cancelled.is_set():
        return False

    final_success = all(results) if require_all else any(results)


    if not cancelled.is_set():
        with lock:
            print(f"\n{src_utils.BORDER_COLOR}  │{src_utils.RESET}📊 Final Result: ", end="")
            if final_success:
                print(f"✅ All Tests succeeded" if require_all else "✅ At least one test succeeded")
            else:
                print(f"❌ All Tests Failed" if require_all else "❌ Some Tests Failed")

    return final_success





def tor_status():
    src_utils.clear_screen()
    status_data = {
        'service': " 🔍Tor Service",
        'config': "⚙️Tor Configuration",
    }
    


    print(f"{src_utils.BORDER_COLOR}╔{'═'*42}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🧦TOR STATUS'.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*42}╣{src_utils.RESET}")


    if not src_utils.is_installed("tor"):
        print(f"\n{status_data['service']}: ❌Not Installed")
        return
    
    if not src_utils.file_exists("/etc/tor/torrc"):
        print(f"\n{status_data['config']}: ❌Missing torrc file")
        return
    

    service_check = subprocess.run("systemctl is-active tor", shell=True, capture_output=True, text=True)
    print(f"\n{status_data['service']}: {'✅Running' if service_check.returncode == 0 else '❌Not Running'}")



    socks_ip, socks_port = src_tor.get_tor_socks_info()
    if socks_ip == "TORRC_NOT_FOUND" or socks_port == "TORRC_NOT_FOUND":
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}SOCKS Proxy: ❌torrc file not found!")
    elif socks_ip is None or socks_port is None:
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}SOCKS Proxy: ❌Invalid configuration")
    else:
        print(f"\n SOCKS Proxy Settings:")
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ SOCKS IP: {socks_ip}")
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ SOCKS Port: {socks_port}")


    dns_ip, dns_port = src_tor.get_tor_dns_info()
    if dns_ip == "TORRC_NOT_FOUND" or dns_port == "TORRC_NOT_FOUND":
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}DNS Proxy: ❌torrc file not found!")
    elif dns_ip is None or dns_port is None:
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}DNS Proxy: ❌Invalid configuration")
    else:
        print(f"\n DNS Proxy Settings:")
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ DNS IP: {dns_ip}")
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ DNS Port: {dns_port}")



    tor_config = src_utils.read_file("/etc/tor/torrc")
    automap_status = "✅Active" if "AutomapHostsOnResolve 1" in tor_config else "❌Inactive"
    VirtualAddrNetworkIPv4_status = "✅Active" if "VirtualAddrNetworkIPv4" in tor_config else "❌Inactive"
    lognotice_status = "✅Active /var/log/tor/notice.log" if "Log notice file /var/log/tor/notice.log" in tor_config else "📋Inactive Or Other Path"
    print(f"\n General Settings:")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ VirtualAddrNetworkIPv4 : {VirtualAddrNetworkIPv4_status}")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ AutomapHosts: {automap_status}")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Log : {lognotice_status}")
    

    print(f"\n{src_utils.BOLD}🛠 ADVANCED SETTINGS:{src_utils.RESET}")

    def show_setting(label, pattern, transform=lambda v: v.strip(), show_if_absent=False):
        match = re.search(rf"^\s*{pattern}\s+(.*)", tor_config, re.IGNORECASE | re.MULTILINE)
        if match:
            value = transform(match.group(1))
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ {label.ljust(22)}: {src_utils.GREEN}✅ {value}{src_utils.RESET}")
        elif show_if_absent:
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ {label.ljust(22)}: {src_utils.RED}❌ Not Set{src_utils.RESET}")

    print(f"\n {src_utils.BOLD}◼ Routing Nodes:{src_utils.RESET}")
    show_setting("EntryNodes", r"EntryNodes\s+\{(.*?)\}", transform=lambda v: f"{{{v}}}")
    show_setting("ExitNodes", r"ExitNodes\s+\{(.*?)\}", transform=lambda v: f"{{{v}}}")
    show_setting("StrictEntryNodes", r"StrictEntryNodes\s+(1)", transform=lambda v: "Enabled", show_if_absent=True)
    show_setting("StrictExitNodes", r"StrictExitNodes\s+(1)", transform=lambda v: "Enabled", show_if_absent=True)

    print(f"\n {src_utils.BOLD}◼ Exclusions:{src_utils.RESET}")
    show_setting("ExcludeEntryNodes", r"ExcludeEntryNodes\s+\{(.*?)\}", transform=lambda v: f"{{{v}}}")
    show_setting("ExcludeExitNodes", r"ExcludeExitNodes\s+\{(.*?)\}", transform=lambda v: f"{{{v}}}")
    show_setting("ExcludeNodes", r"ExcludeNodes\s+\{(.*?)\}", transform=lambda v: f"{{{v}}}")
    show_setting("StrictNodes", r"StrictNodes\s+(1)", transform=lambda v: "Enabled", show_if_absent=True)

    print(f"\n {src_utils.BOLD}◼ Guards Settings:{src_utils.RESET}")
    show_setting("NumEntryGuards", r"NumEntryGuards\s+(\d+)", show_if_absent=True)
    show_setting("NumDirectoryGuards", r"NumDirectoryGuards\s+(\d+)", show_if_absent=True)


    if src_utils.file_exists("/var/log/tor/notice.log"):
        log_content = src_utils.read_file("/var/log/tor/notice.log")
        if "Error" in log_content or "Failed" in log_content:
            print("\n⚠️ Recent Errors in Tor Logs:")
            errors = [line for line in log_content.split('\n') if "Error" in line or "Failed" in line][-3:]
            for err in errors:
                print(f"▸ {err[:60]}...")


    if socks_ip in (None, "TORRC_NOT_FOUND") or socks_port in (None, "TORRC_NOT_FOUND"):
        print(f"\n{src_utils.BORDER_COLOR}🛜  Connection Test Skipped: Invalid SOCKS configuration{src_utils.RESET}")
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Status: {src_utils.RED}❌ Cannot test without valid SOCKS IP and Port{src_utils.RESET}")
    else:
        print(f"\n{src_utils.BORDER_COLOR}🛜  Testing Connection, please wait...{src_utils.RESET}")

        connection_status = src_utils.get_connection_status(
            proxy_ip=socks_ip,
            proxy_port=socks_port,
            protocol="socks5h"
        )

        if connection_status["status"] == "error":
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Status: {src_utils.RED}❌ ERROR")
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Message: {src_utils.RED}{connection_status.get('message', 'Unknown error')}{src_utils.RESET}")

        elif connection_status["status"] == "disconnected":
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Status: {src_utils.RED}❌ NOT CONNECTED{src_utils.RESET}")

        elif connection_status["status"] == "connected":
            ip = connection_status.get("ip", "Unknown")
            region = connection_status.get("region", "Unknown")
            service = connection_status.get("service", "Unknown")
            protocol_used = connection_status.get("protocol", "Unknown")

            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Status: {src_utils.GREEN}✅ CONNECTED{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Server IP: {src_utils.GREEN}{ip}{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Server Region: {src_utils.GREEN}{region}{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Test Service: {src_utils.GREEN}{service}{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Test Protocol: {src_utils.GREEN}{protocol_used}{src_utils.RESET}")



    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*42}╝{src_utils.RESET}")





def dnsson_status():
    src_utils.clear_screen()


    print(f"{src_utils.BORDER_COLOR}╔{'═'*42}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🧦DNSSON STATUS'.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*42}╣{src_utils.RESET}")




    script_path = "/usr/local/bin/dnsson"
    if not src_utils.file_exists(script_path):
        print("\n❌ Not Installed")
        return
    
    content = src_utils.read_file(script_path)
    dest_match = re.search(r'--to-destination\s+([\d\.]+:\d+)', content)
    ns_match = re.search(r'nameserver\s+([\d\.]+)', content)
    
    print("\n ✅Installed | Settings:")
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Destination: {dest_match.group(1) if dest_match else '❌Not found'}")
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Nameserver: {ns_match.group(1) if ns_match else '❌Not found'}")
    

    iptables_check = subprocess.run(
        "sudo iptables -t nat -L OUTPUT | grep DNAT",
        shell=True,
        capture_output=True,
        text=True
    )
    if "DNAT" in iptables_check.stdout:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ IPTables Rules: ✅Active-In Use")
    else:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ IPTables Rules: 🔌Not Active")


    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*42}╝{src_utils.RESET}")







def proxyson_status():
    src_utils.clear_screen()


    print(f"{src_utils.BORDER_COLOR}╔{'═'*42}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🧦PROXYSON STATUS'.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*42}╣{src_utils.RESET}")


    script_path = "/usr/local/bin/proxyson"
    if not src_utils.file_exists(script_path):
        print("\n❌ Not Installed")
        return
    
    content = src_utils.read_file(script_path)
    dest_match = re.search(r'--to-destination\s+([\d\.]+:\d+)', content)
    cmd_match = re.search(r'^\s*(\S+)\s+"\$@"\s*$', content, re.MULTILINE)
    
    print("\n ✅Installed | Settings:")
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Destination: {dest_match.group(1) if dest_match else '❌Not found'}")
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Command: {cmd_match.group(1) if cmd_match else '❌Not found'}")



    iptables_check = subprocess.run(
        "sudo iptables -t nat -L OUTPUT | grep DNAT",
        shell=True,
        capture_output=True,
        text=True
    )
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ IPTables Rules:","✅Active-In Use" if "DNAT" in iptables_check.stdout else "🔌Not Active")


    success = test_connectivity(
        tests=[
            {
                'cmd': 'proxyson nc -z -v -w5 1.1.1.1 80',
                'success_indicator': 'succeeded',
                'timeout': 5
            }
        ],
        require_all=True,
        global_timeout=10,
        kill_patterns=['proxyson']
    )


    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*42}╝{src_utils.RESET}")








def dante_status():
    src_utils.clear_screen()

    print(f"{src_utils.BORDER_COLOR}╔{'═'*42}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🧦Socksify STATUS'.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*42}╣{src_utils.RESET}")

    if not src_utils.is_installed("dante-client"):
        print("❌ Not Installed")
        return

    config_path = "/etc/socks.conf"
    if src_utils.file_exists(config_path):
        print(f"\n 🔍Config File Path: /etc/socks.conf")
    else:
        print(" ⚠️ Missing Configuration File")
        return

    config_content = src_utils.read_file(config_path)

    via_match = re.search(r'via:\s+([\d\.]+)\s+port\s*=\s*(\d+)', config_content, re.IGNORECASE)
    proxyproto_match = re.search(r'^\s*proxyprotocol:\s*([^\n\r]+)', config_content, re.IGNORECASE | re.MULTILINE)
    dnsproto_match = re.search(r'resolveprotocol:\s+(\w+)', config_content, re.IGNORECASE)
    logging_match = re.search(r'logoutput:\s+(\S+)', config_content)

    print("\n SOCKS Settings:")
    if via_match:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Address: {via_match.group(1)}")
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Port: {via_match.group(2)}")
    else:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ ❌Invalid Configuration!")

    if proxyproto_match:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Proxy Protocol: {proxyproto_match.group(1)}")
    else:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ ❌Proxy Protocol not specified!")

    print("\n DNS Settings:")
    if dnsproto_match:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Protocol: {dnsproto_match.group(1).upper()}")
    else:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ ❌DNS Protocol not specified!")

    print("\n Logging:")
    if logging_match:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Output: {logging_match.group(1)}")
    else:
        print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ ❌Logging disabled!")

    success = test_connectivity(
        tests=[
            {
                'cmd': 'socksify nc -z -v -w5 1.1.1.1 80',
                'success_indicator': 'succeeded',
                'timeout': 5
            }
        ],
        require_all=True,
        global_timeout=10,
        kill_patterns=['socksify']
    )

    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*42}╝{src_utils.RESET}")







def proxychains_status():
    src_utils.clear_screen()

    print(f"{src_utils.BORDER_COLOR}╔{'═'*42}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🔗PROXYCHAINS STATUS'.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*42}╣{src_utils.RESET}")


    config_path = "/etc/proxychains.conf"
    if not src_utils.file_exists(config_path):
        print("❌ ProxyChains configuration file not found!")
        return


    config = src_utils.read_file(config_path)
    

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
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Chain Type Mode: {chain_type}")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ DNS Proxy Mode: {dns_status}")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Quiet Mode: {quiet_status}")
    print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ Active Proxies: {proxy_count}")



    if proxies:
        print("\n Recent Proxies:")
        for proxy in proxies[-5:]:
            print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}▸ {proxy}")
    else:
        print(f"{src_utils.BORDER_COLOR}  │{src_utils.RESET}🧦No proxies configured in [ProxyList]")

    

    success = test_connectivity(
        tests=[
            {
                'cmd': 'proxychains4 nc -z -v -w5 1.1.1.1 80',
                'success_indicator': 'succeeded',
                'timeout': 5
            }
        ],
        require_all=True,
        global_timeout=10,
        kill_patterns=['proxychains4']
    )

    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*42}╝{src_utils.RESET}")




def psiphon_status():
    """
    Displays comprehensive status of Psiphon installation, service, and network configuration.
    """
    src_utils.clear_screen()

    CONFIG_FILE = src_psiphon.CONFIG_FILE
    SERVICE_NAME = src_psiphon.SERVICE_NAME
    PSIPHON_BINARY = src_psiphon.PSIPHON_BINARY

    print(f"{src_utils.BORDER_COLOR}╔{'═'*47}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{'🛰️ PSIPHON STATUS'.center(48)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*47}╣{src_utils.RESET}")

    if not src_psiphon.is_psiphon_installed():
        print(f"\n 🔍 Psiphon : {src_utils.RED}❌ Not Installed{src_utils.RESET}")
        return
    else:
        print(f"\n 🔍 Psiphon : {src_utils.GREEN}✅ Installed{src_utils.RESET}")


    if not src_utils.file_exists(PSIPHON_BINARY):
        print(f" 🔍 Psiphon Binary : {src_utils.RED}❌ Not Found{src_utils.RESET}")
        print(f"{src_utils.YELLOW}⚠️ It is recommended to reinstall.{src_utils.RESET}")
        return
    else:
        print(f" 🔍 Psiphon Binary : {src_utils.GREEN}✅ Found{src_utils.RESET}")


    service_check = subprocess.run(f"systemctl is-active {SERVICE_NAME}", shell=True, capture_output=True, text=True)
    status = f"{src_utils.GREEN}✅ Running{src_utils.RESET}" if service_check.returncode == 0 else f"{src_utils.YELLOW}❌ Not Running{src_utils.RESET}"
    print(f" 🔍 Psiphon Service: {status}")

    if not src_utils.file_exists(CONFIG_FILE):
        print(f" 🔍 Psiphon Config: {src_utils.RED}❌ Missing ({CONFIG_FILE}){src_utils.RESET}")
        print(f"{src_utils.YELLOW}⚠️ It is recommended to reinstall or Reset Configuration.{src_utils.RESET}")
        return
    else:
        print(f" 🔍 Psiphon Config: {src_utils.GREEN}✅ Found{src_utils.RESET}\n"
        f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ Path : {src_utils.GREEN}{CONFIG_FILE}{src_utils.RESET}")


    print(f"\n {src_utils.BOLD}⚙️  Configuration Summary:{src_utils.RESET}")
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
    except json.JSONDecodeError:
        print(f" {src_utils.RED}❌ Invalid JSON format in config!{src_utils.RESET}")
        print(f"{src_utils.YELLOW}⚠️ It is recommended Reset Configuration.{src_utils.RESET}")
        return


    def print_param(key, label=None):
        check = src_psiphon.check_parameters(target_keys=key, validate=True)
        entry = check.get(key)
        label = label or key
        if entry is None:
            print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ {label.ljust(18)}: {src_utils.RED}❌ Not Found{src_utils.RESET}")
            return
        value = entry["value"]
        valid = entry["valid"]
        if value is None:
            print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ {label.ljust(18)}: {src_utils.YELLOW}❌ Not Set{src_utils.RESET}")
        elif valid:
            print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ {label.ljust(18)}: {src_utils.GREEN}✅ {value}{src_utils.RESET}")
        else:
            print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ {label.ljust(18)}: {src_utils.RED}⚠️ Invalid [{value}]{src_utils.RESET}")

    print_param("DataRootDirectory", "Data Directory")
    print(f"{src_utils.BORDER_COLOR}   │{src_utils.RESET}▸ {'Local IP'.ljust(18)}: {src_utils.GREEN}✅ 127.0.0.1{src_utils.RESET}")
    print_param("LocalSocksProxyPort", "Socks Port")
    print_param("LocalHttpProxyPort", "HTTP Port")
    print_param("EgressRegion", "Region")
    print_param("ConnectionWorkerPoolSize", "Connection Workers")
    print_param("StaggerConnectionWorkersMilliseconds", "Stagger Workers")
    print_param("TunnelPoolSize", "Tunnel Pool")
    print_param("NetworkLatencyMultiplier", "Latency Multiplier")
    print_param("EstablishTunnelPausePeriodSeconds", "Establish Period")
    print_param("LimitTunnelProtocols", "Tunnel Protocols")
    print_param("UpstreamProxyURL", "Upstream Proxy")
    print_param("SplitTunnelOwnRegion", "Split Own Region")
    print_param("EmitDiagnosticNetworkParameters", "Diagnostic Network")
    print_param("LimitRelayBufferSizes", "Limit BufferSizes")
    print_param("EmitDiagnosticNotices", "Diagnostic Notices")
    print_param("SplitTunnelRegions", "Splited Tunnel Regions")
    

    print(f"\n{src_utils.BORDER_COLOR} 🛜  Testing Connection, please wait...{src_utils.RESET}")
    proxy_info = src_psiphon.check_parameters(target_keys="LocalSocksProxyPort", validate=True)

    if not proxy_info or "LocalSocksProxyPort" not in proxy_info:
        print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.RED}❌ ERROR{src_utils.RESET}")
        print(f"   │▸ Reason: {src_utils.RED}Proxy port not found in config{src_utils.RESET}")
        print(f"   │▸ Solution: {src_utils.YELLOW}Check Psiphon configuration file{src_utils.RESET}")

    elif not proxy_info["LocalSocksProxyPort"].get("valid", False):
        print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.RED}❌ ERROR{src_utils.RESET}")
        print(f"   │▸ Reason: {src_utils.RED}Invalid proxy port value{src_utils.RESET}")
        print(f"   │▸ Solution: {src_utils.YELLOW}Fix port value in config (must be an integer){src_utils.RESET}")

    else:
        proxy_port = proxy_info["LocalSocksProxyPort"]["value"]
        
        connection_status = src_utils.get_connection_status(proxy_port=proxy_port, protocol="socks5h")

        if connection_status["status"] == "error":
            print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.RED}❌ ERROR{src_utils.RESET}")
            print(f"   │▸ Message: {src_utils.RED}{connection_status.get('error', 'Unknown error')}{src_utils.RESET}")

        elif connection_status["status"] == "disconnected":
            print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.RED}❌ NOT CONNECTED{src_utils.RESET}")

        elif connection_status["status"] == "connected":
            region = connection_status["region"]
            ip = connection_status["ip"]
            service = connection_status["service"]
            protocol = connection_status.get("protocol", "unknown")

            print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.GREEN}✅ CONNECTED{src_utils.RESET}")
            print(f"   │▸ Server IP: {src_utils.GREEN}{ip}{src_utils.RESET}")
            print(f"   │▸ Server Region: {src_utils.GREEN}{region}{src_utils.RESET}")
            print(f"   │▸ Test Service: {src_utils.GREEN}{service}{src_utils.RESET}")
            print(f"   │▸ Test Protocol: {src_utils.GREEN}{protocol}{src_utils.RESET}")

        else:
            print(f"\n {src_utils.BOLD}🌐 Connection Status: {src_utils.RED}❌ UNKNOWN{src_utils.RESET}")


    print(f"\n{src_utils.BORDER_COLOR}╚{'═'*47}╝{src_utils.RESET}")
