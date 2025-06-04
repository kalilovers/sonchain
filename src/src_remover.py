#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import src_utils
from src import src_psiphon

#modules >
import os
import sys
import time
import subprocess
from datetime import datetime




# -------------------- Remover --------------------






def fix_apt_issues():
    src_utils.info("Checking APT Issues | Preparing system...")


    src_utils.run_command("sudo pkill -SIGTERM -f 'apt|dpkg'", "Terminating APT/DPKG processes")
    time.sleep(2)
    src_utils.run_command("sudo pkill -SIGKILL -f 'apt|dpkg'", "Forcibly terminating APT/DPKG processes")


    locks = [
        "/var/lib/apt/lists/lock",
        "/var/lib/dpkg/lock",
        "/var/lib/dpkg/lock-frontend",
        "/var/cache/apt/archives/lock"
    ]
    for lock in locks:
        if src_utils.file_exists(lock):
            src_utils.run_command(f"sudo rm -f {lock}", f"Removing lock file {lock}")

    src_utils.run_command("sudo dpkg --configure -a --force-all", "Forcing package configuration")
    








def execute_step(cmd, desc, critical=False):

    start_time = datetime.now().strftime("[%H:%M:%S]")
    sys.stdout.write(f"{src_utils.CYAN}{start_time}{src_utils.RESET} {src_utils.CYAN}{desc}...{src_utils.RESET} ")
    sys.stdout.flush()

    result = src_utils.run_command(cmd, "")


    end_time = datetime.now().strftime("[%H:%M:%S]")
    if result:
        sys.stdout.write(f"{src_utils.GREEN}✅ Done{src_utils.RESET}\n")
    else:
        sys.stdout.write(f"{f'{src_utils.YELLOW}⚠️ Warning{src_utils.RESET}' if not critical else f'{src_utils.RED}❌ Failed{src_utils.RESET}'}\n")
    sys.stdout.flush()

    return not critical or result













def remove_proxychains():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ REMOVING PROXYCHAINS{src_utils.RESET}".center(40))
    print("\n")
    
    fix_apt_issues()
    
    success = True
    success &= execute_step(
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
        success &= execute_step(cmd, desc)

    if success:
        src_utils.success("Complete", details="ProxyChains removal successful")
    else:
        src_utils.warning("Partial Success", details="Some cleanup steps failed")
    

    return success







def remove_tor():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ REMOVING TOR{src_utils.RESET}".center(40))
    print("\n")
    
    fix_apt_issues()
    
    success = True
    execute_step(
        "sudo systemctl stop tor tor@default && killall tor || true",
        "Stopping services"
    )
    
    success &= execute_step(
        "sudo apt autoremove --purge -y tor tor-geoipdb nyx",
        "Removing packages",
        critical=True
    )
    
    cleanup_steps = [
        ("sudo rm -rf /etc/tor /var/lib/tor /var/log/tor", "Cleaning files"),
        ("sudo rm -rf ~/.torrc ~/.config/tor", "User data"),
        ("sudo rm -rf /etc/logrotate.d/tor", "Removing Tor logrotate configuration"),
        ("sudo systemctl stop logrotate-tor.timer", "Stopping Tor logrotate timer"),
        ("sudo systemctl disable logrotate-tor.timer", "Disabling Tor logrotate timer"),
        ("sudo rm -rf /etc/systemd/system/logrotate-tor.timer", "Removing Tor logrotate timer file"),
        ("sudo rm -rf /etc/systemd/system/logrotate-tor.service", "Removing Tor logrotate service file"),
        ("sudo systemctl daemon-reload", "Reloading systemd daemon")
    ]
    
    for cmd, desc in cleanup_steps:
        success &= execute_step(cmd, desc)

    if success:
        src_utils.success("Complete", details="Tor removal successful")
    else:
        src_utils.warning("Partial Success", details="Tor cleanup incomplete")
    

    return success







def remove_dante():
    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ REMOVING DANTE|Socksify{src_utils.RESET}".center(40))
    print("\n")
    
    fix_apt_issues()
    
    success = True
    success &= execute_step(
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
        ("sudo rm -rf /etc/logrotate.d/dante", "Removing Dante logrotate configuration"),
        ("sudo systemctl stop logrotate-dante.timer", "Stopping Dante logrotate timer"),
        ("sudo systemctl disable logrotate-dante.timer", "Disabling Dante logrotate timer"),
        ("sudo rm -rf /etc/systemd/system/logrotate-dante.timer", "Removing Dante logrotate timer file"),
        ("sudo rm -rf /etc/systemd/system/logrotate-dante.service", "Removing Dante logrotate service file"),
        ("sudo systemctl daemon-reload", "Daemon-Reload")
    ]
    
    for cmd, desc in cleanup_steps:
        success &= execute_step(cmd, desc)
    


    if success:
        src_utils.success("Complete", details="Socksify removal successful")
    else:
        src_utils.warning("Partial Success", details="Socksify cleanup incomplete")
    

    return success






def remove_dnsson():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ REMOVING DNSSON{src_utils.RESET}".center(40))
    print("\n")

    result = src_utils.run_command("sudo rm -rf /usr/local/bin/dnsson", "")
    if result:
        src_utils.success("DnsSon Script removed successfully")
    else:
        src_utils.error("Failed to remove DnsSon script")


    return result







def remove_proxyson():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ REMOVING PROXYSON{src_utils.RESET}".center(40))
    print("\n")


    result = src_utils.run_command("sudo rm -rf /usr/local/bin/proxyson", "")
    if result:
        src_utils.success("Script removed successfully")
    else:
        src_utils.error("Failed to remove ProxySon script")


    return result







def remove_dnsson_proxyson():

    print("\n" + "─"*40)
    print(f"{src_utils.YELLOW}🗑️ Removing ProxySon & Dnsson{src_utils.RESET}".center(40))
    print("\n")


    src_utils.run_command("sudo rm -rf /usr/local/bin/dnsson", "Removing Dnsson script")
    src_utils.run_command("sudo rm -rf /usr/local/bin/proxyson", "Removing ProxySon script")
    src_utils.success("Dnsson and ProxySon scripts removed successfully")





def remove_psiphon():
    """
    Completely removes Psiphon from the system, including service, binaries, config, and data directories.
    """

    src_utils.info("Starting Psiphon removal...")
    PSIPHON_BINARY = src_psiphon.PSIPHON_BINARY
    removed = True

    if not src_psiphon.remove_existing_service():
        src_utils.warning("Failed to handle existing service, but continuing...")
        removed = False


    paths_to_remove = [
        PSIPHON_BINARY,
        os.path.dirname(PSIPHON_BINARY),
        src_psiphon.CONFIG_DIR,
        "/etc/psiphon",
        "/opt/psiphon"
    ]

    src_utils.info("Removing Other stuff...")

    for path in paths_to_remove:
        try:
            subprocess.run(["rm", "-rf", path], check=True)
            src_utils.success(f"{path} removed successfully.", newline=False)
        except Exception as e:
            src_utils.warning(f"Failed to remove {path}: {str(e)}")
            removed = False

    if removed:
        src_utils.success("Psiphon removed successfully", 
                          details="All components and configurations deleted")
    else:
        src_utils.warning("⚠️ Some files couldn't be removed. You may need to delete them manually.")

    return removed
