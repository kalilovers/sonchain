#!/usr/bin/env python3

# -*- coding: utf-8 -*-



#src_ > >>>
from src import config
from src import src_utils

#modules >
import os
import sys
import requests  #external-pip install requests

import tarfile
import tempfile
import shutil
import datetime
from pathlib import Path


# -------------------- updater --------------------






def get_latest_release_info():
    try:
        response = requests.get(config.RELEASE_API_URL, timeout=10)
        response.raise_for_status()
        

        if "assets" not in response.json():
            raise ValueError("Invalid GitHub API response")
            
        return response.json()
    except Exception as e:
        print(f"Error fetching release info: {str(e)}")
        return None




def backup_file():

    if not os.path.exists(config.INSTALL_PATH):
        print(f"Error: Main script not found at {config.INSTALL_PATH}")
        return False
    try:
        backup_path = f"{config.INSTALL_PATH}.bak"
        os.replace(config.INSTALL_PATH, backup_path)
        print(f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"Backup failed: {str(e)}")
        return None





def download_asset(asset_url):

    try:
        response = requests.get(asset_url, timeout=10)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Download failed: {str(e)}")
        return None



def update_script():


    release_info = get_latest_release_info()
    if not release_info:
        return False

    latest_version = release_info.get("tag_name", "").lstrip("v")
    if config.VERSION == latest_version:
        print("✓ Already up-to-date")
        return True


    asset = next((a for a in release_info.get("assets", []) 
                if a.get("name") == "sonchain.tar.gz"), None)
    if not asset:
        print("✗ Asset not found")
        return False

    backup_path = None
    temp_dir = tempfile.mkdtemp(prefix="sonchain_update_")
    
    try:

        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = f"{config.INSTALL_DIR}-backup-{timestamp}"
        if os.path.exists(config.INSTALL_DIR):
            os.rename(config.INSTALL_DIR, backup_path)
            print(f"✓ Backup created: {backup_path}")


        tarball_path = os.path.join(temp_dir, "sonchain.tar.gz")
        new_script = download_asset(asset["browser_download_url"])
        if not new_script:
            raise RuntimeError("Download failed")
        
        with open(tarball_path, "wb") as f:
            f.write(new_script)


        os.makedirs(config.INSTALL_DIR, exist_ok=True)
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(config.INSTALL_DIR)
        

        os.chmod(os.path.join(config.INSTALL_DIR, "main.py"), 0o755)
        for root, dirs, files in os.walk(config.INSTALL_DIR):
            for d in dirs:
                os.chmod(os.path.join(root, d), 0o755)
            for f in files:
                if f.endswith(".py"):
                    os.chmod(os.path.join(root, f), 0o755)
                else:
                    os.chmod(os.path.join(root, f), 0o644)

        print("✓ Update successful")
        return True

    except Exception as e:
        print(f"✗ Critical error: {str(e)}. Restoring backup...")
        if backup_path and os.path.exists(backup_path):
            if os.path.exists(config.INSTALL_DIR):
                shutil.rmtree(config.INSTALL_DIR)
            os.rename(backup_path, config.INSTALL_DIR)
            print("✓ Previous version restored")
        return False

    finally:

        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        if backup_path and os.path.exists(backup_path):
            shutil.rmtree(backup_path)





def handle_script_update():
    print(f"{src_utils.BORDER_COLOR}╔{'―'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' Update Manager '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'―'*32}╣{src_utils.RESET}")
    

    print(f"Current version: {src_utils.CYAN}{config.VERSION}{src_utils.RESET}")
    

    release_info = get_latest_release_info()
    if not release_info:
        print(f"{src_utils.RED}Failed to check updates{src_utils.RESET}")
        input("\nPress Enter to return...")
        return
    
    latest_version = release_info.get("tag_name", "").lstrip("v")
    
    if latest_version == config.VERSION:
        print(f"{src_utils.GREEN}✓ Already on latest version{src_utils.RESET}")
        input("\nPress Enter to return...")
        return
        

    print(f"Available version: {src_utils.CYAN}{latest_version}{src_utils.RESET}")
    

    choice = input(f"\nUpdate {src_utils.RED}{config.VERSION}{src_utils.RESET} → {src_utils.GREEN}{latest_version}{src_utils.RESET}? [Y/n] ").strip().lower()
    
    if choice not in {'', 'y', 'yes'}:
        print(f"{src_utils.YELLOW}Update cancelled{src_utils.RESET}")
        input("\nPress Enter to return...")
        return

    try:
        success = update_script()
        if success:
            print(f"\n{src_utils.GREEN}✓ Update successful!{src_utils.RESET}")
            print(f"Re Start with: {src_utils.CYAN}sonchain{src_utils.RESET}")
            sys.exit(0)
        else:
            print(f"\n{src_utils.RED}✗ Update failed{src_utils.RESET}")
            
    except Exception as e:
        print(f"\n{src_utils.RED}✗ Error: {str(e)}{src_utils.RESET}")
    
    input("\nPress Enter to return to main menu...")


