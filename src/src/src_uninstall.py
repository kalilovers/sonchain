#!/usr/bin/env python3

# -*- coding: utf-8 -*-


#src_ > >>>
from src import src_menus
from src import src_remover
from src import src_utils

#modules >
import sys
import os
import shutil


# -------------------- uninstall Manager --------------------





def handle_uninstall():
    while True:
        src_menus.display_uninstall_menu()
        choice = input("\nSelect an option [0-5]: ").strip()
        results = {}
        
        if choice == '0':
            return
        elif choice == '1':
            results['Socksify'] = src_remover.remove_dante()
        elif choice == '2':
            results['Tor'] = src_remover.remove_tor()
        elif choice == '3':
            results['ProxyChains'] = src_remover.remove_proxychains()
        elif choice == '4':
            results['DnsSon'] = src_remover.remove_dnsson()
        elif choice == '5':
            results['ProxySon'] = src_remover.remove_proxyson()
        elif choice == '6':
            print("\n" + "═"*40)
            success = uninstall_script()
            
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
        
        src_utils.success("Successfully removed!", details="Re Install :")
        print("\nbash <(curl -fsSL https://raw.githubusercontent.com/kalilovers/sonchain/main/install.sh)")
        return True
        
    except Exception as e:
        src_utils.warning(f"Error: {str(e)}")
        sys.exit(1)
