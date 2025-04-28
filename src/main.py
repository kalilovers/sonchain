#!/usr/bin/env python3

# -*- coding: utf-8 -*-




"""
Copyright (c) 2025 Kalilovers (https://github.com/kalilovers)

This file is part of [Sonchain]. It is licensed under the MIT License.
You may not remove or alter the above copyright notice.
Any modifications or redistributions must retain the original author's credit.
For more details, please refer to the LICENSE file in the project root.
"""







#------------------------------------MAIN-----------------------------------------#


#src_ > >>>
from src import src_menus
from src import src_status
from src import src_socksify
from src import src_proxychains
from src import src_tor
from src import src_dnsson
from src import src_proxyson
from src import src_updater
from src import src_uninstall
from src import src_utils

#modules >
import os
import sys
import time
import datetime









def main():
    if os.geteuid() != 0:
        print("⚠️ This script requires root access. Please run with 'sudo' .")
        sys.exit(1)

    while True:
        try:
            src_menus.display_main_menu()
            choice = input("\nEnter your choice: ").strip()

            #----------------------------------Status-------------------------------------------
            if choice == '1':
                src_menus.display_status_menu()

            #----------------------------------Auto setup-------------------------------------------
            elif choice == '2':
                while True:
                    src_menus.display_auto_setup_menu()
                    sub_choice = input("\nEnter your choice: ").strip()
                    if sub_choice == '1':
                        src_socksify.setup_dante_tor()
                    elif sub_choice == '2':
                        src_proxychains.setup_proxychains_tor()
                    elif sub_choice == '0':
                        break  # Return to the main menu
                    else:
                        print("Invalid choice. Please try again.")
                        input("Press Enter to continue...")


            #----------------------------------Tor Setup-------------------------------------------
            elif choice == '3':  # Tor Setup
                src_tor.handle_tor_setup()

            #----------------------------------Dante (Socksify) Setup-------------------------------------------
            elif choice == '4':  # Dante Setup
                src_socksify.handle_dante_menu()

            #----------------------------------Proxychains Setup-------------------------------------------
            elif choice == '5': 
                src_proxychains.handle_proxychains_menu()

            #----------------------------------DnsSon Setup-------------------------------------------
            elif choice == '6':  # DnsSon Setup
                src_dnsson.handle_dnsson_setup()

            #----------------------------------ProxySon Setup-------------------------------------------
            elif choice == '7':  # ProxySon Setup
                src_proxyson.handle_proxyson_setup()

            #----------------------------------Uninstall-------------------------------------------
            elif choice == '8':
                src_updater.handle_script_update()

            #----------------------------------Uninstall-------------------------------------------
            elif choice == '9':
                src_uninstall.handle_uninstall()

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
        src_uninstall.uninstall_script()
        sys.exit(0)
    else:
        main()