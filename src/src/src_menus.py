#!/usr/bin/env python3

# -*- coding: utf-8 -*-




#src_ > >>>
from src import src_utils
from src import src_status
from src import config

#modules >
import sys



#---------------------------menus--------------------------------

def display_main_menu():
    src_utils.clear_screen()
    
    script_version = f"v{config.VERSION}"
    github_link    = "Github.com/Kalilovers"
    

    print(f"\n{src_utils.VERSION_COLOR}Version : {script_version}{src_utils.RESET}")
    print(f"{src_utils.VERSION_COLOR}GitHub  : {github_link}{src_utils.RESET}\n")
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' SONCHAIN MANAGER '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | Status",
        "2 | Auto Setup",
        "3 | Tor Setup",
        "4 | Dante'Socksify' Setup",
        "5 | ProxyChains Setup",
        "6 | DnsSon Setup",
        "7 | ProxySon Setup",
        "8 | Update Script",
        "9 | Uninstall"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Exit'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")
   









def display_status_menu():
    while True:
        try:
            src_utils.clear_screen()
            

            print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' STATUS MENU '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
            

            menu_items = [
                "1 | Tor Status",
                "2 | Socksify Status",
                "3 | ProxyChains Status",
                "4 | ProxySon Status",
                "5 | DnsSon Status"
            ]
            
            for item in menu_items:
                print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
            

            print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
            print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")

            choice = input("Enter your choice: ").strip()

            if choice == '0':
                break

            elif choice == '1':
                src_status.tor_status()

                input("\nPress Enter to Return...")
                continue

            elif choice == '2':
                src_status.dante_status()
                input("\nPress Enter to Return...")
                continue

            elif choice == '3':
                src_status.proxychains_status()
                input("\nPress Enter to Return...")
                continue

            elif choice == '4':
                src_status.proxyson_status()
                input("\nPress Enter to Return...")
                continue

            elif choice == '5':
                src_status.dnsson_status()
                input("\nPress Enter to Return...")
                continue

            else:
                input("\n❌Invalid choice! Press 'Enter' to try again...")
                continue

        except KeyboardInterrupt:
            print("\nCancelled by user.")
            print("Son Says GoodBye!")
            sys.exit(0)







def display_auto_setup_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*45}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' AUTO SETUP MENU '.center(45)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*45}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | Setup Socksify + Tor + Proxyson+Dnsson",
        "2 | Setup ProxyChains + Tor"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(43)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*45}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(40)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*45}╝{src_utils.RESET}")







def display_setup_tor_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' TOR SETUP MENU '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | Tor Status",
        "2 | Install Tor",
        "3 | Manual Configuration",
        "4 | Advanced Settings",
        "5 | Stop Tor",
        "6 | Restart Tor",
        "7 | Remove Tor"
    ]

    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Back'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")








def display_dante_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' DANTE (SOCKSIFY) SETUP '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | Socksify Status",
        "2 | Install Socksify",
        "3 | Edit Configuration",
        "4 | Change SOCKS IP/Port",
        "5 | Change DNS Protocol",
        "6 | Change Proxy Protocol",
        "7 | Sync with Tor",
        "8 | Remove Socksify"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")








def display_proxychains_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*41}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' PROXYCHAINS SETUP '.center(41)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")
    

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
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(39)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*41}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(36)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*41}╝{src_utils.RESET}")






def display_proxyson_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' PROXYSON SETUP MENU '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | ProxySon Status",
        "2 | Install ProxySon",
        "3 | Change Destination",
        "4 | Change Command",
        "5 | Sync with Tor",
        "6 | Remove ProxySon"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")






def display_dnsson_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' DNSSON SETUP MENU '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | DnsSon Status",
        "2 | Install DnsSon",
        "3 | Change Destination",
        "4 | Synchronize With Tor",
        "5 | Remove DnsSon"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")







def display_uninstall_menu():
    src_utils.clear_screen()
    

    print(f"{src_utils.BORDER_COLOR}╔{'═'*32}╗{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.HEADER_COLOR}{' ADVANCED UNINSTALLER '.center(32)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    

    menu_items = [
        "1 | Remove Socksify (Socksify)",
        "2 | Remove Tor",
        "3 | Remove ProxyChains",
        "4 | Remove DnsSon",
        "5 | Remove ProxySon",
        "6 | Remove Sonchain Script"
    ]
    
    for item in menu_items:
        print(f"{src_utils.BORDER_COLOR}║ {src_utils.ITEM_COLOR}{item.ljust(30)}{src_utils.RESET} {src_utils.BORDER_COLOR}║{src_utils.RESET}")
    

    print(f"{src_utils.BORDER_COLOR}╠{'═'*32}╣{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}║{src_utils.RESET} 0 | {src_utils.EXIT_STYLE}{'Return to Main Menu'.ljust(27)}{src_utils.RESET}{src_utils.BORDER_COLOR}║{src_utils.RESET}")
    print(f"{src_utils.BORDER_COLOR}╚{'═'*32}╝{src_utils.RESET}")






