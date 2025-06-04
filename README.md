# Sonchain

Github - Project link : https://github.com/kalilovers/sonchain


Sonchain is a modular, extensible Python-based project designed to help users overcome various network restrictions, including censorship, geo-blocks, DNS/IP filtering, and application-layer restrictions.  
It offers a flexible framework that allows users to install, configure, and manage advanced proxy solutions (such as Tor, DNS relay, SOCKS5 proxies, and tunneling techniques) easily through a unified CLI interface.
**More advanced features will be added over time with easy management





## ✨ Some of 'Current' Features

- **Bypass Restrictions**  
  Tackle DNS censorship, IP blocking, geo-restrictions, and service-specific limitations.
  
- **Custom DNS Handling**  
  Use internal DNS resolvers through SOCKS5 or Tor And Other proxies for secure and censorship-free name resolution.

- **Proxy Routing and Management**  
  Configure SOCKS5, TProxy, Proxychains, and DNS-over-Proxy setups dynamically.

- **Tool Integration**  
  Provides easy installation, updating, and removal of major bypass tools like Tor, Socksify, proxychains, and custom proxy solutions.

- **Flexible Framework**  
  The modular code structure allows seamless addition of new proxy methods and tools in the future.

- **CLI-Based Management**  
  A clear command-line interface (CLI) to manage all tools, services, and settings without manual configuration hassle.

- **Multi-Interface Approach**  
  Both CLI-based control and (planned) future web-panel support for easier graphical management.



## 📁 'Current' Project Structure

- `main.py` — Main executable entry point (CLI)
- `src/` — Contains separated core modules such as:
  - `src_tor.py` → Tor management module
  - `src_dnsson.py` → DNS proxy modules
  - `src_socksify.py` → SOCKS5 handler
  - `src_proxychains.py` → Proxychains manager
  - `src_proxyson.py` → Proxy solutions
  - `src_status.py` → Status monitoring tools
  - `src_utils.py` → Helper utilities for system and network tasks
  - `src_menus.py` → Menus and CLI options
  - `src_updater.py` → Auto-updater logic
  - `src_uninstall.py` → uninstallation scripts
  - `config.py` → Project-wide constants (version, install path, GitHub info, etc.)


## Developers_Guide
** If you want to collaborate and improve, correct, or make changes to the project, use the Developers_Guide.md section for guidance.



## 🛠 Installation

You can install the latest Sonchain release directly from GitHub using:
bash <(curl -fsSL https://raw.githubusercontent.com/kalilovers/sonchain/main/install.sh)

** Then run with this command: 
sonchain




