# Sonchain Developer Guide


---

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

Each file is designed to:
- Import its own required Python modules and internal modules
- Be easily extendable or replaceable without breaking the overall system

---

## Key Principles

- **Self-Contained Scripts**: Each feature script must include its own imports (both standard and local modules).
- **Centralized Execution**: `main.py` is the only file users interact with directly.
- **Extensible Design**: Easy to add new modules without heavy refactoring.
- **Consistent Coding Style**: Absolute imports, modular functions, clean organization.

---

## Development Notes
##Thanks for your support. Please follow these development tips :

- **Python or local imports:** Only import what is necessary in each script. Don't overdo it.

- **Modularity:** Any new features should be created inside `src/` or the corresponding script and imported by `main.py`.

- **Documentation:** Update this developer guide (`Developers_Guide.md`) after changes.

- **Coding style:** Consistent naming (prefix `src_` for local feature scripts), use snake_case for functions.

---

## Contribution

- Fork the repository
- Keep everything modular
- Update this guide if needed
- update "Module --Update It-- .md "  File
- Submit pull requests with clear change descriptions

---

## Python and Local Modules Mapping

 **Important:** After any structural or import changes, update		"Modules --Update It--.md "		File

---

## License

Sonchain is licensed under the [MIT License] (LICENSE).

---

