# 🛡️ RCE Shield — Remote Code Execution Hardening for PC Gamers

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-green" />
  <img src="https://img.shields.io/badge/License-MIT-purple" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen" />
</p>

**RCE Shield** is a comprehensive security hardening toolkit designed specifically for PC gamers. It detects, prevents, and remediates Remote Code Execution (RCE) vulnerabilities in game launchers, mod loaders, overlay software, voice chat clients, and gaming peripherals.

## 🎯 Why Gamers Need This

PC gamers are uniquely vulnerable to RCE attacks because they:
- Run **game launchers** with elevated privileges (Steam, Epic, Battle.net, EA App)
- Install **mods** from untrusted sources that execute arbitrary code
- Use **overlay software** (Discord, GeForce Experience) that hooks into game processes
- Run **anti-cheat software** with kernel-level access (EAC, BattlEye, Vanguard)
- Have **open ports** for multiplayer, voice chat, and game streaming
- Use **peripheral software** (Razer Synapse, iCUE, Logitech G Hub) with auto-update RCE vectors

## 🔍 What RCE Shield Scans

### Game Launchers & Stores
| Launcher | Checks |
|----------|--------|
| Steam | Workshop mod validation, Steam protocol handler, overlay DLL injection, VAC bypass detection |
| Epic Games | Unreal Engine RCE (CVE-2023-36340), launcher update integrity |
| Battle.net | Agent process privileges, BNET protocol handler |
| EA App | Origin protocol handler, background services |
| GOG Galaxy | Plugin sandboxing, offline installer integrity |

### Anti-Cheat Systems
| Anti-Cheat | Checks |
|------------|--------|
| Easy Anti-Cheat (EAC) | Kernel driver integrity, service permissions |
| BattlEye | Driver signature validation, memory protection |
| Riot Vanguard | Boot-time driver audit, ring-0 attack surface |
| FACEIT Anti-Cheat | Service isolation, privilege escalation paths |

### Overlay & Communication
| Software | Checks |
|----------|--------|
| Discord | RPC server exposure, rich presence RCE, overlay hooks |
| NVIDIA GeForce Experience | GameStream RCE, Telemetry service, ShadowPlay hooks |
| AMD Adrenalin | Overlay injection, telemetry endpoints |
| OBS Studio | WebSocket API exposure, browser source sandboxing |

### Modding Platforms
| Platform | Checks |
|----------|--------|
| Nexus Mods (Vortex) | FOMOD script execution, symlink attacks |
| CurseForge | Fractureiser-style malware detection, JAR analysis |
| Thunderstore | BepInEx plugin validation |
| Steam Workshop | Serialization RCE, Lua/Python sandbox escape |

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/bad-antics/rce-shield.git
cd rce-shield

# Install
pip install -e .

# Full system scan
rce-shield scan --full

# Scan specific category
rce-shield scan --launchers
rce-shield scan --anticheat
rce-shield scan --mods
rce-shield scan --overlays
rce-shield scan --network

# Auto-fix (with backup)
rce-shield fix --auto

# Generate report
rce-shield report --html --output ~/Desktop/rce_report.html

# Real-time monitoring
rce-shield monitor --daemon
```

## 📋 Scan Modules

### 🎮 `scan_launchers` — Game Launcher Hardening
- Protocol handler validation (`steam://`, `com.epicgames.launcher://`)
- Auto-update MITM vulnerability check
- DLL search order hijacking detection
- Privilege escalation via service misconfigurations
- Workshop/mod directory permission audit

### 🛡️ `scan_anticheat` — Anti-Cheat Driver Audit
- Kernel driver signature validation
- Service ACL and permission analysis
- Known CVE vulnerability matching
- Ring-0 attack surface assessment
- Boot-time driver loading audit

### 🔌 `scan_mods` — Mod & Plugin Security
- Fractureiser malware pattern detection
- Obfuscated code analysis in JAR/DLL mods
- Script sandbox escape detection (Lua, Python, C#)
- Symlink/junction attack prevention
- Mod file hash verification against known-good databases

### 📡 `scan_network` — Gaming Network Hardening
- Open port enumeration (game servers, voice chat, streaming)
- UPnP/NAT-PMP exposure audit
- Game streaming service security (Parsec, Moonlight, Steam Link)
- Voice chat protocol analysis (Discord RPC, TeamSpeak query)
- DDoS protection assessment

### 🖥️ `scan_overlays` — Overlay & Hook Security
- DLL injection detection in game processes
- Overlay permission audit
- WebSocket/HTTP API exposure
- Telemetry endpoint analysis
- Browser source sandboxing (OBS)

### ⌨️ `scan_peripherals` — Gaming Peripheral Software
- Auto-update integrity verification
- Background service privilege audit
- Macro engine sandbox assessment
- Cloud sync credential security
- USB HID attack surface analysis

## 📊 Output Formats

- **Terminal** — Color-coded severity output with progress bars
- **HTML** — Interactive dashboard with risk scores & remediation guides  
- **JSON** — Machine-readable for CI/CD integration
- **CSV** — Spreadsheet-compatible findings export
- **SARIF** — GitHub Security tab integration

## 🏗️ Architecture

```
rce-shield/
├── rce_shield/
│   ├── __init__.py
│   ├── cli.py              # Click-based CLI
│   ├── core/
│   │   ├── scanner.py       # Base scanner engine
│   │   ├── reporter.py      # Multi-format report generator
│   │   ├── fixer.py         # Auto-remediation engine
│   │   └── monitor.py       # Real-time file/process monitor
│   ├── scanners/
│   │   ├── launchers.py     # Game launcher scanner
│   │   ├── anticheat.py     # Anti-cheat driver auditor
│   │   ├── mods.py          # Mod/plugin security scanner
│   │   ├── network.py       # Network exposure scanner
│   │   ├── overlays.py      # Overlay & hook scanner
│   │   └── peripherals.py   # Peripheral software scanner
│   ├── cve/
│   │   └── database.py      # Known CVE database for gaming software
│   └── utils/
│       ├── platform.py      # OS-specific helpers
│       ├── process.py       # Process inspection utilities
│       └── hashing.py       # File integrity helpers
├── tests/
├── docs/
└── pyproject.toml
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

RCE Shield is a **defensive security tool** for auditing your own systems. Never use it to scan systems you don't own or have explicit authorization to test. The authors are not responsible for misuse.

---

<p align="center">
  <strong>Built by <a href="https://github.com/bad-antics">NullSec</a></strong><br>
  <em>Protecting gamers from the threats they don't see coming.</em>
</p>
