# SNI-Spoofing

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![Status: Active](https://img.shields.io/badge/status-active-success.svg)]()

> Bypass DPI with IP/TCP-Header manipulation — a high-performance, configurable SNI (Server Name Indication) spoofing tool designed for network analysis, privacy testing, and educational purposes.

> **⚠️ Disclaimer:** This tool is intended for **authorized security testing, educational research, and privacy protection only**. Unauthorized use of SNI spoofing to bypass security controls or access restricted networks without explicit permission is illegal and unethical. Use at your own risk.

## 📋 Table of Contents

- [Features](#-features)
- [What's New](#-whats-new)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Troubleshooting](#-troubleshooting)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## ✨ Features

- **Dynamic SNI Rotation:** Randomly selects SNI from a configurable list for each connection to avoid fingerprinting.
- **Multi-Protocol Support:** Full support for both **IPv4** and **IPv6**.
- **TLS 1.2 & 1.3 Compatibility:** Generates realistic TLS ClientHello packets with proper extensions (Key Share, Supported Groups, SNI, Padding).
- **Robust Error Handling:** Bounded retry logic for remote connections, exponential backoff on packet-recv errors, and graceful shutdown handling.
- **Thread-Safe Packet Injection:** Uses `pydivert ≥ 2.0` (`WinDivert`) to manipulate packets at the network stack level with proper lock-protected state.
- **Race-Condition Free:** Connections are registered only after `sock_connect` succeeds; the injector ignores half-open sockets via a `ready` flag.
- **Input Validation:** Config IPs/ports are validated with `inet_pton`; TLS field lengths are enforced (32-byte `random`/`session_id`/`key_share`, 1–255 byte SNI).
- **Configurable:** All settings (listen port, target IP, SNI list, TLS version, retries) are managed via `config.json`.
- **Bidirectional Relay:** Clean `asyncio.wait(FIRST_COMPLETED)` teardown — when one direction ends, the other is cancelled and sockets are released.

---

## 🆕 What's New

Recent overhaul (`v2.0.0`):

| Area | Change |
|---|---|
| **Critical bug** | `relay_main_loop` was 100% broken: `loop.sock_sendall()` returns `None`, but the code compared it to `len(data)` and raised on every send. **Fixed.** |
| **Race condition** | `FakeInjectiveConnection` was registered before `sock_connect` — a stray packet could tear down the socket mid-handshake. Now registered **after** a successful connect via a thread-safe helper. |
| **Thread safety** | `fake_injective_connections` was mutated from 3 threads (asyncio, pydivert, signal handler) with no synchronization. Now guarded by a single `threading.Lock`. |
| **Lifecycle** | Retry attempts no longer leak stale dict entries; relay tasks are kept alive and cancelled cleanly. |
| **API migration** | `pydivert.PyDivert` → `pydivert.WinDivert` (renamed in `pydivert ≥ 2.0`). |
| **Resilience** | Injector recv loop has exponential backoff so it never busy-spins if the handle is closed. |
| **Validation** | `_validate_config()` rejects malformed IPs/ports/TLS versions at startup with friendly logs. |
| **Hardening** | `Packet.py` rejects malformed TLS fields instead of relying on bare `assert`. |

---

## 🏗️ Architecture

```
┌──────────┐         ┌────────────────────────────────────────┐         ┌──────────────┐
│  Client  │────────►│  SNI Proxy (127.0.0.1:8080)            │────────►│ Target Server│
└──────────┘         │                                        │         └──────────────┘
                     │  ┌──────────────┐    ┌──────────────┐  │
                     │  │ asyncio loop │◄──►│ FakeTcpInj.  │  │
                     │  │ (relay)      │    │ (WinDivert)  │  │
                     │  └──────────────┘    └──────┬───────┘  │
                     │                             │          │
                     │                  intercepts SYN/ACK    │
                     │                  injects fake CH       │
                     │                             │          │
                     └─────────────────────────────┼──────────┘
                                                   │
                                          ┌────────▼─────────┐
                                          │  WinDivert1.4    │
                                          │  (kernel driver) │
                                          └──────────────────┘
```

**Packet flow:**

1. Client connects to `LISTEN_HOST:LISTEN_PORT`.
2. Proxy opens outgoing socket to `CONNECT_IP:CONNECT_PORT`.
3. `FakeTcpInjector` (via WinDivert) intercepts the SYN/SYN-ACK/ACK of the outgoing TCP handshake.
4. Once the 3-way handshake completes, the injector **injects** a fake `ClientHello` with a **wrong TCP sequence number** (the `wrong_seq` bypass) to confuse DPI middleboxes.
5. The legitimate server's ACK of the fake data confirms the bypass worked; the injector is detached.
6. Bidirectional `asyncio` relay takes over between the two sockets.

---

## 📦 Prerequisites

| Requirement | Notes |
|---|---|
| **OS** | Windows 10/11 (WinDivert is Windows-only) |
| **Python** | **3.8 – 3.12** (pydivert 2.x has no wheel for 3.13/3.14) |
| **Privileges** | **Administrator** required to load the WinDivert kernel driver |
| **Antivirus** | Add an exclusion for `pydivert`'s folder + `python.exe` (see below) |

---

## 🛠️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/ItsWanheda/SNI-Spoofing.git
cd SNI-Spoofing
```

### 2. Install Python dependencies

> ⚠️ **Use Python 3.12 or earlier.** On Python 3.14, `pydivert` imports but the WinDivert handle never binds.

```powershell
# Recommended: use a virtual environment
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install pydivert
```

### 3. Configure `config.json`

Edit the file in the project root (see [Configuration](#-configuration) for the full schema).

### 4. Add Windows Defender exclusions (run as Administrator)

WinDivert is a kernel-level packet tool and is frequently flagged. Open PowerShell **as Administrator** and run:

```powershell
$divertPath = python -c "import pydivert, os; print(os.path.dirname(pydivert.__file__))"
Add-MpPreference -ExclusionPath $divertPath
Add-MpPreference -ExclusionPath "C:\Windows\System32\drivers\WinDivert1.4.sys"
Add-MpPreference -ExclusionProcess "python.exe"
Add-MpPreference -ExclusionProcess "py.exe"
```

> If you're on a corporate device where UAC elevation is blocked, add the same paths via **Windows Security → Virus & threat protection → Exclusions**.

### 5. Run the proxy

In the **same elevated PowerShell**, with the venv active:

```powershell
python SNI.py
```

Expected output:

```
@ItsWanheda - SNI Proxy Overhauled
SNI Proxy listening on 127.0.0.1:8080
Forwarding to 1.2.3.4:443 (interface: 192.168.1.10)
```

---

## ⚙️ Configuration

All runtime settings live in `config.json` next to `SNI.py`:

```json
{
  "LISTEN_HOST": "127.0.0.1",
  "LISTEN_PORT": 8080,
  "CONNECT_IP": "1.2.3.4",
  "CONNECT_PORT": 443,
  "TLS_VERSION": "1.3",
  "SNI_LIST": [
    "www.google.com",
    "www.youtube.com",
    "auth.vercel.com",
    "www.microsoft.com"
  ],
  "MAX_RETRIES": 3,
  "RETRY_DELAY": 2
}
```

| Key | Type | Description | Default |
|---|---|---|---|
| `LISTEN_HOST` | string | Local IP the proxy binds to. Use `127.0.0.1` for local-only, `0.0.0.0` to accept from LAN. | `127.0.0.1` |
| `LISTEN_PORT` | int (1–65535) | Local port the proxy listens on. | `8080` |
| `CONNECT_IP` | string (IPv4/IPv6) | Target server IP to forward traffic to. | *required* |
| `CONNECT_PORT` | int (1–65535) | Target server port (usually `443`). | *required* |
| `TLS_VERSION` | `"1.2"` \| `"1.3"` | TLS version encoded in the fake `ClientHello`. | `"1.2"` |
| `SNI_LIST` | list[string] | Pool of fake SNIs; one is chosen at random per connection. | `["www.google.com"]` |
| `MAX_RETRIES` | int (0–100) | Connect attempts before giving up. | `3` |
| `RETRY_DELAY` | float (0–60) | Seconds between retry attempts. | `2` |

Validation is performed at startup; bad values cause a clear error and exit.

---

## 🚀 Usage

### Basic run
```powershell
# In an elevated PowerShell, with venv active:
python SNI.py
```

### Point your application at the proxy

Configure your client (browser, `curl`, game, etc.) to use `127.0.0.1:8080` as its SOCKS/HTTP proxy, depending on how you integrate it. (This repository provides the SNI-spoofing engine; clients are configured externally.)

### Graceful shutdown

Press `Ctrl+C` once. The proxy will:
- Close all open sockets.
- Tear down any in-flight injectors.
- Exit cleanly.

---

## 🔧 Troubleshooting

### ❌ `ModuleNotFoundError: No module named 'pydivert'`
```powershell
pip install pydivert
```
Make sure you're in the venv (`.\venv\Scripts\Activate.ps1`).

### ❌ `ImportError: cannot import name 'PyDivert' from 'pydivert'`
The class was renamed in `pydivert ≥ 2.0`. Use `WinDivert` instead — this repo already does.

### ❌ `RuntimeError: WinDivert handle is not open` (loop)
**Causes (in order of likelihood):**

1. **Not running as Administrator** — open an elevated PowerShell.
2. **Antivirus blocking WinDivert** — add the exclusions listed in step 4 of installation.
3. **Python 3.13 / 3.14** — `pydivert` has no wheel for these versions. Recreate the venv with `py -3.12 -m venv venv`.

### ❌ `WinDivert1.4.sys` driver not found
```powershell
sc query WinDivert1.4
```
If the service isn't `RUNNING`, reinstall pydivert:
```powershell
pip install --force-reinstall pydivert
```

### ❌ `Access is denied` when adding Defender exclusions
You're not in an elevated shell. Right-click PowerShell → **Run as administrator**, or use the **Windows Security → Exclusions** GUI.

### ❌ `Address already in use`
Another process is on `LISTEN_PORT`. Change it in `config.json`, or stop the conflicting service:
```powershell
netstat -ano | findstr :8080
taskkill /PID <pid> /F
```

### ❌ Connections succeed but DPI still blocks
- Verify the fake `ClientHello` ACK was received: look for `Fake-data ACK received for ...; handshake complete.` in the log.
- Try a different `SNI_LIST` entry — some SNIs are themselves blocked.
- Confirm `BYPASS_METHOD` is supported (currently only `"wrong_seq"`).

---

## 🛡️ Security Considerations

- **Run only on networks you own or are authorized to test.** Bypassing DPI may violate local laws and/or terms of service.
- The proxy has **no authentication on the listening socket**. Do not bind to `0.0.0.0` on a public network unless you add access control yourself.
- The injected `ClientHello` is forged; legitimate servers will see a mismatched handshake and may rate-limit or blacklist your IP if traffic patterns are unusual.
- Source IPs in `config.json` must be valid (`inet_pton`-checked at startup) to prevent filter-injection mistakes.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Commit your changes (`git commit -m "feat: add amazing feature"`).
4. Push to the branch (`git push origin feature/amazing-feature`).
5. Open a Pull Request.

For commit messages we follow **[Conventional Commits](https://www.conventionalcommits.org/)**.

---

## 📄 License

This project is licensed under the **MIT License** — see the `LICENSE` file for details.

---

## 📞 Contact

- **GitHub:** [https://github.com/ItsWanheda](https://github.com/ItsWanheda)
- **Email:** Wanheda.work@gmail.com
- **Maintainer:** ItsWanheda

---

> **Disclaimer:** This tool is intended for educational and legitimate privacy purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. Misuse of this tool to bypass security measures or access unauthorized resources is strictly prohibited.