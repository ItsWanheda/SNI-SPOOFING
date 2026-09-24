# SNI-Spoofing

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![Status: Active](https://img.shields.io/badge/status-active-success.svg)]()

> **Bypass DPI with IP/TCP-header manipulation** — a high-performance, configurable SNI (Server Name Indication) spoofing tool designed for network analysis, privacy testing, and educational purposes.

> [!WARNING]
> **Authorized use only.** This tool is intended for **authorized security testing, educational research, and privacy protection**. Unauthorized use of SNI spoofing to bypass security controls or access restricted networks without explicit permission may be illegal and unethical. Use it at your own risk and comply with all applicable laws and network policies.

---

## 📋 Table of Contents

* [✨ Features](#-features)
* [🆕 What's New](#-whats-new)
* [🏗️ Architecture](#️-architecture)
* [📦 Prerequisites](#-prerequisites)
* [🛠️ Installation & Setup](#️-installation--setup)
* [⚙️ Configuration](#️-configuration)
* [🚀 Usage](#-usage)
* [🔧 Troubleshooting](#-troubleshooting)
* [🛡️ Security Considerations](#️-security-considerations)
* [🤝 Contributing](#-contributing)
* [📄 License](#-license)
* [📞 Contact](#-contact)

---

## ✨ Features

* **Dynamic SNI Rotation**
  Randomly selects an SNI from a configurable list for each connection to reduce predictable fingerprinting.

* **Multi-Protocol Support**
  Full support for both **IPv4** and **IPv6**.

* **TLS 1.2 & 1.3 Compatibility**
  Generates realistic TLS `ClientHello` packets with relevant extensions, including Key Share, Supported Groups, SNI, and Padding.

* **Robust Error Handling**
  Bounded retry logic for remote connections, exponential backoff on packet-receive errors, and graceful shutdown handling.

* **Thread-Safe Packet Injection**
  Uses `pydivert ≥ 2.0` (`WinDivert`) to manipulate packets at the network stack level with properly lock-protected state.

* **Race-Condition Free**
  Connections are registered only after `sock_connect` succeeds. The injector ignores half-open sockets through a `ready` flag.

* **Input Validation**
  Configuration IPs and ports are validated with `inet_pton`, while TLS field lengths are enforced:

  * 32-byte `random`
  * 32-byte `session_id`
  * 32-byte `key_share`
  * 1–255 byte SNI

* **Configurable**
  Runtime settings such as listen port, target IP, SNI list, TLS version, and retry behavior are managed through `config.json`.

* **Bidirectional Relay**
  Uses clean `asyncio.wait(FIRST_COMPLETED)` teardown. When one direction ends, the other is cancelled and sockets are released.

---

## 🆕 What's New

### v2.0.0 Overhaul

| Area               | Change                                                                                                                                                                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Critical bug**   | `relay_main_loop` was completely broken: `loop.sock_sendall()` returns `None`, but the previous implementation compared it to `len(data)` and raised on every send. **Fixed.**                                             |
| **Race condition** | `FakeInjectiveConnection` was registered before `sock_connect`, allowing a stray packet to tear down the socket during the handshake. It is now registered **after** a successful connection through a thread-safe helper. |
| **Thread safety**  | `fake_injective_connections` was mutated from three threads — asyncio, WinDivert, and the signal handler — without synchronization. It is now protected by a single `threading.Lock`.                                      |
| **Lifecycle**      | Retry attempts no longer leak stale dictionary entries. Relay tasks remain alive and are cancelled cleanly during teardown.                                                                                                |
| **API migration**  | `pydivert.PyDivert` → `pydivert.WinDivert`, matching the API introduced in `pydivert ≥ 2.0`.                                                                                                                               |
| **Resilience**     | The injector receive loop uses exponential backoff so it does not busy-spin when the WinDivert handle is closed.                                                                                                           |
| **Validation**     | `_validate_config()` rejects malformed IP addresses, ports, and TLS versions at startup with clear log messages.                                                                                                           |
| **Hardening**      | `Packet.py` rejects malformed TLS fields explicitly instead of relying on bare `assert` statements.                                                                                                                        |

---

## 🏗️ Architecture

```text
┌──────────┐         ┌────────────────────────────────────────┐         ┌──────────────┐
│  Client  │────────►│  SNI Proxy (127.0.0.1:8080)            │────────►│ Target Server│
└──────────┘         │                                        │         └──────────────┘
                     │  ┌──────────────┐    ┌──────────────┐  │
                     │  │ asyncio loop │◄──►│ FakeTcpInj.  │  │
                     │  │    (relay)   │    │  (WinDivert) │  │
                     │  └──────────────┘    └──────┬───────┘  │
                     │                             │          │
                     │                  intercepts SYN/ACK    │
                     │                  injects fake CH       │
                     │                             │          │
                     └─────────────────────────────┼──────────┘
                                                   │
                                          ┌────────▼─────────┐
                                          │  WinDivert 2.2.x   │
                                          │  (kernel driver) │
                                          └──────────────────┘
```

### Packet Flow

1. The client connects to `LISTEN_HOST:LISTEN_PORT`.
2. The proxy opens an outgoing socket to `CONNECT_IP:CONNECT_PORT`.
3. `FakeTcpInjector`, through WinDivert, intercepts the SYN/SYN-ACK/ACK sequence of the outgoing TCP handshake.
4. Once the three-way handshake completes, the injector **injects a fake `ClientHello` with a wrong TCP sequence number** (`wrong_seq`) to confuse DPI middleboxes.
5. The legitimate server's ACK of the fake data confirms that the bypass sequence completed, and the injector detaches.
6. A bidirectional `asyncio` relay takes over between the two sockets.

---

## 📦 Prerequisites

| Requirement    | Notes                                                                    |
| -------------- | ------------------------------------------------------------------------ |
| **OS**         | Windows 10/11 — WinDivert is Windows-only                                |
| **Python**     | **3.10–3.12** — this repository currently targets the PyDivert 3.x API          |
| **Privileges** | **Administrator** access is required to load the WinDivert kernel driver |
| **Antivirus**  | You may need an exclusion for the `pydivert` directory and `python.exe`  |

---

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/ItsWanheda/SNI-Spoofing.git
cd SNI-Spoofing
```

### 2. Install Python Dependencies

> [!WARNING]
> **Use Python 3.12 or earlier.** On Python 3.14, `pydivert` may import successfully, but the WinDivert handle may fail to bind.

```powershell
# Recommended: create a virtual environment
py -3.12 -m venv venv

# Activate the environment
.\venv\Scripts\Activate.ps1

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure `config.json`

Edit `config.json` in the project root.

See the [Configuration](#️-configuration) section for the complete schema.

### 4. Add Windows Defender Exclusions

> [!CAUTION]
> WinDivert operates at the kernel level and may be flagged by security software. Only create exclusions if you understand and accept the security implications.

Open **PowerShell as Administrator** and run:

```powershell
$divertPath = python -c "import pydivert, os; print(os.path.dirname(pydivert.__file__))"

Add-MpPreference -ExclusionPath $divertPath
Add-MpPreference -ExclusionPath "C:\Windows\System32\drivers\WinDivert2.2.sys"
Add-MpPreference -ExclusionProcess "python.exe"
Add-MpPreference -ExclusionProcess "py.exe"
```

If you're using a corporate device where UAC elevation is blocked, add the required paths through:

**Windows Security → Virus & threat protection → Exclusions**

### 5. Run the Proxy

Run the application from the **same elevated PowerShell session** with the virtual environment active:

```powershell
python SNI.py
```

Expected output:

```text
@ItsWanheda - SNI Proxy Overhauled
SNI Proxy listening on 127.0.0.1:8080
Forwarding to 1.2.3.4:443 (interface: 192.168.1.10)
```

---

## ⚙️ Configuration

All runtime settings are stored in `config.json` next to `SNI.py`.

### Example Configuration

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

### Configuration Reference

| Key            | Type          | Description                                                                                                                 | Default              |
| -------------- | ------------- | --------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| `LISTEN_HOST`  | string        | Local IP address the proxy binds to. Use `127.0.0.1` for local-only access or `0.0.0.0` to accept connections from the LAN. | `127.0.0.1`          |
| `LISTEN_PORT`  | int `1–65535` | Local port used by the proxy.                                                                                               | `8080`               |
| `CONNECT_IP`   | string        | Target server IP address, supporting IPv4/IPv6.                                                                             | *required*           |
| `CONNECT_PORT` | int `1–65535` | Target server port, usually `443`.                                                                                          | *required*           |
| `TLS_VERSION`  | `1.2 \| 1.3`  | TLS version encoded in the fake `ClientHello`.                                                                              | `1.2`                |
| `SNI_LIST`     | list[string]  | Pool of fake SNIs. One is selected randomly for each connection.                                                            | `["www.google.com"]` |
| `MAX_RETRIES`  | int `0–100`   | Number of connection attempts before giving up.                                                                             | `3`                  |
| `RETRY_DELAY`  | float `0–60`  | Delay in seconds between retry attempts.                                                                                    | `2`                  |

Configuration is validated at startup. Invalid values cause a clear error message and a clean exit.

---

## 🚀 Usage

### Basic Run

In an elevated PowerShell session with the virtual environment active:

```powershell
python SNI.py
```

### Point Your Application at the Proxy

Configure your client — such as a browser, `curl`, game, or other application — to use:

```text
127.0.0.1:8080
```

as the appropriate proxy endpoint for your integration.

> **Note:** This repository provides the SNI-spoofing engine. Client-side proxy configuration is handled externally.

### Graceful Shutdown

Press `Ctrl+C` once.

The proxy will:

* Close all open sockets.
* Tear down active injectors.
* Cancel in-flight relay tasks.
* Exit cleanly.

---

## 🧪 Testing

The unit-test suite is intentionally runnable without the WinDivert kernel driver:

```powershell
python -m unittest discover -s tests -v
```

The tests currently cover:

- ClientHello construction and parse/rebuild round trips.
- ClientHello input validation.
- Client response round trips.
- ServerHello construction and parse/rebuild round trips.
- Basic `config.json` structure and port validation.

GitHub Actions runs the unit tests on Python 3.10, 3.11, and 3.12.

> **Important:** Passing the unit tests does not mean the full packet-interception path has been validated. End-to-end testing requires a supported Windows environment and WinDivert.

---

## 🔧 Troubleshooting

### ❌ `ModuleNotFoundError: No module named 'pydivert'`

Install `pydivert` inside your active virtual environment:

```powershell
pip install pydivert
```

Make sure the virtual environment is active:

```powershell
.\venv\Scripts\Activate.ps1
```

---

### ❌ `ImportError: cannot import name 'PyDivert' from 'pydivert'`

The class was renamed in `pydivert ≥ 2.0`.

Use:

```python
WinDivert
```

instead of:

```python
PyDivert
```

This repository already uses the updated API.

---

### ❌ `RuntimeError: WinDivert handle is not open`

**Likely causes, in order:**

1. **Not running as Administrator**
   Open an elevated PowerShell session.

2. **Antivirus is blocking WinDivert**
   Review the exclusions described in the installation section.

3. **Unsupported Python version**
   Python 3.13/3.14 is not supported by the current `pydivert` setup.

   Recreate the environment using Python 3.12:

   ```powershell
   py -3.12 -m venv venv
   .\venv\Scripts\Activate.ps1
   pip install pydivert
   ```

---

### ❌ `WinDivert1.4.sys` Driver Not Found

Check the driver service:

```powershell
sc query WinDivert1.4
```

If the service is not running, reinstall `pydivert`:

```powershell
pip install --force-reinstall pydivert
```

---

### ❌ `Access is denied` When Adding Defender Exclusions

The PowerShell session is probably not elevated.

Right-click PowerShell and select:

**Run as administrator**

Alternatively, use:

**Windows Security → Virus & threat protection → Exclusions**

---

### ❌ `Address already in use`

Another process is already using `LISTEN_PORT`.

Check which process owns port `8080`:

```powershell
netstat -ano | findstr :8080
```

Then terminate the conflicting process if appropriate:

```powershell
taskkill /PID <pid> /F
```

Alternatively, change `LISTEN_PORT` in `config.json`.

---

### ❌ Connections Succeed but DPI Still Blocks

Check the following:

* Verify that the fake `ClientHello` ACK was received.

* Look for:

  ```text
  Fake-data ACK received for ...; handshake complete.
  ```

* Try another entry from `SNI_LIST`.

* Confirm that `BYPASS_METHOD` is supported. The current implementation supports only:

  ```text
  wrong_seq
  ```

---

## 🛡️ Security Considerations

* **Run only on networks you own or are explicitly authorized to test.** Bypassing DPI may violate local laws, organizational policies, or terms of service.
* The proxy has **no authentication on the listening socket**. Do not bind to `0.0.0.0` on a public or untrusted network unless you add appropriate access controls.
* The injected `ClientHello` is forged. Legitimate servers may observe an unusual or mismatched handshake pattern and could rate-limit or block traffic.
* Source IP addresses in `config.json` must be valid and are checked with `inet_pton` at startup to prevent invalid filter configuration.

---

## 🤝 Contributing

Contributions are welcome.

1. Fork the repository.

2. Create a feature branch:

   ```bash
   git checkout -b feature/amazing-feature
   ```

3. Commit your changes:

   ```bash
   git commit -m "feat: add amazing feature"
   ```

4. Push the branch:

   ```bash
   git push origin feature/amazing-feature
   ```

5. Open a Pull Request.

Commit messages follow **[Conventional Commits](https://www.conventionalcommits.org/)**.

---

## 📄 License

This project is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for details.

---

## 📞 Contact

* **GitHub:** [ItsWanheda](https://github.com/ItsWanheda)
* **Email:** [Wanheda.work@gmail.com](mailto:Wanheda.work@gmail.com)
* **Maintainer:** **ItsWanheda**

---

> [!IMPORTANT]
> **Disclaimer:** This tool is intended for educational and legitimate privacy purposes only. Users are responsible for complying with all applicable laws, regulations, network policies, and terms of service in their jurisdiction. Misuse of this tool to bypass security measures or access unauthorized resources is strictly prohibited.
