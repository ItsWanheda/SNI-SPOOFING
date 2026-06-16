# SNI-Spoofing

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

Bypass DPI with IP/TCP-Header manipulation
A high-performance, configurable SNI (Server Name Indication) spoofing tool designed for network analysis, privacy testing, and educational purposes. This tool allows users to manipulate the TLS handshake process to mask the true destination of network traffic.

> **⚠️ Disclaimer:** This tool is intended for **authorized security testing, educational research, and privacy protection only**. Unauthorized use of SNI spoofing to bypass security controls or access restricted networks without explicit permission is illegal and unethical. Use at your own risk.

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)

## Features

- **Dynamic SNI Rotation:** Randomly selects SNI from a configurable list for each connection to avoid fingerprinting.
- **Multi-Protocol Support:** Supports both IPv4 and IPv6.
- **TLS 1.2 & 1.3 Compatibility:** Generates realistic TLS ClientHello packets with proper extensions (Key Share, Supported Groups, etc.).
- **Robust Error Handling:** Includes retry logic for remote connections and graceful shutdown handling.
- **Thread-Safe Packet Injection:** Uses `pydivert` to manipulate packets at the network stack level with thread-safe state management.
- **Configurable:** All settings (listen port, target IP, SNI list, TLS version) are managed via `config.json`.

## 🏗️ Architecture
```text
graph TD
    A[User Input] --> B[SNI Spoofing Engine]
    B --> C{TLS Handshake}
    C -->|Modified ClientHello| D[Target Server]
    D -->|ServerHello| C
    C --> E[Data Exchange]
    E --> F[Output/Logging]
```

## 📦 Prerequisites
- **Python 3.8+**
- **Windows OS** (Required for `pydivert` to function correctly with the current implementation).
- **Administrator Privileges** (Required to run the script, as it needs to hook into the network stack).

### Installation
1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Install dependencies:**
    ```bash
    pip install pydivert
    ```

3.  **Configure the proxy:**
    Edit the `config.json` file to set your desired parameters:
    ```json
    {
        "LISTEN_HOST": "127.0.0.1",
        "LISTEN_PORT": 1080,
        "CONNECT_IP": "1.2.3.4",
        "CONNECT_PORT": 443,
        "SNI_LIST": ["www.google.com", "www.youtube.com"],
        "TLS_VERSION": "1.3",
        "MAX_RETRIES": 3,
        "RETRY_DELAY": 2
    }
    ```
    - `LISTEN_HOST/PORT`: The local address where clients will connect.
    - `CONNECT_IP/PORT`: The target server address to forward traffic to.
    - `SNI_LIST`: A list of fake SNIs to rotate through.
    - `TLS_VERSION`: Either "1.2" or "1.3".

### Running the Proxy

Run the script with **Administrator privileges**:

```bash
python SNI.py
```
## 🚀 Usage
Basic Example
    Spoof the SNI to example.com while connecting to IP 192.168.1.1:
        python main.py --target 192.168.1.1 --port 443 --sni example.com
Advanced Options
    python SNI.py \
    --target 10.0.0.5 \
    --port 443 \
    --sni spoofed-domain.com \
    --disable-ssl-verification \

## ⚙️ Configuration
    Open config.json and edit the Defualt Configuration
    {
    "LISTEN_HOST": "0.0.0.0", ==> Change it to 192.0.0.27 or Something Else
    "LISTEN_PORT": 40443, ==> You Can Change It Or Leave it be
    "CONNECT_IP": "188.114.98.0", ==> DNS IPs
    "CONNECT_PORT": 443, 
    "FAKE_SNI": "auth.vercel.com" ==> The Website or Hostname that you want to Sni
    }

## 🤝 Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (git checkout -b feature/amazing-feature).
3. Commit your changes (git commit -m 'Add amazing feature').
4. Push to the branch (git push origin feature/amazing-feature).
5. Open a Pull Request.

## 📄 License
This project is licensed under the GNU GENERAL PUBLIC LICENSE - see the LICENSE file for details.

## 📞 Contact
GitHub: [https://github.com/ItsWanheda]
Email: Wanheda.work@gmail.com
Project Maintainer: ItsWanheda

Disclaimer
```
This tool is intended for educational and legitimate privacy purposes only. Users are responsible for complying with all applicable laws and regulations in their jurisdiction. Misuse of this tool to bypass security measures or access unauthorized resources is strictly prohibited.
```
