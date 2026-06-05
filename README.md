Bypass DPI with IP/TCP-Header manipulation

# SNI-Spoofing

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

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

## ✨ Features

- **Dynamic SNI Manipulation:** Easily override the SNI field in the ClientHello packet.
- **Certificate Validation Control:** Option to disable or enforce strict SSL/TLS certificate verification.
- **Multi-Protocol Support:** Supports TCP, UDP, and custom protocol wrappers.
- **Logging & Debugging:** Comprehensive logging for network traffic analysis.
- **Lightweight & Fast:** Built for low-latency operations with minimal overhead.
- **Configurable Payloads:** Customizable headers and handshake parameters.

## 🏗️ Architecture

The tool operates at the application layer, intercepting or constructing TLS ClientHello messages. It modifies the `server_name` extension before sending the packet to the target server.

```mermaid
graph TD
    A[User Input] --> B[SNI Spoofing Engine]
    B --> C{TLS Handshake}
    C -->|Modified ClientHello| D[Target Server]
    D -->|ServerHello| C
    C --> E[Data Exchange]
    E --> F[Output/Logging]

## 📦 Prerequisites
- Python 3.8+
OpenSSL (system dependency)
Root/Administrator Privileges (required for raw socket manipulation, if applicable)
🛠️ Installation & Setup
    1. Clone the Repository
        git clone https://github.com/[Wanheda7737]/SNI-SPOOFING.git
        cd SNI-SPOOFING
    2. Create a Virtual Environment (Recommended)
        python -m venv venv
        source venv/bin/activate  # On Windows: venv\Scripts\activate
    3. Install Dependencies
        pip install -r requirements.txt
    4. Verify Installation
        python SNI.py --version

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
GitHub: [https://github.com/Wanheda7737]
Email: Wanheda.work@gmail.com
Project Maintainer: ItsWanheda