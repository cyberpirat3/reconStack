# Reconstack

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Bash 4.0+](https://img.shields.io/badge/Bash-4.0+-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)

## 📋 Prerequisites

### System Requirements
- Linux (Kali Linux recommended)
- Python 3.8 or higher
- Bash 4.0 or higher
- Git

### Required System Packages
```bash
# For Debian/Ubuntu/Kali
sudo apt update
sudo apt install -y \
    python3-pip \
    python3-venv \
    git \
    jq \
    curl \
    dnsutils \
    nmap \
    subfinder \
    sublist3r \
    amass \
    gobuster \
    dirsearch \
    dnsx \
    httpx
```

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/reconstack.git
   cd reconstack
   ```

2. **Set up a Python virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Make the script executable:**
   ```bash
   chmod +x reconstack.sh
   ```

## 📦 Dependencies

### Core Tools
- **Amass** - For subdomain enumeration
- **Sublist3r** - For subdomain enumeration
- **GoBuster** - For directory brute-forcing
- **dirsearch** - For web path discovery
- **httpx** - For HTTP probing
- **dnsx** - For DNS resolution
- **altdns** - For subdomain permutation

### Python Packages
- `requests` - For HTTP requests
- `beautifulsoup4` - For HTML parsing
- `colorama` - For colored console output

## 🔧 Configuration

1. **SecLists Integration:**
   The tool automatically looks for SecLists in `/usr/share/seclists`. If you have it installed elsewhere, update the `SECLISTS` variable in the script.

2. **Custom Wordlists:**
   You can specify custom wordlists by modifying the following variables in the script:
   - `DEFAULT_DIR_LIST` - For directory brute-forcing
   - `DEFAULT_DNS_LIST` - For subdomain enumeration

## 🛠️ Usage

```bash
# Basic usage
./reconstack.sh example.com

# Full scan with all modules
./reconstack.sh -m all example.com

# Subdomain enumeration only
./reconstack.sh -m subs-only example.com

# Directory brute-forcing only
./reconstack.sh -m dir-only example.com

# Scan multiple targets from a file
./reconstack.sh -l targets.txt

# Specify output directory
./reconstack.sh -o /path/to/results example.com
```

## 📝 Notes

- Run with sudo if you encounter permission issues with certain tools
- For best results, ensure all required tools are in your system PATH
- The script creates a new directory for each target in the specified output directory

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
