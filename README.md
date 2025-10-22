# 🔍 Advanced Port Scanner v3.0

**A comprehensive, professional-grade port scanning tool with advanced features**

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🌟 Features

### Core Scanning Capabilities
- ✅ **6 Scan Types**: TCP Connect, UDP, SYN, FIN, NULL, XMAS
- ✅ **Multi-Target Support**: IP ranges, CIDR notation, comma-separated lists, file input
- ✅ **70+ Service Detection**: Automatic service identification
- ✅ **Banner Grabbing**: HTTP, FTP, SSH, SMTP, MySQL protocols
- ✅ **High Performance**: 100-2000 ports/second with multi-threading

### Security Analysis
- 🛡️ **Vulnerability Scanning**: 10+ CVE checks for common services
- 🛡️ **SSL/TLS Analysis**: Detects weak protocols (SSLv2, SSLv3, TLS1.0, TLS1.1)
- 🛡️ **OS Fingerprinting**: TTL and TCP Window analysis
- 🛡️ **WAF/IDS Detection**: Identifies security systems
- 🛡️ **Scan Comparison**: Track changes between scans

### Output & Reporting
- 📊 **5 Output Formats**: JSON, CSV, TXT, HTML, XML (Nmap compatible)
- 📊 **Professional HTML Reports**: Beautiful, interactive web reports
- 📊 **XML Compatibility**: Works with Nmap tools
- 📊 **Web Dashboard**: Real-time monitoring and visualization

### Advanced Features
- ⚡ **Speed Presets**: Slow, Normal, Fast, Aggressive
- ⚡ **Customizable Threading**: 10-500 concurrent threads
- ⚡ **Timeout Control**: Adjustable connection timeouts
- ⚡ **Verbose Mode**: Detailed real-time output
- ⚡ **Port Presets**: Common, Top100, Top1000, All

---

## 📦 Installation

### Requirements
- Python 3.7 or higher
- Root/sudo access (for SYN, FIN, NULL, XMAS scans and OS detection)

### Quick Install

```bash
# Clone or download the repository
cd port-scanner

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x port_scanner.py
```

### Dependencies
```
scapy>=2.4.5    # For advanced scan types (optional)
flask>=2.0.0    # For web dashboard (optional)
```

---

## 🚀 Quick Start

### Basic Scan
```bash
# Scan common ports
python3 port_scanner.py -t 192.168.1.1 --preset common

# Scan specific ports
python3 port_scanner.py -t example.com -p 80,443,8080

# Scan port range
python3 port_scanner.py -t 192.168.1.1 -p 1-1000
```

### Advanced Scans
```bash
# Full security scan with HTML report
python3 port_scanner.py -t 192.168.1.1 -p 1-1000 \
    --vuln-scan --ssl-scan --detect-waf \
    -o report.html -f html -v

# SYN scan (stealth)
sudo python3 port_scanner.py -t 192.168.1.1 -p 1-1000 -s syn

# Fast aggressive scan
python3 port_scanner.py -t 192.168.1.1 --preset top1000 --speed aggressive
```

### Multi-Target Scanning
```bash
# CIDR notation
python3 port_scanner.py -t 192.168.1.0/24 -p 80,443

# IP range
python3 port_scanner.py -t 192.168.1.1-192.168.1.50 -p 22,80

# Multiple IPs
python3 port_scanner.py -t 192.168.1.1,192.168.1.2,192.168.1.3 -p 80

# From file
python3 port_scanner.py --target-file targets.txt -p 1-1000
```

### Web Dashboard
```bash
# Start web interface
python3 port_scanner.py --web-dashboard

# Access at http://localhost:8080
```

---

## 📖 Usage Guide

### Command Line Options

#### Target Options
```
-t, --target          Target IP/hostname (supports: IP, range, CIDR, comma-separated)
--target-file         File containing targets (one per line)
```

#### Port Options
```
-p, --ports           Ports to scan (e.g., 80, 80-100, 80,443,8080)
--preset              Use preset port list (common, top100, top1000, all)
```

#### Scan Types
```
-s, --scan-type       Scan type (default: tcp)
    tcp               TCP Connect scan (default, no root required)
    udp               UDP scan
    syn               SYN scan (stealth, requires root)
    fin               FIN scan (stealth, requires root)
    null              NULL scan (stealth, requires root)
    xmas              XMAS scan (stealth, requires root)
```

#### Performance Options
```
-T, --threads         Number of threads (default: 100)
--timeout             Connection timeout in seconds (default: 1.0)
--speed               Speed preset (slow, normal, fast, aggressive)
```

#### Security Options
```
--vuln-scan          Enable vulnerability scanning
--ssl-scan           Enable SSL/TLS vulnerability scanning
--os-detection       Enable OS detection (requires root)
--detect-waf         Detect WAF/IDS/IPS systems
```

#### Output Options
```
-o, --output         Output file path
-f, --format         Output format (json, csv, txt, html, xml)
-v, --verbose        Enable verbose output
```

#### Advanced Options
```
--compare            Compare with previous scan (JSON file)
--web-dashboard      Start web dashboard
```

---

## 💡 Examples

### Example 1: Quick Web Server Scan
```bash
python3 port_scanner.py -t example.com -p 80,443,8080,8443 -v
```

### Example 2: Comprehensive Security Audit
```bash
sudo python3 port_scanner.py -t 192.168.1.100 -p 1-65535 \
    -s syn --vuln-scan --ssl-scan --os-detection --detect-waf \
    -o full_audit.html -f html -v
```

### Example 3: Network Sweep
```bash
python3 port_scanner.py -t 192.168.1.0/24 --preset common \
    --speed fast -o network_scan.json -f json
```

### Example 4: Stealth Scan
```bash
sudo python3 port_scanner.py -t target.com -p 1-1000 \
    -s xmas --speed slow -o stealth_scan.xml -f xml
```

### Example 5: Database Server Scan
```bash
python3 port_scanner.py -t db-server.local \
    -p 3306,5432,1433,27017,6379 \
    --vuln-scan -v
```

### Example 6: Compare Scans
```bash
# First scan
python3 port_scanner.py -t 192.168.1.1 -p 1-1000 -o scan1.json

# Second scan (later)
python3 port_scanner.py -t 192.168.1.1 -p 1-1000 -o scan2.json

# Compare
python3 port_scanner.py --compare scan1.json -o scan2.json
```

### Example 7: Bulk Scanning from File
```bash
# Create targets.txt
echo "192.168.1.1" > targets.txt
echo "192.168.1.2" >> targets.txt
echo "example.com" >> targets.txt

# Scan all targets
python3 port_scanner.py --target-file targets.txt \
    --preset top100 -o bulk_scan.html -f html
```

---

## 📊 Output Formats

### JSON Format
```json
{
    "target": "example.com",
    "target_ip": "93.184.216.34",
    "scan_type": "tcp",
    "start_time": "2025-10-22T04:51:12",
    "duration": 1.23,
    "open_ports": 2,
    "results": {
        "80": {
            "status": "open",
            "service": "HTTP",
            "banner": "Apache/2.4.41"
        }
    }
}
```

### XML Format (Nmap Compatible)
```xml
<?xml version="1.0" ?>
<nmaprun scanner="advanced-port-scanner" version="3.0">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="HTTP"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

### HTML Report
Professional, interactive web report with:
- Beautiful gradient design
- Statistics dashboard
- Port details table
- Vulnerability highlights
- OS detection results
- Responsive layout

---

## 🛡️ Security Features

### Vulnerability Detection
Checks for known vulnerabilities in:
- Apache (CVE-2011-3192, CVE-2021-41773, etc.)
- OpenSSH (CVE-2018-15473, CVE-2018-15919)
- ProFTPD, vsftpd, nginx, IIS, Samba
- And more...

### SSL/TLS Analysis
Detects weak protocols:
- SSLv2 (DROWN Attack)
- SSLv3 (POODLE Attack)
- TLSv1.0 (BEAST Attack)
- TLSv1.1 (Deprecated)

### WAF/IDS Detection
Identifies security systems:
- Cloudflare, Incapsula, Imperva
- F5, Barracuda, FortiWeb
- ModSecurity
- Custom IDS/IPS systems

---

## 🌐 Web Dashboard

Start the web dashboard for real-time monitoring:

```bash
python3 port_scanner.py --web-dashboard
```

Features:
- 📊 Real-time statistics
- 🎯 Start scans from browser
- 📈 View scan history
- 💾 Download results
- 📱 Responsive design

Access at: `http://localhost:8080`

---

## ⚠️ Legal Disclaimer

**IMPORTANT: This tool is for educational and authorized security testing ONLY.**

- ✅ **Legal Use**: Your own systems, authorized penetration tests
- ❌ **Illegal Use**: Unauthorized scanning, accessing systems without permission

Unauthorized port scanning may be illegal in your jurisdiction and can result in:
- Criminal charges
- Civil lawsuits
- Network bans
- Legal prosecution

**Always obtain written permission before scanning any network or system you do not own.**

---

## 🔧 Troubleshooting

### "Scapy not available" Warning
```bash
# Install scapy for advanced features
pip install scapy

# Or use TCP scan (no scapy required)
python3 port_scanner.py -t target -p 80 -s tcp
```

### "Permission denied" Error
```bash
# SYN, FIN, NULL, XMAS scans require root
sudo python3 port_scanner.py -t target -p 80 -s syn
```

### Slow Scanning
```bash
# Increase threads and reduce timeout
python3 port_scanner.py -t target -p 1-1000 -T 300 --timeout 0.5

# Or use speed preset
python3 port_scanner.py -t target -p 1-1000 --speed aggressive
```

### Web Dashboard Not Starting
```bash
# Install Flask
pip install flask

# Check if port 8080 is available
netstat -tuln | grep 8080
```

---

## 📈 Performance Tips

1. **Local Network**: Use high thread count (200-500) and low timeout (0.3-0.5s)
2. **Internet Scanning**: Use moderate threads (50-100) and higher timeout (1-2s)
3. **Stealth Scanning**: Use slow speed preset and SYN/FIN/NULL/XMAS scans
4. **Large Port Ranges**: Use aggressive speed preset or increase threads
5. **Firewall Detection**: Use multiple scan types to identify filtered ports

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

---

## 📝 Version History

### v3.0.0 (2025-10-22)
- ✨ Added multi-target support (IP ranges, CIDR, file input)
- ✨ Added XML output format (Nmap compatible)
- ✨ Added FIN, NULL, XMAS scan techniques
- ✨ Added WAF/IDS detection
- ✨ Added scan comparison feature
- ✨ Added web dashboard
- 🔧 Improved performance and stability
- 📚 Enhanced documentation

### v2.0.0 (Previous)
- Added vulnerability scanning
- Added SSL/TLS analysis
- Added OS fingerprinting
- Added HTML reports

### v1.0.0 (Initial)
- Basic TCP/UDP/SYN scanning
- Service detection
- JSON/CSV output

---

## 📄 License

MIT License - See LICENSE file for details

---

## 👨‍💻 Author

Advanced Port Scanner v3.0

---

## 🙏 Acknowledgments

- Inspired by Nmap
- Built with Python, Scapy, and Flask
- Community feedback and contributions

---

**Happy Scanning! 🚀**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
