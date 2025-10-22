# 🌟 Features Documentation

Complete feature list and technical documentation for Advanced Port Scanner v3.0

---

## 📑 Table of Contents

1. [Scan Types](#scan-types)
2. [Multi-Target Support](#multi-target-support)
3. [Security Analysis](#security-analysis)
4. [Output Formats](#output-formats)
5. [Performance Features](#performance-features)
6. [Web Dashboard](#web-dashboard)
7. [Advanced Features](#advanced-features)

---

## 🔍 Scan Types

### TCP Connect Scan
**Default scan type, no root required**

```bash
python3 port_scanner.py -t target -p 80 -s tcp
```

**How it works:**
- Completes full TCP 3-way handshake
- Most reliable but easily detected
- Works without root privileges
- Best for: General scanning, compatibility

**Advantages:**
- ✅ No special privileges needed
- ✅ Most accurate results
- ✅ Works on all systems

**Disadvantages:**
- ❌ Easily logged by target
- ❌ Slower than SYN scan
- ❌ More detectable

---

### SYN Scan (Stealth)
**Half-open scan, requires root**

```bash
sudo python3 port_scanner.py -t target -p 80 -s syn
```

**How it works:**
- Sends SYN packet
- Waits for SYN-ACK (open) or RST (closed)
- Sends RST to close connection
- Never completes handshake

**Advantages:**
- ✅ Faster than TCP connect
- ✅ Less likely to be logged
- ✅ Stealthier

**Disadvantages:**
- ❌ Requires root/admin privileges
- ❌ Requires scapy library
- ❌ May be blocked by firewalls

---

### FIN Scan
**Stealth scan using FIN flag, requires root**

```bash
sudo python3 port_scanner.py -t target -p 80 -s fin
```

**How it works:**
- Sends TCP packet with FIN flag
- Open ports: No response
- Closed ports: RST response

**Advantages:**
- ✅ Can bypass some firewalls
- ✅ Less detectable than SYN
- ✅ Good for firewall testing

**Disadvantages:**
- ❌ Requires root privileges
- ❌ May not work on Windows
- ❌ Results can be ambiguous

---

### NULL Scan
**Sends packet with no flags, requires root**

```bash
sudo python3 port_scanner.py -t target -p 80 -s null
```

**How it works:**
- Sends TCP packet with no flags set
- Open ports: No response
- Closed ports: RST response

**Advantages:**
- ✅ Very stealthy
- ✅ Can evade some IDS
- ✅ Good for testing firewall rules

**Disadvantages:**
- ❌ Requires root privileges
- ❌ Doesn't work on Windows
- ❌ May be blocked by modern firewalls

---

### XMAS Scan
**Sends packet with FIN, PSH, URG flags, requires root**

```bash
sudo python3 port_scanner.py -t target -p 80 -s xmas
```

**How it works:**
- Sends TCP packet with FIN, PSH, URG flags
- Open ports: No response
- Closed ports: RST response
- Named "XMAS" because flags light up like a Christmas tree

**Advantages:**
- ✅ Very stealthy
- ✅ Can bypass some packet filters
- ✅ Good for IDS evasion

**Disadvantages:**
- ❌ Requires root privileges
- ❌ Doesn't work on Windows
- ❌ May trigger IDS alerts

---

### UDP Scan
**Scans UDP ports**

```bash
python3 port_scanner.py -t target -p 53,67,161 -s udp
```

**How it works:**
- Sends UDP packet to port
- Open: Response or no response
- Closed: ICMP port unreachable

**Advantages:**
- ✅ Scans UDP services
- ✅ Finds DNS, DHCP, SNMP servers

**Disadvantages:**
- ❌ Slower than TCP scans
- ❌ Less reliable
- ❌ Difficult to determine open vs filtered

---

## 🎯 Multi-Target Support

### Single Target
```bash
python3 port_scanner.py -t 192.168.1.1 -p 80
```

### Multiple IPs (Comma-Separated)
```bash
python3 port_scanner.py -t 192.168.1.1,192.168.1.2,192.168.1.3 -p 80
```

### IP Range
```bash
python3 port_scanner.py -t 192.168.1.1-192.168.1.50 -p 80
```
Scans all IPs from 192.168.1.1 to 192.168.1.50

### CIDR Notation
```bash
python3 port_scanner.py -t 192.168.1.0/24 -p 80
```
Scans entire /24 subnet (254 hosts)

### File Input
```bash
# Create targets.txt
cat > targets.txt << EOF
192.168.1.1
192.168.1.2
example.com
10.0.0.0/24
EOF

# Scan all targets
python3 port_scanner.py --target-file targets.txt -p 80
```

**Features:**
- ✅ Supports comments (lines starting with #)
- ✅ Supports all target formats in file
- ✅ Automatic target validation
- ✅ Individual reports per target

---

## 🛡️ Security Analysis

### Vulnerability Scanning

**Detects 10+ known CVEs:**

```bash
python3 port_scanner.py -t target -p 1-1000 --vuln-scan -v
```

**Checks for:**
- Apache vulnerabilities (CVE-2011-3192, CVE-2021-41773, etc.)
- OpenSSH vulnerabilities (CVE-2018-15473, CVE-2018-15919)
- ProFTPD vulnerabilities (CVE-2010-4221)
- vsftpd backdoor (CVE-2011-2523)
- nginx vulnerabilities (CVE-2017-7529)
- Microsoft IIS vulnerabilities (CVE-2017-7269)
- Samba vulnerabilities (CVE-2017-7494)

**Output includes:**
- CVE identifiers
- Vulnerability descriptions
- Affected versions
- Severity ratings

---

### SSL/TLS Analysis

```bash
python3 port_scanner.py -t target -p 443 --ssl-scan -v
```

**Detects weak protocols:**
- SSLv2 (DROWN Attack - CVE-2016-0800)
- SSLv3 (POODLE Attack - CVE-2014-3566)
- TLSv1.0 (BEAST Attack - CVE-2011-3389)
- TLSv1.1 (Deprecated protocol)

**Checks:**
- Protocol versions
- Certificate validity
- Cipher suites
- Certificate expiration

---

### OS Fingerprinting

```bash
sudo python3 port_scanner.py -t target -p 80 --os-detection -v
```

**Detection methods:**
- TTL (Time To Live) analysis
- TCP Window Size analysis
- ICMP responses

**Can identify:**
- Linux/Unix systems (TTL 64)
- Windows systems (TTL 128)
- Cisco devices (TTL 255)
- Confidence level (0-100%)

---

### WAF/IDS Detection

```bash
python3 port_scanner.py -t target -p 80 --detect-waf -v
```

**Detects:**
- Web Application Firewalls (WAF)
  - Cloudflare
  - Incapsula
  - Imperva
  - F5 BIG-IP
  - Barracuda
  - FortiWeb
  - ModSecurity

- Intrusion Detection Systems (IDS)
  - High filtered port ratio
  - Unusual response patterns
  - Timeout patterns

**Output includes:**
- Detection confidence (0-100%)
- Identified systems
- Detection indicators
- Recommendations

---

## 📊 Output Formats

### JSON Format
```bash
python3 port_scanner.py -t target -p 80 -o scan.json -f json
```

**Features:**
- Machine-readable
- Complete scan data
- Easy to parse
- API-friendly

**Use cases:**
- Automation
- Integration with other tools
- Data analysis
- Archiving

---

### XML Format (Nmap Compatible)
```bash
python3 port_scanner.py -t target -p 80 -o scan.xml -f xml
```

**Features:**
- Nmap-compatible format
- Works with Nmap tools
- Standard format
- Widely supported

**Compatible with:**
- Nmap
- Zenmap
- Metasploit
- Other security tools

---

### HTML Format
```bash
python3 port_scanner.py -t target -p 80 -o report.html -f html
```

**Features:**
- Professional web report
- Beautiful gradient design
- Interactive tables
- Statistics dashboard
- Vulnerability highlights
- Responsive layout

**Includes:**
- Target information
- Scan statistics
- Port details table
- Service information
- Vulnerability list
- OS detection results

---

### CSV Format
```bash
python3 port_scanner.py -t target -p 80 -o scan.csv -f csv
```

**Features:**
- Excel-compatible
- Easy to import
- Tabular format

**Use cases:**
- Spreadsheet analysis
- Reporting
- Data manipulation

---

### TXT Format
```bash
python3 port_scanner.py -t target -p 80 -o scan.txt -f txt
```

**Features:**
- Human-readable
- Plain text
- Easy to read

**Use cases:**
- Quick review
- Documentation
- Email reports

---

## ⚡ Performance Features

### Speed Presets

#### Slow
```bash
python3 port_scanner.py -t target -p 1-1000 --speed slow
```
- Timeout: 3.0s
- Threads: 10
- Best for: Unstable connections, avoiding detection

#### Normal (Default)
```bash
python3 port_scanner.py -t target -p 1-1000 --speed normal
```
- Timeout: 1.0s
- Threads: 50
- Best for: General use, balanced performance

#### Fast
```bash
python3 port_scanner.py -t target -p 1-1000 --speed fast
```
- Timeout: 0.5s
- Threads: 200
- Best for: Local networks, quick scans

#### Aggressive
```bash
python3 port_scanner.py -t target -p 1-1000 --speed aggressive
```
- Timeout: 0.3s
- Threads: 500
- Best for: High-speed networks, maximum performance

---

### Custom Performance Tuning

```bash
python3 port_scanner.py -t target -p 1-1000 \
    -T 300 \
    --timeout 0.5
```

**Parameters:**
- `-T, --threads`: Number of concurrent threads (10-500)
- `--timeout`: Connection timeout in seconds (0.1-10.0)

**Performance tips:**
- Local network: High threads (200-500), low timeout (0.3-0.5s)
- Internet: Moderate threads (50-100), higher timeout (1-2s)
- Unstable network: Low threads (10-50), high timeout (2-5s)

---

## 🌐 Web Dashboard

### Starting Dashboard
```bash
python3 port_scanner.py --web-dashboard
```

Access at: `http://localhost:8080`

### Features

#### Real-Time Statistics
- Total scans performed
- Active scans running
- Total open ports found
- Total vulnerabilities detected

#### Scan Management
- Start new scans from browser
- Configure scan parameters
- Select scan types
- Choose output formats

#### Results Viewer
- View recent scans
- See scan details
- Download results
- Auto-refresh every 5 seconds

#### Responsive Design
- Works on desktop
- Works on mobile
- Modern UI
- Beautiful gradients

---

## 🔧 Advanced Features

### Scan Comparison

```bash
# First scan
python3 port_scanner.py -t target -p 1-1000 -o scan1.json

# Second scan (later)
python3 port_scanner.py -t target -p 1-1000 -o scan2.json

# Compare
python3 port_scanner.py --compare scan1.json -o scan2.json
```

**Shows:**
- New open ports
- Closed ports
- Service changes
- Banner changes
- Summary statistics

**Use cases:**
- Change detection
- Monitoring
- Compliance checking
- Security audits

---

### Port Presets

#### Common Ports
```bash
python3 port_scanner.py -t target --preset common
```
Scans most common 70+ ports

#### Top 100
```bash
python3 port_scanner.py -t target --preset top100
```
Scans top 100 most common ports

#### Top 1000
```bash
python3 port_scanner.py -t target --preset top1000
```
Scans ports 1-1000

#### All Ports
```bash
python3 port_scanner.py -t target --preset all
```
Scans all 65535 ports (takes time!)

---

### Verbose Mode

```bash
python3 port_scanner.py -t target -p 80 -v
```

**Shows:**
- Real-time port status
- Connection attempts
- Service detection
- Banner grabbing
- Vulnerability checks
- Progress updates

---

### Service Detection

**Automatically detects 70+ services:**
- Web: HTTP, HTTPS, HTTP-Alt
- Mail: SMTP, POP3, IMAP, SMTPS, POP3S, IMAPS
- File Transfer: FTP, FTPS, TFTP, NFS
- Remote Access: SSH, Telnet, RDP, VNC
- Databases: MySQL, PostgreSQL, MSSQL, MongoDB, Redis, CouchDB
- Other: DNS, DHCP, SNMP, LDAP, SMB, and more

---

### Banner Grabbing

**Supported protocols:**
- HTTP/HTTPS
- FTP
- SSH
- SMTP
- MySQL
- Generic TCP

**Information gathered:**
- Server software
- Version numbers
- Operating system hints
- Service banners

---

## 🎓 Best Practices

### 1. Start Small
```bash
# Test with a few ports first
python3 port_scanner.py -t target -p 80,443 -v
```

### 2. Use Appropriate Scan Type
- **TCP**: General purpose, no root needed
- **SYN**: Faster, stealthier, needs root
- **FIN/NULL/XMAS**: Firewall evasion, needs root

### 3. Save Results
```bash
# Always save output
python3 port_scanner.py -t target -p 80 -o scan.json
```

### 4. Use Verbose Mode
```bash
# See what's happening
python3 port_scanner.py -t target -p 80 -v
```

### 5. Respect Rate Limits
```bash
# Don't overwhelm targets
python3 port_scanner.py -t target -p 1-1000 --speed normal
```

---

## ⚠️ Limitations

### Technical Limitations
- UDP scanning is less reliable than TCP
- Some firewalls may block all scan types
- OS detection requires open ports
- WAF detection may have false positives

### Legal Limitations
- Only scan systems you own
- Get written permission for pen tests
- Respect network policies
- Follow local laws

---

## 🔮 Future Features

Coming in future versions:
- Exploit suggestions
- Shodan integration
- Custom scan scripts
- API server mode
- Machine learning detection
- Distributed scanning

---

**For more information, see README.md and QUICKSTART.md**
