# 🚀 Quick Start Guide

Get started with Advanced Port Scanner in 5 minutes!

---

## 📦 Installation

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Make executable (optional)
chmod +x port_scanner.py

# 3. Test installation
python3 port_scanner.py --help
```

---

## 🎯 Your First Scan

### 1. Basic Scan
```bash
# Scan common ports on localhost
python3 port_scanner.py -t 127.0.0.1 --preset common -v
```

### 2. Scan Specific Ports
```bash
# Scan web server ports
python3 port_scanner.py -t example.com -p 80,443,8080 -v
```

### 3. Scan Port Range
```bash
# Scan first 1000 ports
python3 port_scanner.py -t 192.168.1.1 -p 1-1000 -v
```

---

## 🔥 Common Use Cases

### Web Server Audit
```bash
python3 port_scanner.py -t webserver.com \
    -p 80,443,8080,8443 \
    --vuln-scan --ssl-scan \
    -o web_audit.html -f html -v
```

### Network Discovery
```bash
# Scan entire subnet
python3 port_scanner.py -t 192.168.1.0/24 \
    --preset common \
    --speed fast \
    -o network.json -f json
```

### Security Assessment
```bash
# Full security scan (requires root)
sudo python3 port_scanner.py -t target.com \
    -p 1-1000 -s syn \
    --vuln-scan --ssl-scan --os-detection --detect-waf \
    -o security_audit.html -f html -v
```

### Stealth Scan
```bash
# Use XMAS scan for stealth (requires root)
sudo python3 port_scanner.py -t target.com \
    -p 1-1000 -s xmas \
    --speed slow \
    -o stealth.xml -f xml
```

---

## 🌐 Web Dashboard

### Start Dashboard
```bash
python3 port_scanner.py --web-dashboard
```

### Access Dashboard
Open browser: `http://localhost:8080`

Features:
- Start scans from web interface
- Real-time monitoring
- View scan history
- Download results

---

## 📊 Output Formats

### JSON (Default)
```bash
python3 port_scanner.py -t target -p 80 -o scan.json -f json
```

### HTML Report
```bash
python3 port_scanner.py -t target -p 80 -o report.html -f html
```

### XML (Nmap Compatible)
```bash
python3 port_scanner.py -t target -p 80 -o scan.xml -f xml
```

### CSV
```bash
python3 port_scanner.py -t target -p 80 -o scan.csv -f csv
```

### Plain Text
```bash
python3 port_scanner.py -t target -p 80 -o scan.txt -f txt
```

---

## 🎯 Multi-Target Scanning

### CIDR Notation
```bash
python3 port_scanner.py -t 192.168.1.0/24 -p 80,443
```

### IP Range
```bash
python3 port_scanner.py -t 192.168.1.1-192.168.1.50 -p 22,80
```

### Multiple IPs
```bash
python3 port_scanner.py -t 192.168.1.1,192.168.1.2,192.168.1.3 -p 80
```

### From File
```bash
# Create targets.txt
echo "192.168.1.1" > targets.txt
echo "192.168.1.2" >> targets.txt
echo "example.com" >> targets.txt

# Scan all
python3 port_scanner.py --target-file targets.txt -p 80,443
```

---

## 🔍 Scan Types

### TCP Connect (Default)
```bash
python3 port_scanner.py -t target -p 80 -s tcp
```

### SYN Scan (Stealth, requires root)
```bash
sudo python3 port_scanner.py -t target -p 80 -s syn
```

### FIN Scan (Stealth, requires root)
```bash
sudo python3 port_scanner.py -t target -p 80 -s fin
```

### NULL Scan (Stealth, requires root)
```bash
sudo python3 port_scanner.py -t target -p 80 -s null
```

### XMAS Scan (Stealth, requires root)
```bash
sudo python3 port_scanner.py -t target -p 80 -s xmas
```

### UDP Scan
```bash
python3 port_scanner.py -t target -p 53,67,161 -s udp
```

---

## ⚡ Speed Optimization

### Speed Presets
```bash
# Slow (timeout: 3s, threads: 10)
python3 port_scanner.py -t target -p 1-1000 --speed slow

# Normal (timeout: 1s, threads: 50)
python3 port_scanner.py -t target -p 1-1000 --speed normal

# Fast (timeout: 0.5s, threads: 200)
python3 port_scanner.py -t target -p 1-1000 --speed fast

# Aggressive (timeout: 0.3s, threads: 500)
python3 port_scanner.py -t target -p 1-1000 --speed aggressive
```

### Custom Settings
```bash
# Custom threads and timeout
python3 port_scanner.py -t target -p 1-1000 \
    -T 300 --timeout 0.5
```

---

## 🛡️ Security Features

### Vulnerability Scan
```bash
python3 port_scanner.py -t target -p 1-1000 --vuln-scan -v
```

### SSL/TLS Analysis
```bash
python3 port_scanner.py -t target -p 443 --ssl-scan -v
```

### OS Detection (requires root)
```bash
sudo python3 port_scanner.py -t target -p 80 --os-detection -v
```

### WAF/IDS Detection
```bash
python3 port_scanner.py -t target -p 80 --detect-waf -v
```

### All Security Features
```bash
sudo python3 port_scanner.py -t target -p 1-1000 \
    --vuln-scan --ssl-scan --os-detection --detect-waf \
    -o full_security.html -f html -v
```

---

## 📈 Scan Comparison

```bash
# First scan
python3 port_scanner.py -t target -p 1-1000 -o scan1.json

# Wait some time...

# Second scan
python3 port_scanner.py -t target -p 1-1000 -o scan2.json

# Compare scans
python3 port_scanner.py --compare scan1.json -o scan2.json
```

Output shows:
- New open ports
- Closed ports
- Service changes
- Summary statistics

---

## 🔧 Troubleshooting

### Scapy Not Available
```bash
# Install scapy
pip install scapy

# Or use TCP scan (no scapy needed)
python3 port_scanner.py -t target -p 80 -s tcp
```

### Permission Denied
```bash
# Use sudo for SYN/FIN/NULL/XMAS scans
sudo python3 port_scanner.py -t target -p 80 -s syn
```

### Slow Scanning
```bash
# Increase threads and use fast preset
python3 port_scanner.py -t target -p 1-1000 --speed fast
```

### Web Dashboard Not Starting
```bash
# Install Flask
pip install flask

# Start dashboard
python3 port_scanner.py --web-dashboard
```

---

## 💡 Pro Tips

1. **Start Small**: Test with a few ports first
2. **Use Presets**: `--preset common` for quick scans
3. **Verbose Mode**: Add `-v` to see real-time progress
4. **Save Results**: Always use `-o` to save output
5. **Legal Use**: Only scan systems you own or have permission to test

---

## 📚 Next Steps

- Read full documentation: `README.md`
- Check changelog: `CHANGELOG.md`
- View all options: `python3 port_scanner.py --help`
- Try web dashboard: `python3 port_scanner.py --web-dashboard`

---

## ⚠️ Legal Notice

**Only scan systems you own or have explicit permission to test.**

Unauthorized scanning is illegal and can result in:
- Criminal charges
- Civil lawsuits
- Network bans

**Be responsible. Be ethical. Be legal.**

---

**Happy Scanning! 🚀**
