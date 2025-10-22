#!/bin/bash

# Advanced Port Scanner - Example Usage Scripts
# This script demonstrates various scanning scenarios

echo "=============================================="
echo "Advanced Port Scanner v3.0 - Examples"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Example 1: Basic TCP Scan
echo -e "${BLUE}Example 1: Basic TCP Scan${NC}"
echo "python3 port_scanner.py -t scanme.nmap.org -p 22,80,443 -v"
echo ""

# Example 2: Fast Network Sweep
echo -e "${BLUE}Example 2: Fast Network Sweep (CIDR)${NC}"
echo "python3 port_scanner.py -t 192.168.1.0/24 --preset common --speed fast"
echo ""

# Example 3: Stealth SYN Scan
echo -e "${BLUE}Example 3: Stealth SYN Scan (requires root)${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 -s syn -v"
echo ""

# Example 4: FIN Scan for Firewall Evasion
echo -e "${BLUE}Example 4: FIN Scan (requires root)${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 -s fin"
echo ""

# Example 5: NULL Scan
echo -e "${BLUE}Example 5: NULL Scan (requires root)${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 -s null"
echo ""

# Example 6: XMAS Scan
echo -e "${BLUE}Example 6: XMAS Scan (requires root)${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 -s xmas"
echo ""

# Example 7: Full Security Audit
echo -e "${BLUE}Example 7: Full Security Audit${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    --vuln-scan --ssl-scan --os-detection --detect-waf \\"
echo "    -o security_audit.html -f html -v"
echo ""

# Example 8: Multi-Target Scan
echo -e "${BLUE}Example 8: Multi-Target Scan${NC}"
echo "python3 port_scanner.py -t 192.168.1.1,192.168.1.2,192.168.1.3 -p 80,443"
echo ""

# Example 9: IP Range Scan
echo -e "${BLUE}Example 9: IP Range Scan${NC}"
echo "python3 port_scanner.py -t 192.168.1.1-192.168.1.50 -p 22,80,443"
echo ""

# Example 10: Scan from File
echo -e "${BLUE}Example 10: Scan from File${NC}"
echo "# Create targets.txt first:"
echo "echo '192.168.1.1' > targets.txt"
echo "echo '192.168.1.2' >> targets.txt"
echo "echo 'example.com' >> targets.txt"
echo ""
echo "python3 port_scanner.py --target-file targets.txt --preset common"
echo ""

# Example 11: Web Server Audit
echo -e "${BLUE}Example 11: Web Server Audit${NC}"
echo "python3 port_scanner.py -t webserver.com \\"
echo "    -p 80,443,8080,8443 \\"
echo "    --vuln-scan --ssl-scan \\"
echo "    -o web_audit.html -f html -v"
echo ""

# Example 12: Database Server Scan
echo -e "${BLUE}Example 12: Database Server Scan${NC}"
echo "python3 port_scanner.py -t db-server.local \\"
echo "    -p 3306,5432,1433,27017,6379 \\"
echo "    --vuln-scan -v"
echo ""

# Example 13: JSON Output
echo -e "${BLUE}Example 13: JSON Output${NC}"
echo "python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -o scan_results.json -f json"
echo ""

# Example 14: XML Output (Nmap Compatible)
echo -e "${BLUE}Example 14: XML Output (Nmap Compatible)${NC}"
echo "python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -o scan_results.xml -f xml"
echo ""

# Example 15: CSV Output
echo -e "${BLUE}Example 15: CSV Output${NC}"
echo "python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -o scan_results.csv -f csv"
echo ""

# Example 16: HTML Report
echo -e "${BLUE}Example 16: HTML Report${NC}"
echo "python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -o scan_report.html -f html"
echo ""

# Example 17: Aggressive Fast Scan
echo -e "${BLUE}Example 17: Aggressive Fast Scan${NC}"
echo "python3 port_scanner.py -t target.com --preset top1000 \\"
echo "    --speed aggressive -o fast_scan.json"
echo ""

# Example 18: Slow Stealth Scan
echo -e "${BLUE}Example 18: Slow Stealth Scan${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -s xmas --speed slow -o stealth_scan.xml -f xml"
echo ""

# Example 19: UDP Service Discovery
echo -e "${BLUE}Example 19: UDP Service Discovery${NC}"
echo "python3 port_scanner.py -t target.com \\"
echo "    -p 53,67,68,69,123,161,162 -s udp -v"
echo ""

# Example 20: Scan Comparison
echo -e "${BLUE}Example 20: Scan Comparison${NC}"
echo "# First scan"
echo "python3 port_scanner.py -t target.com -p 1-1000 -o scan1.json"
echo ""
echo "# Wait some time, then second scan"
echo "python3 port_scanner.py -t target.com -p 1-1000 -o scan2.json"
echo ""
echo "# Compare scans"
echo "python3 port_scanner.py --compare scan1.json -o scan2.json"
echo ""

# Example 21: Web Dashboard
echo -e "${BLUE}Example 21: Web Dashboard${NC}"
echo "python3 port_scanner.py --web-dashboard"
echo "# Then open browser: http://localhost:8080"
echo ""

# Example 22: Custom Threading
echo -e "${BLUE}Example 22: Custom Threading and Timeout${NC}"
echo "python3 port_scanner.py -t target.com -p 1-1000 \\"
echo "    -T 300 --timeout 0.5 -v"
echo ""

# Example 23: All Ports Scan
echo -e "${BLUE}Example 23: All Ports Scan (65535 ports - takes time!)${NC}"
echo "python3 port_scanner.py -t target.com --preset all \\"
echo "    --speed aggressive -o full_scan.json"
echo ""

# Example 24: WAF Detection
echo -e "${BLUE}Example 24: WAF/IDS Detection${NC}"
echo "python3 port_scanner.py -t target.com -p 80,443 \\"
echo "    --detect-waf -v"
echo ""

# Example 25: Complete Security Assessment
echo -e "${BLUE}Example 25: Complete Security Assessment${NC}"
echo "sudo python3 port_scanner.py -t target.com -p 1-65535 \\"
echo "    -s syn --vuln-scan --ssl-scan --os-detection --detect-waf \\"
echo "    --speed fast -o complete_assessment.html -f html -v"
echo ""

echo -e "${GREEN}=============================================="
echo "Usage Tips:"
echo "=============================================="
echo "1. Always use -v (verbose) to see real-time progress"
echo "2. Save results with -o and -f options"
echo "3. Use --preset for quick scans"
echo "4. Use speed presets for performance tuning"
echo "5. Stealth scans (SYN, FIN, NULL, XMAS) require root"
echo "6. Multi-target scanning saves time"
echo "7. Use web dashboard for easy management"
echo "8. Compare scans to track changes"
echo "9. XML format works with Nmap tools"
echo "10. HTML reports are great for documentation"
echo -e "${NC}"

echo -e "${YELLOW}=============================================="
echo "Performance Guidelines:"
echo "=============================================="
echo "Local Network:"
echo "  - Use --speed fast or aggressive"
echo "  - High thread count (200-500)"
echo "  - Low timeout (0.3-0.5s)"
echo ""
echo "Internet Scanning:"
echo "  - Use --speed normal"
echo "  - Moderate threads (50-100)"
echo "  - Higher timeout (1-2s)"
echo ""
echo "Stealth Scanning:"
echo "  - Use --speed slow"
echo "  - Low thread count (10-50)"
echo "  - Use FIN/NULL/XMAS scans"
echo -e "${NC}"

echo -e "${RED}=============================================="
echo "⚠️  LEGAL WARNING"
echo "=============================================="
echo "Only scan systems you own or have permission to test!"
echo ""
echo "Unauthorized scanning is ILLEGAL and can result in:"
echo "  - Criminal charges"
echo "  - Civil lawsuits"
echo "  - Network bans"
echo "  - Legal prosecution"
echo ""
echo "BE RESPONSIBLE. BE ETHICAL. BE LEGAL."
echo -e "${NC}"

echo ""
echo "For more information:"
echo "  - Full documentation: cat README.md"
echo "  - Quick start guide: cat QUICKSTART.md"
echo "  - Feature details: cat FEATURES.md"
echo "  - Help: python3 port_scanner.py --help"
echo ""
