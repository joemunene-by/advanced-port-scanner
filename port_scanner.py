#!/usr/bin/env python3
"""
Advanced Port Scanner v3.0
A comprehensive port scanning tool with multiple scanning modes and advanced features.

New Features:
- Multi-target support (IP ranges, CIDR, file input)
- XML output (Nmap compatible)
- FIN/NULL/XMAS scan techniques
- WAF/IDS detection
- Scan comparison
- Web dashboard
"""

import socket
import struct
import threading
import time
import json
import csv
import argparse
import sys
import os
import re
import ssl
import hashlib
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional, Set
import ipaddress
import random
import subprocess
import platform
from pathlib import Path
import difflib

# Try to import optional dependencies
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available. SYN scan and OS fingerprinting will be disabled.")

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Vulnerability signatures for common services
VULNERABILITY_SIGNATURES = {
    'Apache/2.2': ['CVE-2011-3192: Range Header DoS', 'CVE-2012-0053: Cookie Info Disclosure'],
    'Apache/2.4.49': ['CVE-2021-41773: Path Traversal and RCE'],
    'Apache/2.4.50': ['CVE-2021-42013: Path Traversal and RCE'],
    'OpenSSH_7.4': ['CVE-2018-15473: Username Enumeration'],
    'OpenSSH_7.7': ['CVE-2018-15919: Username Enumeration'],
    'ProFTPD 1.3.3': ['CVE-2010-4221: Telnet IAC Buffer Overflow'],
    'vsftpd 2.3.4': ['BACKDOOR: Backdoor Command Execution'],
    'nginx/1.10': ['CVE-2017-7529: Integer Overflow'],
    'Microsoft-IIS/6.0': ['CVE-2017-7269: WebDAV Buffer Overflow'],
    'Samba 3.5': ['CVE-2017-7494: Remote Code Execution'],
}

# SSL/TLS vulnerabilities
SSL_WEAK_PROTOCOLS = {
    'SSLv2': 'DROWN Attack (CVE-2016-0800)',
    'SSLv3': 'POODLE Attack (CVE-2014-3566)',
    'TLSv1.0': 'BEAST Attack (CVE-2011-3389)',
    'TLSv1.1': 'Deprecated Protocol'
}

# Common ports and their services
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD", 587: "SMTP", 631: "IPP", 636: "LDAPS",
    873: "Rsync", 989: "FTPS", 990: "FTPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker", 3000: "Node.js",
    3306: "MySQL", 3389: "RDP", 4369: "Erlang", 5000: "Flask",
    5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 6660: "IRC", 6661: "IRC", 6662: "IRC", 6663: "IRC",
    6664: "IRC", 6665: "IRC", 6666: "IRC", 6667: "IRC", 6668: "IRC",
    6669: "IRC", 7000: "Cassandra", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "SonarQube", 9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch", 10000: "Webmin",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB",
    50000: "SAP", 50070: "Hadoop"
}

class PortScanner:
    """Advanced port scanner with multiple scanning modes."""
    
    def __init__(self, target: str, ports: List[int], timeout: float = 1.0,
                 threads: int = 100, scan_type: str = "tcp", verbose: bool = False,
                 os_detection: bool = False, vuln_scan: bool = False, ssl_scan: bool = False):
        """
        Initialize the port scanner.
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan
            timeout: Connection timeout in seconds
            threads: Number of concurrent threads
            scan_type: Type of scan (tcp, udp, syn)
            verbose: Enable verbose output
        """
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
        self.scan_type = scan_type.lower()
        self.verbose = verbose
        self.os_detection = os_detection
        self.vuln_scan = vuln_scan
        self.ssl_scan = ssl_scan
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.results = {}
        self.vulnerabilities = {}
        self.os_info = {'os': 'Unknown', 'confidence': 0, 'details': []}
        self.lock = threading.Lock()
        self.start_time = None
        self.end_time = None
        
        # Resolve hostname to IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve hostname: {target}")
    
    def print_verbose(self, message: str):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(message)
    
    def get_service_name(self, port: int) -> str:
        """Get service name for a given port."""
        if port in COMMON_PORTS:
            return COMMON_PORTS[port]
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"
    
    def grab_banner(self, port: int) -> Optional[str]:
        """
        Attempt to grab banner from an open port.
        
        Args:
            port: Port number
            
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000, 8008, 8081, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
            # Send SMTP EHLO for mail services
            elif port in [25, 587]:
                sock.send(b"EHLO scanner\r\n")
            # Send SSH version request
            elif port == 22:
                pass  # SSH sends banner automatically
            # Send FTP request
            elif port in [21]:
                pass  # FTP sends banner automatically
            # Send MySQL handshake
            elif port == 3306:
                pass  # MySQL sends handshake automatically
            else:
                # Try to receive data without sending
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner if banner else None
        except:
            return None
    
    def check_ssl_vulnerabilities(self, port: int) -> List[str]:
        """
        Check for SSL/TLS vulnerabilities on a port.
        
        Args:
            port: Port number
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Check for weak protocols
            for protocol_name, protocol_const in [('SSLv2', None), ('SSLv3', ssl.PROTOCOL_SSLv23)]:
                if protocol_const:
                    try:
                        test_context = ssl.SSLContext(protocol_const)
                        test_context.check_hostname = False
                        test_context.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((self.target_ip, port), timeout=2) as sock:
                            with test_context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                                if protocol_name in SSL_WEAK_PROTOCOLS:
                                    vulnerabilities.append(SSL_WEAK_PROTOCOLS[protocol_name])
                    except:
                        pass
            
            # Get certificate info
            with socket.create_connection((self.target_ip, port), timeout=2) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Check certificate expiration
                        not_after = cert.get('notAfter')
                        if not_after:
                            from datetime import datetime
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            if expiry < datetime.now():
                                vulnerabilities.append('Expired SSL Certificate')
        except:
            pass
        
        return vulnerabilities
    
    def detect_service_vulnerabilities(self, banner: str) -> List[str]:
        """
        Detect known vulnerabilities based on service banner.
        
        Args:
            banner: Service banner string
            
        Returns:
            List of potential vulnerabilities
        """
        vulnerabilities = []
        
        if not banner:
            return vulnerabilities
        
        # Check against known vulnerable versions
        for service_version, vulns in VULNERABILITY_SIGNATURES.items():
            if service_version.lower() in banner.lower():
                vulnerabilities.extend(vulns)
        
        # Check for outdated software indicators
        if 'apache/2.2' in banner.lower() or 'apache/2.0' in banner.lower():
            vulnerabilities.append('Outdated Apache version detected')
        
        if 'openssh' in banner.lower():
            version_match = re.search(r'OpenSSH[_\s]([0-9.]+)', banner, re.IGNORECASE)
            if version_match:
                version = version_match.group(1)
                try:
                    major, minor = map(int, version.split('.')[:2])
                    if major < 7 or (major == 7 and minor < 4):
                        vulnerabilities.append('Outdated OpenSSH version')
                except:
                    pass
        
        return vulnerabilities
    
    def perform_os_detection(self):
        """
        Perform OS detection using various techniques.
        """
        if not SCAPY_AVAILABLE:
            self.print_verbose(f"{Colors.WARNING}[!] OS detection requires Scapy{Colors.ENDC}")
            return
        
        try:
            conf.verb = 0
            
            # Send ICMP echo request
            icmp_packet = IP(dst=self.target_ip)/ICMP()
            response = sr1(icmp_packet, timeout=2, verbose=0)
            
            if response:
                ttl = response.ttl
                
                # Analyze TTL
                if ttl <= 64:
                    if ttl > 32:
                        self.os_info['os'] = 'Linux/Unix'
                        self.os_info['confidence'] = 75
                        self.os_info['details'].append(f'TTL: {ttl} (typical for Linux)')
                elif ttl <= 128:
                    if ttl > 64:
                        self.os_info['os'] = 'Windows'
                        self.os_info['confidence'] = 75
                        self.os_info['details'].append(f'TTL: {ttl} (typical for Windows)')
                elif ttl <= 255:
                    if ttl > 128:
                        self.os_info['os'] = 'Cisco/Network Device'
                        self.os_info['confidence'] = 70
                        self.os_info['details'].append(f'TTL: {ttl} (typical for network devices)')
                
                # Check for TCP window size if we have open ports
                if self.open_ports and len(self.open_ports) > 0:
                    test_port = self.open_ports[0]
                    syn_packet = IP(dst=self.target_ip)/TCP(dport=test_port, flags='S')
                    syn_response = sr1(syn_packet, timeout=2, verbose=0)
                    
                    if syn_response and syn_response.haslayer(TCP):
                        window = syn_response[TCP].window
                        self.os_info['details'].append(f'TCP Window Size: {window}')
                        
                        # Windows typically has larger window sizes
                        if window >= 8192:
                            if 'Windows' in self.os_info['os']:
                                self.os_info['confidence'] = min(90, self.os_info['confidence'] + 15)
                        
                        # Send RST to close
                        rst_packet = IP(dst=self.target_ip)/TCP(dport=test_port, flags='R')
                        sr1(rst_packet, timeout=1, verbose=0)
        except Exception as e:
            self.print_verbose(f"{Colors.WARNING}[!] OS detection error: {str(e)}{Colors.ENDC}")
    
    def tcp_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform TCP connect scan on a port.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                banner = self.grab_banner(port)
                
                # Check for vulnerabilities if enabled
                port_vulns = []
                if self.vuln_scan and banner:
                    port_vulns = self.detect_service_vulnerabilities(banner)
                
                # Check SSL vulnerabilities if enabled
                if self.ssl_scan and port in [443, 8443, 465, 993, 995, 636]:
                    ssl_vulns = self.check_ssl_vulnerabilities(port)
                    port_vulns.extend(ssl_vulns)
                
                with self.lock:
                    self.open_ports.append(port)
                    self.results[port] = {
                        'status': 'open',
                        'service': service,
                        'banner': banner,
                        'vulnerabilities': port_vulns
                    }
                    if port_vulns:
                        self.vulnerabilities[port] = port_vulns
                
                vuln_indicator = f" {Colors.FAIL}[VULN!]{Colors.ENDC}" if port_vulns else ""
                self.print_verbose(f"{Colors.OKGREEN}[+] Port {port} is OPEN - {service}{vuln_indicator}{Colors.ENDC}")
                return port, 'open', service, banner
            else:
                with self.lock:
                    self.closed_ports.append(port)
                return port, 'closed', None, None
        except socket.timeout:
            with self.lock:
                self.filtered_ports.append(port)
            return port, 'filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error scanning port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def udp_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform UDP scan on a port.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (self.target_ip, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                service = self.get_service_name(port)
                banner = data.decode('utf-8', errors='ignore').strip() if data else None
                with self.lock:
                    self.open_ports.append(port)
                    self.results[port] = {
                        'status': 'open',
                        'service': service,
                        'banner': banner
                    }
                self.print_verbose(f"{Colors.OKGREEN}[+] Port {port}/UDP is OPEN - {service}{Colors.ENDC}")
                sock.close()
                return port, 'open', service, banner
            except socket.timeout:
                # No response might mean open or filtered
                with self.lock:
                    self.filtered_ports.append(port)
                self.print_verbose(f"{Colors.WARNING}[?] Port {port}/UDP is OPEN|FILTERED{Colors.ENDC}")
                sock.close()
                return port, 'open|filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error scanning UDP port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def syn_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform SYN scan (stealth scan) on a port.
        Requires root privileges and scapy.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}[!] Scapy is required for SYN scan{Colors.ENDC}")
            return port, 'error', None, None
        
        try:
            # Disable scapy verbosity
            conf.verb = 0
            
            # Create SYN packet
            src_port = random.randint(1024, 65535)
            ip_packet = IP(dst=self.target_ip)
            syn_packet = TCP(sport=src_port, dport=port, flags='S', seq=1000)
            
            # Send packet and wait for response
            response = sr1(ip_packet/syn_packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                with self.lock:
                    self.filtered_ports.append(port)
                return port, 'filtered', None, None
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    # Send RST to close connection
                    rst_packet = TCP(sport=src_port, dport=port, flags='R', seq=response.ack)
                    sr1(ip_packet/rst_packet, timeout=self.timeout, verbose=0)
                    
                    service = self.get_service_name(port)
                    with self.lock:
                        self.open_ports.append(port)
                        self.results[port] = {
                            'status': 'open',
                            'service': service,
                            'banner': None
                        }
                    self.print_verbose(f"{Colors.OKGREEN}[+] Port {port} is OPEN - {service}{Colors.ENDC}")
                    return port, 'open', service, None
                elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
                    with self.lock:
                        self.closed_ports.append(port)
                    return port, 'closed', None, None
            elif response.haslayer(ICMP):
                with self.lock:
                    self.filtered_ports.append(port)
                return port, 'filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error in SYN scan on port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def fin_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform FIN scan on a port.
        Sends TCP packet with FIN flag. Open ports don't respond, closed ports send RST.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}[!] Scapy is required for FIN scan{Colors.ENDC}")
            return port, 'error', None, None
        
        try:
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            ip_packet = IP(dst=self.target_ip)
            fin_packet = TCP(sport=src_port, dport=port, flags='F')
            
            response = sr1(ip_packet/fin_packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                # No response = open or filtered
                service = self.get_service_name(port)
                with self.lock:
                    self.open_ports.append(port)
                    self.results[port] = {'status': 'open|filtered', 'service': service, 'banner': None}
                self.print_verbose(f"{Colors.OKGREEN}[+] Port {port} is OPEN|FILTERED - {service}{Colors.ENDC}")
                return port, 'open|filtered', service, None
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
                with self.lock:
                    self.closed_ports.append(port)
                return port, 'closed', None, None
            elif response.haslayer(ICMP):
                with self.lock:
                    self.filtered_ports.append(port)
                return port, 'filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error in FIN scan on port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def null_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform NULL scan on a port.
        Sends TCP packet with no flags. Open ports don't respond, closed ports send RST.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}[!] Scapy is required for NULL scan{Colors.ENDC}")
            return port, 'error', None, None
        
        try:
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            ip_packet = IP(dst=self.target_ip)
            null_packet = TCP(sport=src_port, dport=port, flags='')
            
            response = sr1(ip_packet/null_packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                service = self.get_service_name(port)
                with self.lock:
                    self.open_ports.append(port)
                    self.results[port] = {'status': 'open|filtered', 'service': service, 'banner': None}
                self.print_verbose(f"{Colors.OKGREEN}[+] Port {port} is OPEN|FILTERED - {service}{Colors.ENDC}")
                return port, 'open|filtered', service, None
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                with self.lock:
                    self.closed_ports.append(port)
                return port, 'closed', None, None
            elif response.haslayer(ICMP):
                with self.lock:
                    self.filtered_ports.append(port)
                return port, 'filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error in NULL scan on port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def xmas_scan(self, port: int) -> Tuple[int, str, Optional[str], Optional[str]]:
        """
        Perform XMAS scan on a port.
        Sends TCP packet with FIN, PSH, and URG flags. Open ports don't respond, closed ports send RST.
        
        Args:
            port: Port number
            
        Returns:
            Tuple of (port, status, service, banner)
        """
        if not SCAPY_AVAILABLE:
            print(f"{Colors.FAIL}[!] Scapy is required for XMAS scan{Colors.ENDC}")
            return port, 'error', None, None
        
        try:
            conf.verb = 0
            src_port = random.randint(1024, 65535)
            ip_packet = IP(dst=self.target_ip)
            xmas_packet = TCP(sport=src_port, dport=port, flags='FPU')
            
            response = sr1(ip_packet/xmas_packet, timeout=self.timeout, verbose=0)
            
            if response is None:
                service = self.get_service_name(port)
                with self.lock:
                    self.open_ports.append(port)
                    self.results[port] = {'status': 'open|filtered', 'service': service, 'banner': None}
                self.print_verbose(f"{Colors.OKGREEN}[+] Port {port} is OPEN|FILTERED - {service}{Colors.ENDC}")
                return port, 'open|filtered', service, None
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                with self.lock:
                    self.closed_ports.append(port)
                return port, 'closed', None, None
            elif response.haslayer(ICMP):
                with self.lock:
                    self.filtered_ports.append(port)
                return port, 'filtered', None, None
        except Exception as e:
            self.print_verbose(f"{Colors.FAIL}[!] Error in XMAS scan on port {port}: {str(e)}{Colors.ENDC}")
            return port, 'error', None, None
    
    def detect_waf_ids(self) -> Dict[str, any]:
        """
        Detect presence of WAF/IDS/IPS by analyzing responses.
        
        Returns:
            Dictionary with detection results
        """
        detection_results = {
            'waf_detected': False,
            'ids_detected': False,
            'indicators': [],
            'confidence': 0
        }
        
        if not self.open_ports:
            return detection_results
        
        try:
            # Test with HTTP port if available
            http_ports = [p for p in self.open_ports if p in [80, 8080, 8000, 8008]]
            
            if http_ports:
                test_port = http_ports[0]
                
                # Send suspicious requests
                test_payloads = [
                    b"GET /../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n",
                    b"GET /?id=1' OR '1'='1 HTTP/1.1\r\nHost: test\r\n\r\n",
                    b"GET /<script>alert(1)</script> HTTP/1.1\r\nHost: test\r\n\r\n"
                ]
                
                for payload in test_payloads:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        sock.connect((self.target_ip, test_port))
                        sock.send(payload)
                        response = sock.recv(4096).decode('utf-8', errors='ignore')
                        sock.close()
                        
                        # Check for WAF signatures
                        waf_signatures = [
                            'cloudflare', 'incapsula', 'imperva', 'f5', 'barracuda',
                            'fortiweb', 'modsecurity', 'blocked', 'forbidden', 'access denied'
                        ]
                        
                        response_lower = response.lower()
                        for sig in waf_signatures:
                            if sig in response_lower:
                                detection_results['waf_detected'] = True
                                detection_results['indicators'].append(f"WAF signature found: {sig}")
                                detection_results['confidence'] += 20
                        
                        # Check for unusual response codes
                        if '406' in response or '418' in response or '419' in response:
                            detection_results['waf_detected'] = True
                            detection_results['indicators'].append("Unusual HTTP response code")
                            detection_results['confidence'] += 15
                            
                    except:
                        pass
            
            # Check for filtered ports (IDS indicator)
            if len(self.filtered_ports) > len(self.open_ports) * 0.3:
                detection_results['ids_detected'] = True
                detection_results['indicators'].append("High ratio of filtered ports")
                detection_results['confidence'] += 25
            
            detection_results['confidence'] = min(100, detection_results['confidence'])
            
        except Exception as e:
            self.print_verbose(f"{Colors.WARNING}[!] WAF/IDS detection error: {str(e)}{Colors.ENDC}")
        
        return detection_results
    
    def scan_port(self, port: int):
        """
        Scan a single port based on scan type.
        
        Args:
            port: Port number
        """
        if self.scan_type == 'tcp':
            return self.tcp_scan(port)
        elif self.scan_type == 'udp':
            return self.udp_scan(port)
        elif self.scan_type == 'syn':
            return self.syn_scan(port)
        elif self.scan_type == 'fin':
            return self.fin_scan(port)
        elif self.scan_type == 'null':
            return self.null_scan(port)
        elif self.scan_type == 'xmas':
            return self.xmas_scan(port)
        else:
            raise ValueError(f"Invalid scan type: {self.scan_type}")
    
    def scan(self):
        """Execute the port scan."""
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}Advanced Port Scanner{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKCYAN}[*] Target: {self.target} ({self.target_ip}){Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Scan Type: {self.scan_type.upper()}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Ports to scan: {len(self.ports)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Timeout: {self.timeout}s{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Threads: {self.threads}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")
        
        self.start_time = time.time()
        
        # Scan ports using thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    port = futures[future]
                    print(f"{Colors.FAIL}[!] Exception scanning port {port}: {str(e)}{Colors.ENDC}")
        
        self.end_time = time.time()
        
        # Perform OS detection if enabled
        if self.os_detection and self.open_ports:
            print(f"\n{Colors.OKCYAN}[*] Performing OS detection...{Colors.ENDC}")
            self.perform_os_detection()
        
        self.print_summary()
    
    def print_summary(self):
        """Print scan summary."""
        duration = self.end_time - self.start_time
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}Scan Summary{Colors.ENDC}")
        print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
        
        print(f"{Colors.OKGREEN}[+] Open Ports: {len(self.open_ports)}{Colors.ENDC}")
        print(f"{Colors.FAIL}[-] Closed Ports: {len(self.closed_ports)}{Colors.ENDC}")
        print(f"{Colors.WARNING}[?] Filtered Ports: {len(self.filtered_ports)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Scan Duration: {duration:.2f} seconds{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Scan Rate: {len(self.ports)/duration:.2f} ports/sec{Colors.ENDC}\n")
        
        if self.open_ports:
            print(f"{Colors.OKGREEN}{Colors.BOLD}Open Ports Details:{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'PORT':<10}{'SERVICE':<20}{'BANNER'}{Colors.ENDC}")
            print(f"{Colors.OKGREEN}{'-'*60}{Colors.ENDC}")
            
            for port in sorted(self.open_ports):
                info = self.results[port]
                service = info['service']
                banner = info['banner'][:40] + '...' if info['banner'] and len(info['banner']) > 40 else info['banner']
                banner_str = banner if banner else 'N/A'
                vuln_marker = f" {Colors.FAIL}[!]{Colors.ENDC}" if port in self.vulnerabilities else ""
                print(f"{Colors.OKGREEN}{port:<10}{service:<20}{banner_str}{vuln_marker}{Colors.ENDC}")
        
        # Print OS detection results
        if self.os_detection and self.os_info['os'] != 'Unknown':
            print(f"\n{Colors.HEADER}{Colors.BOLD}OS Detection Results:{Colors.ENDC}")
            print(f"{Colors.OKCYAN}[*] OS: {self.os_info['os']}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}[*] Confidence: {self.os_info['confidence']}%{Colors.ENDC}")
            if self.os_info['details']:
                print(f"{Colors.OKCYAN}[*] Details:{Colors.ENDC}")
                for detail in self.os_info['details']:
                    print(f"{Colors.OKCYAN}    - {detail}{Colors.ENDC}")
        
        # Print vulnerability summary
        if self.vulnerabilities:
            print(f"\n{Colors.FAIL}{Colors.BOLD}Vulnerabilities Found:{Colors.ENDC}")
            for port, vulns in sorted(self.vulnerabilities.items()):
                print(f"{Colors.WARNING}[!] Port {port}:{Colors.ENDC}")
                for vuln in vulns:
                    print(f"{Colors.WARNING}    - {vuln}{Colors.ENDC}")
        
        print(f"\n{Colors.OKCYAN}[*] Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}\n")
    
    def save_results(self, output_file: str, format: str = 'json'):
        """
        Save scan results to file.
        
        Args:
            output_file: Output file path
            format: Output format (json, csv, txt)
        """
        if format == 'json':
            self._save_json(output_file)
        elif format == 'csv':
            self._save_csv(output_file)
        elif format == 'txt':
            self._save_txt(output_file)
        elif format == 'html':
            self._save_html(output_file)
        elif format == 'xml':
            self._save_xml(output_file)
        else:
            raise ValueError(f"Invalid format: {format}")
        
        print(f"{Colors.OKGREEN}[+] Results saved to: {output_file}{Colors.ENDC}")
    
    def _save_json(self, output_file: str):
        """Save results in JSON format."""
        data = {
            'target': self.target,
            'target_ip': self.target_ip,
            'scan_type': self.scan_type,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time).isoformat(),
            'duration': self.end_time - self.start_time,
            'total_ports': len(self.ports),
            'open_ports': len(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'filtered_ports': len(self.filtered_ports),
            'os_detection': self.os_info if self.os_detection else None,
            'vulnerabilities': self.vulnerabilities if self.vuln_scan or self.ssl_scan else None,
            'results': self.results
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
    
    def _save_csv(self, output_file: str):
        """Save results in CSV format."""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service', 'Banner', 'Vulnerabilities'])
            
            for port in sorted(self.ports):
                if port in self.results:
                    info = self.results[port]
                    vulns = '; '.join(info.get('vulnerabilities', [])) if info.get('vulnerabilities') else ''
                    writer.writerow([port, info['status'], info['service'], info['banner'], vulns])
                elif port in self.closed_ports:
                    writer.writerow([port, 'closed', '', '', ''])
                elif port in self.filtered_ports:
                    writer.writerow([port, 'filtered', '', '', ''])
    
    def _save_txt(self, output_file: str):
        """Save results in TXT format."""
        with open(output_file, 'w') as f:
            f.write(f"Port Scan Report\n")
            f.write(f"{'='*60}\n\n")
            f.write(f"Target: {self.target} ({self.target_ip})\n")
            f.write(f"Scan Type: {self.scan_type.upper()}\n")
            f.write(f"Start Time: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"End Time: {datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {self.end_time - self.start_time:.2f} seconds\n\n")
            
            f.write(f"Summary:\n")
            f.write(f"  Open Ports: {len(self.open_ports)}\n")
            f.write(f"  Closed Ports: {len(self.closed_ports)}\n")
            f.write(f"  Filtered Ports: {len(self.filtered_ports)}\n\n")
            
            if self.open_ports:
                f.write(f"Open Ports Details:\n")
                f.write(f"{'PORT':<10}{'SERVICE':<20}{'BANNER'}\n")
                f.write(f"{'-'*60}\n")
                
                for port in sorted(self.open_ports):
                    info = self.results[port]
                    service = info['service']
                    banner = info['banner'] if info['banner'] else 'N/A'
                    f.write(f"{port:<10}{service:<20}{banner}\n")
            
            # Add OS detection results
            if self.os_detection and self.os_info['os'] != 'Unknown':
                f.write(f"\nOS Detection:\n")
                f.write(f"  OS: {self.os_info['os']}\n")
                f.write(f"  Confidence: {self.os_info['confidence']}%\n")
                if self.os_info['details']:
                    f.write(f"  Details:\n")
                    for detail in self.os_info['details']:
                        f.write(f"    - {detail}\n")
            
            # Add vulnerabilities
            if self.vulnerabilities:
                f.write(f"\nVulnerabilities Found:\n")
                for port, vulns in sorted(self.vulnerabilities.items()):
                    f.write(f"  Port {port}:\n")
                    for vuln in vulns:
                        f.write(f"    - {vuln}\n")
    
    def _save_html(self, output_file: str):
        """Save results in HTML format with styling."""
        duration = self.end_time - self.start_time
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scan Report - {self.target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .content {{
            padding: 40px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }}
        .info-card h3 {{
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .info-card p {{
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-box {{
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            color: white;
        }}
        .stat-box.open {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}
        .stat-box.closed {{
            background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        }}
        .stat-box.filtered {{
            background: linear-gradient(135deg, #f2994a 0%, #f2c94c 100%);
        }}
        .stat-box h3 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .stat-box p {{
            font-size: 1em;
            opacity: 0.9;
        }}
        .section {{
            margin: 40px 0;
        }}
        .section h2 {{
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        thead {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
        }}
        th {{
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        tbody tr {{
            border-bottom: 1px solid #e0e0e0;
            transition: background 0.3s;
        }}
        tbody tr:hover {{
            background: #f8f9fa;
        }}
        tbody tr:nth-child(even) {{
            background: #fafafa;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        .badge.open {{
            background: #38ef7d;
            color: white;
        }}
        .badge.vuln {{
            background: #eb3349;
            color: white;
        }}
        .vuln-list {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .vuln-item {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 5px;
        }}
        .vuln-item strong {{
            color: #dc3545;
        }}
        .os-detection {{
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #11998e 0%, #38ef7d 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Port Scan Report</h1>
            <p>Advanced Network Security Assessment</p>
        </div>
        
        <div class="content">
            <div class="info-grid">
                <div class="info-card">
                    <h3>Target</h3>
                    <p>{self.target}</p>
                </div>
                <div class="info-card">
                    <h3>IP Address</h3>
                    <p>{self.target_ip}</p>
                </div>
                <div class="info-card">
                    <h3>Scan Type</h3>
                    <p>{self.scan_type.upper()}</p>
                </div>
                <div class="info-card">
                    <h3>Duration</h3>
                    <p>{duration:.2f}s</p>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat-box open">
                    <h3>{len(self.open_ports)}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="stat-box closed">
                    <h3>{len(self.closed_ports)}</h3>
                    <p>Closed Ports</p>
                </div>
                <div class="stat-box filtered">
                    <h3>{len(self.filtered_ports)}</h3>
                    <p>Filtered Ports</p>
                </div>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: {(len(self.open_ports)/len(self.ports)*100) if self.ports else 0:.1f}%">
                    {(len(self.open_ports)/len(self.ports)*100) if self.ports else 0:.1f}% Open
                </div>
            </div>
"""
        
        # Add open ports table
        if self.open_ports:
            html_content += """
            <div class="section">
                <h2>📊 Open Ports Details</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Banner</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
"""
            for port in sorted(self.open_ports):
                info = self.results[port]
                service = info['service']
                banner = info['banner'][:50] + '...' if info['banner'] and len(info['banner']) > 50 else (info['banner'] or 'N/A')
                vuln_badge = '<span class="badge vuln">VULNERABLE</span>' if port in self.vulnerabilities else '<span class="badge open">SECURE</span>'
                
                html_content += f"""
                        <tr>
                            <td><strong>{port}</strong></td>
                            <td>{service}</td>
                            <td><code>{banner}</code></td>
                            <td>{vuln_badge}</td>
                        </tr>
"""
            html_content += """
                    </tbody>
                </table>
            </div>
"""
        
        # Add OS detection results
        if self.os_detection and self.os_info['os'] != 'Unknown':
            html_content += f"""
            <div class="section">
                <h2>💻 OS Detection Results</h2>
                <div class="os-detection">
                    <p><strong>Operating System:</strong> {self.os_info['os']}</p>
                    <p><strong>Confidence:</strong> {self.os_info['confidence']}%</p>
"""
            if self.os_info['details']:
                html_content += "<p><strong>Details:</strong></p><ul>"
                for detail in self.os_info['details']:
                    html_content += f"<li>{detail}</li>"
                html_content += "</ul>"
            html_content += """
                </div>
            </div>
"""
        
        # Add vulnerabilities
        if self.vulnerabilities:
            html_content += """
            <div class="section">
                <h2>⚠️ Vulnerabilities Found</h2>
                <div class="vuln-list">
"""
            for port, vulns in sorted(self.vulnerabilities.items()):
                html_content += f"""
                    <div class="vuln-item">
                        <strong>Port {port}:</strong>
                        <ul>
"""
                for vuln in vulns:
                    html_content += f"<li>{vuln}</li>"
                html_content += """
                        </ul>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""
        
        # Footer
        html_content += f"""
        </div>
        
        <div class="footer">
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Scan Rate: {len(self.ports)/duration:.2f} ports/sec | Total Ports Scanned: {len(self.ports)}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
    
    def _save_xml(self, output_file: str):
        """Save results in XML format (Nmap compatible)."""
        # Create root element
        root = ET.Element('nmaprun')
        root.set('scanner', 'advanced-port-scanner')
        root.set('start', str(int(self.start_time)))
        root.set('version', '3.0')
        
        # Add scan info
        scaninfo = ET.SubElement(root, 'scaninfo')
        scaninfo.set('type', self.scan_type)
        scaninfo.set('protocol', 'tcp' if self.scan_type in ['tcp', 'syn', 'fin', 'null', 'xmas'] else 'udp')
        scaninfo.set('numservices', str(len(self.ports)))
        
        # Add host information
        host = ET.SubElement(root, 'host')
        
        # Host status
        status = ET.SubElement(host, 'status')
        status.set('state', 'up')
        status.set('reason', 'user-set')
        
        # Address
        address = ET.SubElement(host, 'address')
        address.set('addr', self.target_ip)
        address.set('addrtype', 'ipv4')
        
        # Hostnames
        if self.target != self.target_ip:
            hostnames = ET.SubElement(host, 'hostnames')
            hostname = ET.SubElement(hostnames, 'hostname')
            hostname.set('name', self.target)
            hostname.set('type', 'user')
        
        # Ports
        ports_elem = ET.SubElement(host, 'ports')
        
        # Add all scanned ports
        for port in sorted(self.ports):
            port_elem = ET.SubElement(ports_elem, 'port')
            port_elem.set('protocol', 'tcp' if self.scan_type != 'udp' else 'udp')
            port_elem.set('portid', str(port))
            
            # Port state
            state_elem = ET.SubElement(port_elem, 'state')
            if port in self.open_ports:
                state_elem.set('state', 'open')
                state_elem.set('reason', 'syn-ack' if self.scan_type == 'syn' else 'response')
            elif port in self.closed_ports:
                state_elem.set('state', 'closed')
                state_elem.set('reason', 'reset')
            elif port in self.filtered_ports:
                state_elem.set('state', 'filtered')
                state_elem.set('reason', 'no-response')
            
            # Service information
            if port in self.results:
                info = self.results[port]
                service_elem = ET.SubElement(port_elem, 'service')
                service_elem.set('name', info.get('service', 'unknown'))
                if info.get('banner'):
                    service_elem.set('product', info['banner'][:50])
                
                # Add vulnerabilities if present
                if info.get('vulnerabilities'):
                    script_elem = ET.SubElement(port_elem, 'script')
                    script_elem.set('id', 'vulners')
                    script_elem.set('output', ', '.join(info['vulnerabilities']))
        
        # OS detection
        if self.os_detection and self.os_info.get('os') != 'Unknown':
            os_elem = ET.SubElement(host, 'os')
            osmatch = ET.SubElement(os_elem, 'osmatch')
            osmatch.set('name', self.os_info['os'])
            osmatch.set('accuracy', str(self.os_info['confidence']))
        
        # Run stats
        runstats = ET.SubElement(root, 'runstats')
        finished = ET.SubElement(runstats, 'finished')
        finished.set('time', str(int(self.end_time)))
        finished.set('elapsed', f"{self.end_time - self.start_time:.2f}")
        
        hosts_elem = ET.SubElement(runstats, 'hosts')
        hosts_elem.set('up', '1')
        hosts_elem.set('down', '0')
        hosts_elem.set('total', '1')
        
        # Pretty print XML
        xml_string = ET.tostring(root, encoding='unicode')
        dom = minidom.parseString(xml_string)
        pretty_xml = dom.toprettyxml(indent='  ')
        
        with open(output_file, 'w') as f:
            f.write(pretty_xml)


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port string into list of ports.
    Supports formats: 80, 80-100, 80,443,8080
    
    Args:
        port_string: Port specification string
        
    Returns:
        List of port numbers
    """
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(list(set(ports)))


def get_common_ports(preset: str) -> List[int]:
    """
    Get list of common ports based on preset.
    
    Args:
        preset: Port preset (top100, top1000, all)
        
    Returns:
        List of port numbers
    """
    if preset == 'top100':
        return list(COMMON_PORTS.keys())[:100]
    elif preset == 'top1000':
        return list(range(1, 1001))
    elif preset == 'all':
        return list(range(1, 65536))
    else:
        return list(COMMON_PORTS.keys())


def parse_targets(target_input: str, target_file: Optional[str] = None) -> List[str]:
    """
    Parse multiple targets from various input formats.
    
    Supports:
    - Single IP: 192.168.1.1
    - Multiple IPs: 192.168.1.1,192.168.1.2
    - IP range: 192.168.1.1-192.168.1.10
    - CIDR notation: 192.168.1.0/24
    - Hostname: example.com
    - File: targets.txt (one per line)
    
    Args:
        target_input: Target specification string
        target_file: Optional file containing targets
        
    Returns:
        List of target IP addresses/hostnames
    """
    targets = []
    
    # Read from file if specified
    if target_file:
        try:
            with open(target_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.extend(parse_targets(line))
            return targets
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error reading target file: {e}{Colors.ENDC}")
            return []
    
    # Parse target_input
    if not target_input:
        return []
    
    # Check if CIDR notation
    if '/' in target_input:
        try:
            network = ipaddress.ip_network(target_input, strict=False)
            targets.extend([str(ip) for ip in network.hosts()])
            return targets
        except:
            pass
    
    # Check if IP range (192.168.1.1-192.168.1.10)
    if '-' in target_input and ',' not in target_input:
        parts = target_input.split('-')
        if len(parts) == 2:
            try:
                start_ip = ipaddress.ip_address(parts[0].strip())
                end_ip = ipaddress.ip_address(parts[1].strip())
                
                current = int(start_ip)
                end = int(end_ip)
                
                while current <= end:
                    targets.append(str(ipaddress.ip_address(current)))
                    current += 1
                return targets
            except:
                pass
    
    # Check if comma-separated list
    if ',' in target_input:
        for target in target_input.split(','):
            target = target.strip()
            if target:
                targets.append(target)
        return targets
    
    # Single target
    return [target_input.strip()]


def compare_scans(scan1_file: str, scan2_file: str) -> Dict:
    """
    Compare two scan results and return differences.
    
    Args:
        scan1_file: First scan JSON file
        scan2_file: Second scan JSON file
        
    Returns:
        Dictionary containing differences
    """
    try:
        with open(scan1_file, 'r') as f:
            scan1 = json.load(f)
        with open(scan2_file, 'r') as f:
            scan2 = json.load(f)
        
        # Extract open ports
        scan1_open = set(scan1.get('results', {}).keys())
        scan2_open = set(scan2.get('results', {}).keys())
        
        # Find differences
        new_open = scan2_open - scan1_open
        closed = scan1_open - scan2_open
        still_open = scan1_open & scan2_open
        
        # Check for service/banner changes
        changes = {}
        for port in still_open:
            port_str = str(port)
            if port_str in scan1['results'] and port_str in scan2['results']:
                s1 = scan1['results'][port_str]
                s2 = scan2['results'][port_str]
                
                if s1.get('service') != s2.get('service') or s1.get('banner') != s2.get('banner'):
                    changes[port_str] = {
                        'old': s1,
                        'new': s2
                    }
        
        return {
            'scan1_date': scan1.get('start_time'),
            'scan2_date': scan2.get('start_time'),
            'new_open_ports': sorted([int(p) for p in new_open]),
            'closed_ports': sorted([int(p) for p in closed]),
            'unchanged_ports': sorted([int(p) for p in still_open]),
            'service_changes': changes,
            'summary': {
                'total_changes': len(new_open) + len(closed) + len(changes),
                'new_ports': len(new_open),
                'closed_ports': len(closed),
                'service_changes': len(changes)
            }
        }
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error comparing scans: {e}{Colors.ENDC}")
        return {}


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Advanced Port Scanner - A comprehensive port scanning tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.1 -p 80,443,8080
  %(prog)s -t example.com -p 1-1000 -T 50
  %(prog)s -t 192.168.1.1 --preset top100 -s syn
  %(prog)s -t 192.168.1.1 -p 80-100 -o results.json -f json
  %(prog)s -t 192.168.1.1 -p 1-65535 --speed fast -v
        """
    )
    
    parser.add_argument('-t', '--target',
                        help='Target IP/hostname (supports: IP, IP range, CIDR, comma-separated)')
    parser.add_argument('--target-file',
                        help='File containing targets (one per line)')
    parser.add_argument('-p', '--ports',
                        help='Ports to scan (e.g., 80, 80-100, 80,443,8080)')
    parser.add_argument('--preset', choices=['common', 'top100', 'top1000', 'all'],
                        help='Use preset port list')
    parser.add_argument('-s', '--scan-type', 
                        choices=['tcp', 'udp', 'syn', 'fin', 'null', 'xmas'],
                        default='tcp', help='Scan type (default: tcp)')
    parser.add_argument('-T', '--threads', type=int, default=100,
                        help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('--speed', choices=['slow', 'normal', 'fast', 'aggressive'],
                        help='Scan speed preset')
    parser.add_argument('-o', '--output',
                        help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'txt', 'html', 'xml'],
                        default='json', help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--os-detection', action='store_true',
                        help='Enable OS detection (requires scapy and root)')
    parser.add_argument('--vuln-scan', action='store_true',
                        help='Enable vulnerability scanning')
    parser.add_argument('--ssl-scan', action='store_true',
                        help='Enable SSL/TLS vulnerability scanning')
    parser.add_argument('--detect-waf', action='store_true',
                        help='Detect WAF/IDS/IPS')
    parser.add_argument('--compare',
                        help='Compare with previous scan (JSON file)')
    parser.add_argument('--web-dashboard', action='store_true',
                        help='Start web dashboard')
    
    args = parser.parse_args()
    
    # Handle web dashboard mode
    if args.web_dashboard:
        try:
            from web_dashboard import run_dashboard
            run_dashboard()
        except ImportError:
            print(f"{Colors.FAIL}[!] Flask is required for web dashboard. Install: pip install flask{Colors.ENDC}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error starting web dashboard: {e}{Colors.ENDC}")
            sys.exit(1)
        return
    
    # Handle comparison mode
    if args.compare:
        if not args.output:
            print(f"{Colors.FAIL}[!] Please specify output file (-o) for comparison{Colors.ENDC}")
            sys.exit(1)
        
        print(f"{Colors.OKCYAN}[*] Comparing scans...{Colors.ENDC}")
        diff = compare_scans(args.compare, args.output)
        
        if diff:
            print(f"\n{Colors.HEADER}{Colors.BOLD}Scan Comparison Results{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Previous scan: {diff['scan1_date']}{Colors.ENDC}")
            print(f"{Colors.OKCYAN}Current scan: {diff['scan2_date']}{Colors.ENDC}\n")
            
            print(f"{Colors.OKGREEN}New open ports: {diff['new_open_ports']}{Colors.ENDC}")
            print(f"{Colors.FAIL}Closed ports: {diff['closed_ports']}{Colors.ENDC}")
            print(f"{Colors.WARNING}Service changes: {len(diff['service_changes'])}{Colors.ENDC}")
        sys.exit(0)
    
    # Parse targets
    if not args.target and not args.target_file:
        print(f"{Colors.FAIL}[!] Please specify target (-t) or target file (--target-file){Colors.ENDC}")
        sys.exit(1)
    
    targets = parse_targets(args.target if args.target else '', args.target_file)
    
    if not targets:
        print(f"{Colors.FAIL}[!] No valid targets found{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.OKCYAN}[*] Total targets: {len(targets)}{Colors.ENDC}")
    
    # Check for root privileges if SYN scan is requested
    if args.scan_type in ['syn', 'fin', 'null', 'xmas'] and os.geteuid() != 0:
        print(f"{Colors.FAIL}[!] {args.scan_type.upper()} scan requires root privileges. Please run with sudo.{Colors.ENDC}")
        sys.exit(1)
    
    # Parse ports
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            print(f"{Colors.FAIL}[!] Invalid port specification: {e}{Colors.ENDC}")
            sys.exit(1)
    elif args.preset:
        ports = get_common_ports(args.preset)
    else:
        print(f"{Colors.FAIL}[!] Please specify ports (-p) or preset (--preset){Colors.ENDC}")
        sys.exit(1)
    
    # Apply speed preset
    if args.speed:
        if args.speed == 'slow':
            args.timeout = 3.0
            args.threads = 10
        elif args.speed == 'normal':
            args.timeout = 1.0
            args.threads = 50
        elif args.speed == 'fast':
            args.timeout = 0.5
            args.threads = 200
        elif args.speed == 'aggressive':
            args.timeout = 0.3
            args.threads = 500
    
    # Validate port count for aggressive scans
    if len(ports) > 10000 and args.threads > 200:
        print(f"{Colors.WARNING}[!] Warning: Scanning {len(ports)} ports with {args.threads} threads may be resource-intensive{Colors.ENDC}")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    try:
        # Check for root privileges if OS detection is requested
        if args.os_detection and os.geteuid() != 0:
            print(f"{Colors.WARNING}[!] OS detection requires root privileges for best results.{Colors.ENDC}")
        
        # Scan all targets
        all_results = []
        for idx, target in enumerate(targets, 1):
            print(f"\n{Colors.HEADER}[*] Scanning target {idx}/{len(targets)}: {target}{Colors.ENDC}")
            
            # Create scanner and run scan
            scanner = PortScanner(
                target=target,
                ports=ports,
                timeout=args.timeout,
                threads=args.threads,
                scan_type=args.scan_type,
                verbose=args.verbose,
                os_detection=args.os_detection,
                vuln_scan=args.vuln_scan,
                ssl_scan=args.ssl_scan
            )
            
            scanner.scan()
            
            # WAF/IDS detection if requested
            if args.detect_waf:
                print(f"\n{Colors.OKCYAN}[*] Detecting WAF/IDS/IPS...{Colors.ENDC}")
                waf_results = scanner.detect_waf_ids()
                if waf_results['waf_detected'] or waf_results['ids_detected']:
                    print(f"{Colors.WARNING}[!] Security system detected!{Colors.ENDC}")
                    print(f"    WAF: {'Yes' if waf_results['waf_detected'] else 'No'}")
                    print(f"    IDS/IPS: {'Yes' if waf_results['ids_detected'] else 'No'}")
                    print(f"    Confidence: {waf_results['confidence']}%")
                    for indicator in waf_results['indicators']:
                        print(f"    - {indicator}")
            
            all_results.append({
                'target': target,
                'results': scanner.results,
                'open_ports': scanner.open_ports,
                'closed_ports': scanner.closed_ports,
                'filtered_ports': scanner.filtered_ports
            })
            
            # Save individual results if output file specified
            if args.output and len(targets) > 1:
                output_base = Path(args.output).stem
                output_ext = Path(args.output).suffix or f'.{args.format}'
                target_safe = target.replace('/', '_').replace(':', '_')
                output_file = f"{output_base}_{target_safe}{output_ext}"
                scanner.save_results(output_file, args.format)
            elif args.output:
                scanner.save_results(args.output, args.format)
        
        # Print summary for multiple targets
        if len(targets) > 1:
            print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
            print(f"{Colors.HEADER}{Colors.BOLD}Multi-Target Scan Summary{Colors.ENDC}")
            print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}\n")
            
            for result in all_results:
                print(f"{Colors.OKCYAN}Target: {result['target']}{Colors.ENDC}")
                print(f"  Open: {len(result['open_ports'])}, Closed: {len(result['closed_ports'])}, Filtered: {len(result['filtered_ports'])}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error: {str(e)}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
