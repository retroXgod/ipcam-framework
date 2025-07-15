#!/usr/bin/env python3

import argparse
import csv
import logging
import nmap
import socket
import ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ip_camera_framework.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Vendor definitions
VENDORS = {
    'hikvision': ['hikvision'],
    'dahua': ['dahua'],
    'reolink': ['reolink'],
    'axis': ['axis'],
    'foscam': ['foscam'],
    'avtech': ['avtech']
}

# Common ports for IP cameras
COMMON_PORTS = [
    80, 443, 554, 8000, 8080, 8443, 8554, 9000, 
    37777, 37778, 34567, 34568, 7001, 7002, 
    9001, 9002, 9999, 8081, 8082, 8083, 8084, 
    8085, 8086, 8087, 8088, 8089, 8090
]

class IPCameraScanner:
    def __init__(self, target_file, output_file='camera_scan_results.csv', 
                 passive=False, threads=10, verbose=False):
        self.target_file = target_file
        self.output_file = output_file
        self.passive = passive
        self.threads = threads
        self.verbose = verbose
        self.results = []
        self.lock = threading.Lock()
        
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)

    def load_targets(self):
        """Load target IP addresses from file."""
        try:
            with open(self.target_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error(f"Error loading targets: {e}")
            sys.exit(1)

    def scan_ports(self, ip):
        """Scan ports on target IP."""
        if self.passive:
            return COMMON_PORTS

        try:
            nm = nmap.PortScanner()
            ports = ','.join(map(str, COMMON_PORTS))
            nm.scan(ip, ports, arguments='-sT -T4')
            
            open_ports = []
            if ip in nm.all_hosts():
                for port in nm[ip].all_tcp():
                    if nm[ip]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
            return open_ports
        except Exception as e:
            logging.error(f"Port scan failed for {ip}: {e}")
            return []

    def grab_banner(self, ip, port, timeout=3):
        """Grab service banner from target IP:port."""
        try:
            if port in [443, 8443, 9443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                        ssock.sendall(request.encode())
                        return ssock.recv(1024).decode(errors='ignore').strip()
            else:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    if port in [80, 8000, 8080]:
                        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                        sock.sendall(request.encode())
                    elif port in [554, 8554]:
                        request = f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                        sock.sendall(request.encode())
                    return sock.recv(1024).decode(errors='ignore').strip()
        except Exception as e:
            logging.debug(f"Banner grab failed for {ip}:{port} - {e}")
            return None

    def identify_vendor(self, banner):
        """Identify vendor from banner."""
        if not banner:
            return "unknown"
        
        banner_lower = banner.lower()
        for vendor, signatures in VENDORS.items():
            if any(sig in banner_lower for sig in signatures):
                return vendor
        return "unknown"

    def check_default_credentials(self, ip, port, vendor):
        """Test default credentials."""
        creds_file = Path('creds/default_credentials.txt')
        if not creds_file.exists():
            logging.warning(f"Default credentials file not found: {creds_file}")
            return []

        valid_creds = []
        try:
            with open(creds_file, 'r') as f:
                for line in f:
                    username, password = line.strip().split(':')
                    if self.test_credentials(ip, port, username, password):
                        valid_creds.append(f"{username}:{password}")
        except Exception as e:
            logging.error(f"Error checking credentials: {e}")
        
        return valid_creds

    def test_credentials(self, ip, port, username, password):
        """Test a single set of credentials."""
        # Implementation depends on vendor-specific authentication methods
        # This is a placeholder - implement actual authentication logic
        return False

    def scan_target(self, ip):
        """Scan a single target IP."""
        try:
            open_ports = self.scan_ports(ip)
            
            for port in open_ports:
                banner = self.grab_banner(ip, port)
                vendor = self.identify_vendor(banner)
                valid_creds = self.check_default_credentials(ip, port, vendor)
                
                result = {
                    'ip': ip,
                    'port': port,
                    'vendor': vendor,
                    'banner': banner,
                    'valid_credentials': valid_creds,
                    'timestamp': datetime.now().isoformat()
                }
                
                with self.lock:
                    self.results.append(result)
                    logging.info(f"Scan result for {ip}:{port} - Vendor: {vendor}")
        
        except Exception as e:
            logging.error(f"Error scanning {ip}: {e}")

    def save_results(self):
        """Save scan results to CSV file."""
        try:
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'ip', 'port', 'vendor', 'banner', 
                    'valid_credentials', 'timestamp'
                ])
                writer.writeheader()
                writer.writerows(self.results)
            logging.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logging.error(f"Error saving results: {e}")

    def run(self):
        """Run the scanner."""
        targets = self.load_targets()
        logging.info(f"Starting scan of {len(targets)} targets")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_target, targets)
        
        self.save_results()
        logging.info("Scan completed")

def main():
    parser = argparse.ArgumentParser(description='IP Camera Security Assessment Framework')
    parser.add_argument('-t', '--targets', required=True, help='File containing target IPs')
    parser.add_argument('-o', '--output', default='camera_scan_results.csv', 
                        help='Output CSV file')
    parser.add_argument('--passive', action='store_true', 
                        help='Enable passive mode (skip port scanning)')
    parser.add_argument('--threads', type=int, default=10, 
                        help='Number of concurrent threads')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    scanner = IPCameraScanner(
        target_file=args.targets,
        output_file=args.output,
        passive=args.passive,
        threads=args.threads,
        verbose=args.verbose
    )
    
    scanner.run()

if __name__ == '__main__':
    main()