import socket
import ssl
import requests
from requests.auth import HTTPBasicAuth
import csv
import logging
import argparse
import concurrent.futures
import nmap
import importlib
import os
import time

# Configure logging
logging.basicConfig(
    filename='ip_camera_framework.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

CAMERA_PORTS = [
    1025, 1159, 1160, 1600, 1852, 2000, 2002, 2003, 2433, 3000, 3357, 3454,
    4000, 4321, 4602, 5000, 5050, 5101, 5150, 5445, 5920, 6000, 6002, 6003,
    6036, 6100, 6666, 6667, 7000, 7008, 7621, 7777, 8000, 8008, 8016, 8080,
    8101, 8124, 8200, 8554, 8670, 8888, 9000, 9001, 9008, 9010, 9011, 9013,
    9091, 9191, 9221, 9350, 9871, 9998, 10063, 10101, 15961, 18004, 18600,
    32789, 32791, 34567, 34599, 37777, 50000, 50333, 54000
]

# Load default credentials from file
def load_default_creds(file_path='creds/default_credentials.txt'):
    creds = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    user, pwd = line.split(':', 1)
                    creds.append((user, pwd))
    except Exception as e:
        logging.error(f"Failed to load default credentials: {e}")
    return creds

DEFAULT_CREDS = load_default_creds()

VENDORS = {
    'hikvision': ['hikvision'],
    'dahua': ['dahua'],
    'reolink': ['reolink'],
    'axis': ['axis'],
    'foscam': ['foscam'],
    'avtech': ['avtech'],
}

def read_targets(file_path):
    try:
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(targets)} targets from {file_path}")
        return targets
    except Exception as e:
        logging.error(f"Failed to read targets file: {e}")
        return []

def scan_ports_nmap(ip, ports):
    nm = nmap.PortScanner()
    port_str = ','.join(str(p) for p in ports)
    try:
        nm.scan(ip, port_str, arguments='-Pn -T4')
        open_ports = []
        for port in ports:
            if nm[ip].has_tcp(port) and nm[ip]['tcp'][port]['state'] == 'open':
                open_ports.append(port)
        logging.info(f"{ip} open ports: {open_ports}")
        return open_ports
    except Exception as e:
        logging.error(f"Nmap scan failed for {ip}: {e}")
        return []

def grab_banner(ip, port, timeout=3):
    try:
        if port in [443, 8443, 9443]:  # common HTTPS ports
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.settimeout(timeout)
                    request = f"HEAD / HTTP/1.1
Host: {ip}

"
                    ssock.sendall(request.encode())
                    banner = ssock.recv(1024).decode(errors='ignore')
                    logging.info(f"HTTPS banner from {ip}:{port}: {banner.strip()}")
                    return banner.strip()
        else:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in [80, 8000, 8080, 7000, 8888, 9000, 9091, 9191, 37777]:
                    request = f"HEAD / HTTP/1.1
Host: {ip}

"
                    sock.sendall(request.encode())
                    banner = sock.recv(1024).decode(errors='ignore')
                elif port in [554, 8554]:
                    request = f"OPTIONS rtsp://{ip}/ RTSP/1.0
CSeq: 1

"
                    sock.sendall(request.encode())
                    banner = sock.recv(1024).decode(errors='ignore')
                else:
                    banner = sock.recv(1024).decode(errors='ignore')
                logging.info(f"Banner from {ip}:{port}: {banner.strip()}")
                return banner.strip()
    except Exception as e:
        logging.debug(f"Banner grab failed for {ip}:{port} - {e}")
        return None

def identify_vendor(banner):
    if not banner:
        return None
    banner_lower = banner.lower()
    for vendor, keywords in VENDORS.items():
        for keyword in keywords:
            if keyword in banner_lower:
                return vendor
    return None

def load_pocs():
    pocs = {}
    pocs_dir = os.path.join(os.path.dirname(__file__), 'pocs')
    for filename in os.listdir(pocs_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            mod_name = filename[:-3]
            module = importlib.import_module(f'pocs.{mod_name}')
            pocs[mod_name] = module
    return pocs

def run_pocs(ip, port, vendor, pocs):
    results = []
    if not vendor:
        return results
    for name, module in pocs.items():
        if vendor in name:
            try:
                vulnerable, note = module.check(ip, port)
                if vulnerable:
                    results.append(note)
            except Exception as e:
                logging.error(f"Error running PoC {name} on {ip}:{port} - {e}")
    return results

def test_creds(ip, port, creds, use_https=False, max_retries=3):
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{ip}:{port}/"
    for user, pwd in creds:
        for attempt in range(max_retries):
            try:
                r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=5, verify=False)
                if r.status_code == 200:
                    logging.info(f"Valid creds for {ip}:{port} - {user}:{pwd}")
                    return user, pwd
                else:
                    break  # no need to retry on non-200
            except requests.exceptions.SSLError:
                logging.warning(f"SSL error for {ip}:{port} with creds {user}:{pwd}")
                break
            except requests.exceptions.RequestException as e:
                logging.debug(f"Request error for {ip}:{port} attempt {attempt+1}: {e}")
                time.sleep(1)  # backoff before retry
                continue
    return None, None

def scan_ip(ip, passive=False):
    results = []
    if passive:
        ports_to_check = CAMERA_PORTS
    else:
        open_ports = scan_ports_nmap(ip, CAMERA_PORTS)
        ports_to_check = open_ports

    pocs = load_pocs()

    for port in ports_to_check:
        banner = grab_banner(ip, port)
        vendor = identify_vendor(banner)
        pocs_results = run_pocs(ip, port, vendor, pocs)
        use_https = port in [443, 8443, 9443]
        user, pwd = test_creds(ip, port, DEFAULT_CREDS, use_https=use_https)
        results.append({
            'IP': ip,
            'Port': port,
            'Vendor': vendor or "Unknown",
            'Banner': banner or "",
            'Vulnerabilities': '; '.join(pocs_results) if pocs_results else "None found",
            'Valid Credentials': f"{user}:{pwd}" if user else "None"
        })
    return results

def write_results_to_csv(results, output_file):
    fieldnames = ['IP', 'Port', 'Vendor', 'Banner', 'Vulnerabilities', 'Valid Credentials']
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow(row)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to write CSV: {e}")

def main():
    parser = argparse.ArgumentParser(description="IP Camera Security Assessment Framework")
    parser.add_argument('-t', '--targets', required=True, help="File with list of target IPs")
    parser.add_argument('-o', '--output', default='camera_scan_results.csv', help="Output CSV file")
    parser.add_argument('--passive', action='store_true', help="Passive scan (no port scanning)")
    parser.add_argument('--threads', type=int, default=10, help="Number of concurrent threads")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    targets = read_targets(args.targets)
    if not targets:
        print("No targets found. Exiting.")
        return

    all_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_ip, ip, args.passive): ip for ip in targets}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                res = future.result()
                all_results.extend(res)
                print(f"Scanned {ip}")
            except Exception as e:
                logging.error(f"Error scanning {ip}: {e}")

    write_results_to_csv(all_results, args.output)
    print(f"Scan complete. Results saved to {args.output}")

if __name__ == "__main__":
    main()
