#!/usr/bin/env python3
import socket
import argparse

P2P_UDP_PORTS = [32100, 32101, 32102, 37777, 37020, 37021, 37022]

def scan_udp_ports(ip, ports, timeout=1):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(b'\x00', (ip, port))
            data, _ = sock.recvfrom(1024)
            open_ports.append(port)
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports

def ssdp_discover(timeout=2):
    ssdp_request = '\r\n'.join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 1',
        'ST: ssdp:all',
        '', ''
    ]).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.sendto(ssdp_request, ('239.255.255.250', 1900))

    devices = []
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            devices.append((addr[0], data.decode('utf-8', errors='ignore')))
    except socket.timeout:
        pass
    finally:
        sock.close()
    return devices

def is_camera_ssdp(response):
    keywords = ['ipcamera', 'camera', 'hikvision', 'dahua', 'axis', 'foscam', 'reolink']
    response_lower = response.lower()
    return any(keyword in response_lower for keyword in keywords)

def main():
    parser = argparse.ArgumentParser(description="P2P Camera UDP and SSDP Discovery Tool")
    parser.add_argument('-t', '--target', help='Target IP address for UDP port scan')
    parser.add_argument('--ssdp', action='store_true', help='Run SSDP discovery on local network')
    args = parser.parse_args()

    if args.target:
        print(f"[*] Scanning UDP ports on {args.target}...")
        open_ports = scan_udp_ports(args.target, P2P_UDP_PORTS)
        if open_ports:
            print(f"[+] Open UDP P2P ports on {args.target}: {open_ports}")
        else:
            print(f"[-] No open UDP P2P ports found on {args.target}")

    if args.ssdp:
        print("[*] Running SSDP discovery...")
        devices = ssdp_discover()
        if devices:
            for ip, resp in devices:
                if is_camera_ssdp(resp):
                    print(f"[+] Possible camera detected via SSDP at {ip}")
                    print(resp)
                    print("-" * 40)
        else:
            print("[-] No SSDP devices found")

if __name__ == "__main__":
    main()
