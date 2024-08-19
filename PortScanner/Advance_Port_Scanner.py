import socket
import sys
import concurrent.futures
import argparse
from scapy.all import sr1, IP, TCP, ICMP
import time
import re

def check_host(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10, verbose=False)
    return resp is not None

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def probe_service(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        # Send HTTP GET request
        sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # Try to extract version information
        server_header = re.search(r'Server: (.*)', response)
        if server_header:
            return server_header.group(1)
        
        # If no Server header, look for other common patterns
        version_patterns = [
            r'SSH-([\d\.]+)',  # SSH
            r'220.*FTP',  # FTP
            r'SMTP (.*)',  # SMTP
            r'POP3 (.*)',  # POP3
            r'IMAP4 (.*)',  # IMAP
            r'HTTP/[\d\.]+',  # HTTP without Server header
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, response)
            if match:
                return match.group(0)
        
        return "Version unknown"
    except Exception as e:
        return f"Probe failed: {str(e)}"
    finally:
        sock.close()

def scan_port(ip, port, scan_type):
    if scan_type == 'connect':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        is_open = result == 0
    elif scan_type == 'syn':
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(packet, timeout=2, verbose=False)
        is_open = resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12
    
    if is_open:
        service = get_service_name(port)
        version = probe_service(ip, port)
        return port, True, service, version
    else:
        return port, False, None, None

def scan_ports(ip, start_port, end_port, scan_type, num_threads=100):
    print(f"Scanning {ip} from port {start_port} to {end_port} using {scan_type} scan")
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, scan_type): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service, version = future.result()
            if is_open:
                print(f"Port {port} is open - Service: {service} - Version: {version}")
                open_ports.append((port, service, version))
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Version Detection")
    parser.add_argument("ip", help="IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("-t", "--type", choices=['connect', 'syn'], default='connect', help="Scan type (default: connect)")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    args = parser.parse_args()

    ip = args.ip
    start_port, end_port = map(int, args.ports.split("-"))
    scan_type = args.type
    num_threads = args.threads

    if not check_host(ip):
        print(f"Host {ip} seems to be down or not responding to ICMP.")
        sys.exit(1)

    start_time = time.time()
    open_ports = scan_ports(ip, start_port, end_port, scan_type, num_threads)
    end_time = time.time()

    print("\nScan completed")
    print(f"Open ports:")
    for port, service, version in open_ports:
        print(f"  {port}/tcp - {service} - {version}")
    print(f"\nScan duration: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
