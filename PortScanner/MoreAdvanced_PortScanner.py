import socket
import sys
import concurrent.futures
import argparse
from scapy.all import sr1, IP, IPv6, TCP, ICMP, ICMPv6EchoRequest
import time
import re
import ipaddress

def is_ipv6(ip):
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def check_host(ip):
    if is_ipv6(ip):
        icmp = IPv6(dst=ip)/ICMPv6EchoRequest()
    else:
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
        if is_ipv6(ip):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        
        sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        server_header = re.search(r'Server: (.*)', response)
        if server_header:
            return server_header.group(1)
        
        version_patterns = [
            r'SSH-([\d\.]+)',
            r'220.*FTP',
            r'SMTP (.*)',
            r'POP3 (.*)',
            r'IMAP4 (.*)',
            r'HTTP/[\d\.]+',
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

def get_ttl(ip):
    try:
        if is_ipv6(ip):
            packet = IPv6(dst=ip)/ICMPv6EchoRequest()
        else:
            packet = IP(dst=ip)/ICMP()
        reply = sr1(packet, timeout=10, verbose=False)
        if reply is not None:
            return reply.hlim if is_ipv6(ip) else reply.ttl
    except:
        pass
    return None

def guess_os(ttl):
    if ttl is None:
        return "Unknown"
    elif ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Unknown"

def tcp_window_size(ip, port):
    try:
        if is_ipv6(ip):
            packet = IPv6(dst=ip)/TCP(dport=port, flags="S")
        else:
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        reply = sr1(packet, timeout=2, verbose=False)
        if reply and reply.haslayer(TCP):
            return reply[TCP].window
    except:
        pass
    return None

def scan_port(ip, port, scan_type):
    if scan_type == 'connect':
        if is_ipv6(ip):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        is_open = result == 0
    elif scan_type == 'syn':
        if is_ipv6(ip):
            packet = IPv6(dst=ip)/TCP(dport=port, flags="S")
        else:
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(packet, timeout=2, verbose=False)
        is_open = resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12
    
    if is_open:
        service = get_service_name(port)
        version = probe_service(ip, port)
        ttl = get_ttl(ip)
        os = guess_os(ttl)
        window_size = tcp_window_size(ip, port)
        return port, True, service, version, os, ttl, window_size
    else:
        return port, False, None, None, None, None, None

def scan_ports(ip, start_port, end_port, scan_type, num_threads=100):
    print(f"Scanning {ip} from port {start_port} to {end_port} using {scan_type} scan")
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, scan_type): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service, version, os, ttl, window_size = future.result()
            if is_open:
                print(f"Port {port} is open - Service: {service} - Version: {version} - OS: {os}")
                open_ports.append((port, service, version, os, ttl, window_size))
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with IPv6, Version and OS Detection")
    parser.add_argument("ip", help="IP address to scan (IPv4 or IPv6)")
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
    for port, service, version, os, ttl, window_size in open_ports:
        print(f"  {port}/tcp - {service} - {version}")
        print(f"    OS: {os} (TTL/Hop Limit: {ttl}, Window Size: {window_size})")
    print(f"\nScan duration: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
