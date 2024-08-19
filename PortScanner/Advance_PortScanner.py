import socket
import sys
import concurrent.futures
import argparse
from scapy.all import sr1, IP, TCP, ICMP
import time

def check_host(ip):
    icmp = IP(dst=ip)/ICMP()
    resp = sr1(icmp, timeout=10, verbose=False)
    return resp is not None

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def scan_port(ip, port, scan_type):
    if scan_type == 'connect':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0, get_service_name(port)
    elif scan_type == 'syn':
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(packet, timeout=2, verbose=False)
        if resp is None:
            return port, False, get_service_name(port)
        elif resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            return port, True, get_service_name(port)
        else:
            return port, False, get_service_name(port)

def scan_ports(ip, start_port, end_port, scan_type, num_threads=100):
    print(f"Scanning {ip} from port {start_port} to {end_port} using {scan_type} scan")
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, scan_type): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open, service = future.result()
            if is_open:
                print(f"Port {port} is open - Service: {service}")
                open_ports.append((port, service))
    
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
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
    for port, service in open_ports:
        print(f"  {port}/tcp - {service}")
    print(f"\nScan duration: {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()
