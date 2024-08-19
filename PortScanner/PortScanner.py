import socket
import sys
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return port, result == 0

def scan_ports(ip, start_port, end_port, num_threads=100):
    print(f"Scanning {ip} from port {start_port} to {end_port}")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                print(f"Port {port} is open")
                open_ports.append(port)
    
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <ip> <start_port> <end_port>")
        sys.exit(1)

    ip = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    open_ports = scan_ports(ip, start_port, end_port)
    
    print("\nScan completed")
    print(f"Open ports: {', '.join(map(str, open_ports))}")
