#!/usr/bin/env python3
"""
Network Port Scanner
Author: Nuzhat Atiqua Nafis
Description: Multithreaded port scanner with service detection
"""

import socket
import threading
import argparse
import ipaddress
from datetime import datetime
from queue import Queue

# Thread-safe results storage
results = []
results_lock = threading.Lock()
queue = Queue()

# Common ports and their services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 27017: "MongoDB"
}

def scan_port(host, port, timeout=1):
    """Attempt to connect to a specific port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            # Try to grab banner
            banner = grab_banner(host, port, timeout)
            return {
                "port": port,
                "status": "open",
                "service": service,
                "banner": banner
            }
    except socket.error:
        pass
    return None

def grab_banner(host, port, timeout=1):
    """Attempt to grab service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100] if banner else "N/A"
    except Exception:
        return "N/A"

def worker(host, timeout):
    """Thread worker function."""
    while not queue.empty():
        port = queue.get()
        result = scan_port(host, port, timeout)
        if result:
            with results_lock:
                results.append(result)
                print(f"  [OPEN] Port {result['port']:5d} | "
                      f"{result['service']:15s} | {result['banner'][:50]}")
        queue.task_done()

def validate_ip(host):
    """Validate IP address or resolve hostname."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            raise ValueError(f"Cannot resolve host: {host}")

def scan(host, port_range, threads=100, timeout=1):
    """Main scanning function."""
    ip = validate_ip(host)
    start_port, end_port = port_range

    print(f"\n{'='*60}")
    print(f"  Network Port Scanner")
    print(f"  Target  : {host} ({ip})")
    print(f"  Ports   : {start_port} - {end_port}")
    print(f"  Threads : {threads}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # Fill queue with ports
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # Launch threads
    thread_list = []
    for _ in range(min(threads, end_port - start_port + 1)):
        t = threading.Thread(target=worker, args=(ip, timeout))
        t.daemon = True
        thread_list.append(t)
        t.start()

    # Wait for completion
    queue.join()

    # Print summary
    print(f"\n{'='*60}")
    print(f"  Scan Complete | {len(results)} open port(s) found")
    print(f"  Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    return sorted(results, key=lambda x: x["port"])

def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner",
        epilog="Example: python scanner.py -t 192.168.1.1 -p 1-1000"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds")

    args = parser.parse_args()

    # Parse port range
    try:
        start, end = map(int, args.ports.split("-"))
    except ValueError:
        print("Error: Port range must be in format START-END (e.g., 1-1024)")
        return

    scan(args.target, (start, end), args.threads, args.timeout)

if __name__ == "__main__":
    main()