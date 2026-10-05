"""Multithreaded TCP connect scanner with banner grabbing.

For use ONLY on hosts you own or are explicitly authorised to test.

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py 192.168.1.10 -p 1-1024 --threads 200 --timeout 0.5
    python port_scanner.py scanme.nmap.org -p 22,80,443
"""
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec):
    """'22,80,8000-8010' -> sorted unique list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"invalid port(s): {bad[:5]}")
    return sorted(ports)


def scan_port(host, port, timeout):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        banner = ""
        try:
            s.settimeout(0.6)
            banner = s.recv(128).decode(errors="replace").strip().splitlines()[0]
        except (OSError, IndexError):
            pass
        return port, COMMON_PORTS.get(port, "unknown"), banner


def scan(host, ports, threads=100, timeout=0.5):
    ip = socket.gethostbyname(host)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda p: scan_port(ip, p, timeout), ports)
    return ip, [r for r in results if r]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("-p", "--ports", default=",".join(map(str, COMMON_PORTS)))
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("--timeout", type=float, default=0.5)
    a = ap.parse_args()

    ip, open_ports = scan(a.host, parse_ports(a.ports), a.threads, a.timeout)
    print(f"Scan report for {a.host} ({ip})")
    print(f"{'PORT':<8}{'SERVICE':<12}BANNER")
    for port, service, banner in open_ports:
        print(f"{port:<8}{service:<12}{banner}")
    if not open_ports:
        print("No open ports found in the scanned range.")


if __name__ == "__main__":
    main()
