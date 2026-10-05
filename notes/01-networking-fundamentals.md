# 01 — Networking Fundamentals for Security

## OSI vs TCP/IP

| OSI layer | TCP/IP layer | PDU | Examples | Typical attacks |
|---|---|---|---|---|
| 7 Application | Application | Data | HTTP, DNS, SMTP, SSH | SQLi, XSS, DNS spoofing |
| 6 Presentation | Application | Data | TLS, encodings | SSL stripping, downgrade |
| 5 Session | Application | Data | RPC, NetBIOS | Session hijacking |
| 4 Transport | Transport | Segment / Datagram | TCP, UDP | SYN flood, port scanning |
| 3 Network | Internet | Packet | IP, ICMP, routing | IP spoofing, ICMP tunnelling |
| 2 Data link | Link | Frame | Ethernet, ARP, 802.11 | ARP poisoning, MAC flooding |
| 1 Physical | Link | Bits | Cables, radio | Tapping, jamming |

## TCP three-way handshake and teardown

```
Client                Server
  | ---- SYN (seq=x) ---> |
  | <-- SYN-ACK (y,x+1) - |
  | ---- ACK (y+1) -----> |     connection ESTABLISHED
  ...
  | ---- FIN -----------> |
  | <--- ACK ------------ |
  | <--- FIN ------------ |
  | ---- ACK -----------> |     TIME_WAIT on the closer
```

- **SYN flood**: many SYNs with no final ACK exhaust the server's half-open queue. Mitigations: SYN cookies, rate limiting, upstream scrubbing.
- **RST** aborts a connection. A closed port answers SYN with RST; a filtered port gives no answer or ICMP unreachable.

## Ports worth knowing

| Port | Service | Note |
|---|---|---|
| 20/21 | FTP | Cleartext credentials, so prefer SFTP/FTPS |
| 22 | SSH | Brute-force target: keys only, no root login |
| 23 | Telnet | Cleartext, so disable it |
| 25 / 587 | SMTP / submission | Open relay risk |
| 53 | DNS | UDP and TCP; amplification and tunnelling |
| 80 / 443 | HTTP / HTTPS | Enforce HSTS |
| 135, 139, 445 | MSRPC / NetBIOS / SMB | Never expose to the Internet (WannaCry, EternalBlue) |
| 3306 / 5432 / 1433 | MySQL / PostgreSQL / MSSQL | Keep in private subnets |
| 3389 | RDP | Put behind a VPN or gateway, use NLA |
| 6379 / 27017 | Redis / MongoDB | Often left unauthenticated |

## IPv4 addressing and subnetting

- Private ranges (RFC 1918): `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Usable hosts in a subnet = 2^(32 − prefix) − 2
- `/24` → 254 hosts, `/26` → 62, `/28` → 14, `/30` → 2 (point-to-point)
- Practice with [`tools/subnet_calc.py`](../tools/subnet_calc.py), including VLSM allocation.

## Key protocols

- **ARP** maps IP to MAC on the local segment. It has no authentication, which makes ARP poisoning possible (mitigations: Dynamic ARP Inspection, static entries for gateways).
- **DHCP** (DORA: Discover, Offer, Request, Ack). Rogue DHCP servers can redirect traffic (mitigation: DHCP snooping).
- **DNS** resolution is recursive or iterative. Cache poisoning is mitigated by DNSSEC and source-port randomisation.
- **ICMP** covers echo, unreachable, and time-exceeded (used by traceroute). It's useful for diagnostics, so filter it rather than blocking it blindly.
