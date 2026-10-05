# 02 — Wireshark Cheat Sheet

## Capture vs display filters

- **Capture filters** (BPF syntax) decide what is recorded: `host 10.0.0.5 and port 443`
- **Display filters** (Wireshark syntax) decide what is shown: `ip.addr == 10.0.0.5 && tcp.port == 443`

## Display filters I use most

| Goal | Filter |
|---|---|
| Traffic to/from a host | `ip.addr == 192.168.1.10` |
| Only source / destination | `ip.src == 10.0.0.5` / `ip.dst == 10.0.0.5` |
| A TCP or UDP port | `tcp.port == 22` / `udp.port == 53` |
| HTTP requests | `http.request` |
| POST requests (possible credentials) | `http.request.method == "POST"` |
| DNS queries for a domain | `dns.qry.name contains "example"` |
| TLS handshakes (SNI) | `tls.handshake.type == 1` then column `tls.handshake.extensions_server_name` |
| SYN-only packets (scans) | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| Connection resets | `tcp.flags.reset == 1` |
| Retransmissions / problems | `tcp.analysis.flags` |
| ARP spoofing hint | `arp.duplicate-address-detected` |
| ICMP | `icmp` |
| Exclude noise | `!(arp or dns or icmp)` |
| Large frames | `frame.len > 1400` |

## Investigation workflow

1. **Statistics → Protocol Hierarchy** shows what is on the wire.
2. **Statistics → Conversations / Endpoints** shows the top talkers and unusual peers.
3. **Statistics → I/O Graph** shows spikes such as scans, exfiltration, or floods.
4. **Follow → TCP/HTTP Stream** reconstructs a session.
5. **File → Export Objects → HTTP** recovers transferred files.
6. Add columns (right-click a field → *Apply as Column*) for SNI, user-agent, and so on.

For a scripted first pass on large captures, use [`tools/pcap_summary.py`](../tools/pcap_summary.py): protocol mix, top talkers, DNS queries, and port-scan or DNS-tunnelling alerts.

## Red flags in a capture

- One source sending SYNs to many ports or hosts → **port scan**
- Many ARP replies for the gateway IP from different MACs → **ARP poisoning**
- Long random-looking subdomains in DNS → **DNS tunnelling / DGA malware**
- Regular, fixed-interval small connections to one IP → **C2 beaconing**
- Cleartext `USER` / `PASS` (FTP, Telnet, HTTP Basic) → **credential exposure**
- Large outbound transfers at odd hours → **data exfiltration**
