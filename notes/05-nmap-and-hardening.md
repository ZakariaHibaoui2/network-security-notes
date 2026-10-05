# 05 — Nmap Reference & System Hardening

> ⚠️ Only scan networks you own or have **written permission** to test. `scanme.nmap.org` is provided by the Nmap project for practice.

## Nmap essentials

| Goal | Command |
|---|---|
| Host discovery (no port scan) | `nmap -sn 192.168.1.0/24` |
| Top 1000 TCP ports | `nmap 192.168.1.10` |
| Fast top 100 | `nmap -F 192.168.1.10` |
| All TCP ports | `nmap -p- 192.168.1.10` |
| SYN (half-open) scan | `sudo nmap -sS 192.168.1.10` |
| Service / version detection | `nmap -sV 192.168.1.10` |
| OS detection | `sudo nmap -O 192.168.1.10` |
| Default safe scripts | `nmap -sC 192.168.1.10` |
| UDP top ports | `sudo nmap -sU --top-ports 50 192.168.1.10` |
| Aggressive (OS + version + scripts + traceroute) | `nmap -A 192.168.1.10` |
| Save all formats | `nmap -oA scan_results 192.168.1.10` |

**Port states**: `open` (service answering), `closed` (RST returned), `filtered` (no answer, firewall), `open|filtered` (common with UDP).

A minimal TCP-connect scanner with banner grabbing is implemented in [`tools/port_scanner.py`](../tools/port_scanner.py) to show how this works under the hood.

## Windows hardening checklist

- [ ] Automatic updates on; remove unsupported software
- [ ] Standard user accounts for daily work; separate admin account; **LAPS** for local admin passwords
- [ ] BitLocker on all drives
- [ ] Microsoft Defender + attack surface reduction rules; SmartScreen on
- [ ] Windows Firewall on for all profiles; block inbound SMB/RDP from untrusted networks
- [ ] Disable SMBv1, LLMNR, and NetBIOS over TCP/IP where not needed
- [ ] RDP only via VPN/gateway with Network Level Authentication
- [ ] Audit policy: logon events, account management, process creation, with logs forwarded to a SIEM

## Linux hardening checklist

- [ ] `unattended-upgrades` / `dnf-automatic`
- [ ] SSH: `PermitRootLogin no`, `PasswordAuthentication no`, keys only, `AllowUsers`
- [ ] Firewall default-deny: `ufw default deny incoming && ufw allow 22/tcp`
- [ ] `fail2ban` for SSH and web logins
- [ ] Remove unused services: `systemctl list-unit-files --state=enabled`
- [ ] File integrity monitoring (AIDE, or [`tools/file_integrity.py`](../tools/file_integrity.py))
- [ ] `auditd` + centralised logging

## Firewall rule design

1. Default **deny** inbound, allow only what is required.
2. Most specific rules first; document every rule with an owner and reason.
3. Restrict by **source** (security group, IP range), not just port.
4. Log denied traffic and review regularly.
