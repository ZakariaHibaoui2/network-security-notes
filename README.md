# Network Security Notes & Tools

> My cybersecurity study notes (networking, Wireshark, attacks and defenses, cryptography, Nmap and hardening) plus a set of small, tested **defensive Python tools** that put the concepts into practice.

[![Tests](https://github.com/ZakariaHibaoui2/network-security-notes/actions/workflows/tests.yml/badge.svg)](https://github.com/ZakariaHibaoui2/network-security-notes/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?logo=wireshark&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2C3E50)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 📒 Notes

| # | Topic | Covers |
|---|---|---|
| 01 | [Networking fundamentals](notes/01-networking-fundamentals.md) | OSI vs TCP/IP with attacks per layer, TCP handshake, key ports, subnetting, ARP/DHCP/DNS |
| 02 | [Wireshark cheat sheet](notes/02-wireshark-cheatsheet.md) | Capture vs display filters, the filters I use most, investigation workflow, red flags |
| 03 | [Attacks & defenses](notes/03-attacks-and-defenses.md) | Phishing → ransomware: how each works, how to detect it, how to defend; defense in depth; NIST IR |
| 04 | [Cryptography basics](notes/04-cryptography-basics.md) | Symmetric vs asymmetric, hashing and password storage, signatures, TLS 1.3, entropy |
| 05 | [Nmap & hardening](notes/05-nmap-and-hardening.md) | Nmap reference, Windows and Linux hardening checklists, firewall rule design |

## 🛠️ Tools

| Tool | What it does | Concept |
|---|---|---|
| [`subnet_calc.py`](tools/subnet_calc.py) | Network/broadcast/mask/host range, subnet splitting, **VLSM** allocation | Addressing & segmentation |
| [`port_scanner.py`](tools/port_scanner.py) | Multithreaded TCP-connect scan with **banner grabbing** | Recon / attack surface |
| [`pcap_summary.py`](tools/pcap_summary.py) | Protocol mix, top talkers, DNS queries, **port-scan and DNS-tunnelling alerts** from a PCAP | Traffic analysis |
| [`password_audit.py`](tools/password_audit.py) | Entropy, crack-time estimate, weak-pattern detection (common lists, keyboard runs, years) | Authentication |
| [`file_integrity.py`](tools/file_integrity.py) | SHA-256 baseline and change detection (added / removed / modified) | Integrity (CIA) |

```bash
git clone https://github.com/ZakariaHibaoui2/network-security-notes.git
cd network-security-notes
pip install -r requirements.txt

python tools/subnet_calc.py 10.0.0.0/16 --vlsm 500 200 60 10
python tools/port_scanner.py 127.0.0.1 -p 1-1024
python tools/pcap_summary.py capture.pcapng
python tools/password_audit.py
python tools/file_integrity.py baseline ./folder -o base.json
python tools/file_integrity.py check    ./folder -b base.json

pytest -v
```

> ⚖️ **Ethical use**: scan and capture only on networks you own or are authorised to test.

## Author

**Zakaria Hibaoui** — [GitHub](https://github.com/ZakariaHibaoui2) · [LinkedIn](https://www.linkedin.com/in/zakaria-hibaoui-08b235337/)

## License

[MIT](LICENSE)
