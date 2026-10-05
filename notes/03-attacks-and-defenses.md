# 03 — Common Attacks and Defenses

| Attack | How it works | Detection | Defense |
|---|---|---|---|
| **Phishing** | Deceptive email or site steals credentials or delivers malware | Mail gateway, user reports, look-alike domains | MFA, SPF/DKIM/DMARC, awareness training |
| **Brute force / credential stuffing** | Automated login attempts with guessed or leaked passwords | Failed-login spikes per IP or account | Lockout and rate limiting, MFA, strong hashing (bcrypt / Argon2 / PBKDF2) |
| **SQL injection** | User input concatenated into SQL | WAF logs, DB errors | Parameterised queries, least-privilege DB user |
| **XSS** | Injected script runs in victims' browsers | CSP violation reports | Output encoding, Content-Security-Policy, HttpOnly cookies |
| **CSRF** | Victim's browser sends an authenticated request to a forged URL | Unexpected `Origin`/`Referer` | SameSite cookies, CSRF tokens, Origin checks |
| **MITM / ARP poisoning** | Attacker positions between host and gateway | Duplicate-IP ARP, certificate warnings | TLS everywhere + HSTS, Dynamic ARP Inspection |
| **DNS spoofing** | Forged DNS answers redirect users | Mismatched resolver answers | DNSSEC, DoH/DoT to trusted resolvers |
| **DoS / DDoS** | Exhaust bandwidth, connections, or CPU | Traffic baselines, NetFlow | Rate limiting, SYN cookies, CDN / scrubbing |
| **Ransomware** | Encrypts files, often after lateral movement | Mass file renames, canary files, EDR | Offline 3-2-1 backups, patching, segmentation, least privilege |
| **Privilege escalation** | Exploit or misconfiguration grants admin | Unusual admin group changes | Patch management, no local admin for users, LAPS |

## Defense in depth

```
Policies & training → Physical → Perimeter (firewall, WAF) → Network (segmentation, IDS)
→ Host (EDR, patching, hardening) → Application (secure coding, auth) → Data (encryption, backups)
```

## CIA triad and AAA

- **Confidentiality** (encryption, access control) · **Integrity** (hashing, signatures, see [`tools/file_integrity.py`](../tools/file_integrity.py)) · **Availability** (redundancy, backups, DDoS protection)
- **Authentication** (who you are) → **Authorization** (what you may do) → **Accounting** (what you did: audit logs)

## Incident response (NIST SP 800-61)

1. Preparation → 2. Detection & analysis → 3. Containment, eradication & recovery → 4. Post-incident lessons learned
