"""PCAP triage: protocol mix, top talkers, DNS queries and suspicious patterns.

Complements Wireshark for a quick first look at a capture.

Usage:
    pip install scapy
    python pcap_summary.py capture.pcapng --top 10
"""
import argparse
from collections import Counter, defaultdict


def summarize(packets, top=10):
    from scapy.layers.dns import DNSQR
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    protocols, talkers, conversations, dns = Counter(), Counter(), Counter(), Counter()
    syn_targets = defaultdict(set)

    for pkt in packets:
        if IP not in pkt:
            protocols["non-IP"] += 1
            continue
        ip = pkt[IP]
        talkers[ip.src] += len(pkt)
        if TCP in pkt:
            protocols["TCP"] += 1
            conversations[(ip.src, ip.dst, pkt[TCP].dport)] += 1
            if pkt[TCP].flags == "S":
                syn_targets[ip.src].add((ip.dst, pkt[TCP].dport))
        elif UDP in pkt:
            protocols["UDP"] += 1
            conversations[(ip.src, ip.dst, pkt[UDP].dport)] += 1
        elif ICMP in pkt:
            protocols["ICMP"] += 1
        else:
            protocols[f"IP proto {ip.proto}"] += 1
        if pkt.haslayer(DNSQR):
            dns[pkt[DNSQR].qname.decode(errors="replace").rstrip(".")] += 1

    alerts = [
        f"{src} sent SYNs to {len(targets)} distinct host:port pairs (possible port scan)"
        for src, targets in syn_targets.items() if len(targets) >= 50
    ]
    alerts += [f"Long DNS name {q[:60]}... (possible DNS tunnelling)" for q in dns if len(q) > 60]
    return {
        "packets": len(packets),
        "protocols": protocols.most_common(),
        "top_talkers_bytes": talkers.most_common(top),
        "top_conversations": conversations.most_common(top),
        "top_dns_queries": dns.most_common(top),
        "alerts": alerts,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    from scapy.utils import rdpcap
    report = summarize(rdpcap(a.pcap), a.top)

    print(f"Packets: {report['packets']}\n\nProtocols:")
    for proto, n in report["protocols"]:
        print(f"  {proto:<14}{n}")
    print("\nTop talkers (bytes sent):")
    for host, n in report["top_talkers_bytes"]:
        print(f"  {host:<18}{n:,}")
    print("\nTop conversations (src -> dst:port):")
    for (src, dst, port), n in report["top_conversations"]:
        print(f"  {src} -> {dst}:{port}  ({n} pkts)")
    print("\nTop DNS queries:")
    for q, n in report["top_dns_queries"]:
        print(f"  {q} ({n})")
    print("\nAlerts:" if report["alerts"] else "\nNo alerts.")
    for alert in report["alerts"]:
        print("  !", alert)


if __name__ == "__main__":
    main()
