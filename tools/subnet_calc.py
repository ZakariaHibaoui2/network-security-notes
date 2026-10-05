"""Subnet calculator: network details and VLSM splitting.

Usage:
    python subnet_calc.py 10.0.0.0/16
    python subnet_calc.py 192.168.1.0/24 --split 26
    python subnet_calc.py 10.0.0.0/16 --vlsm 500 200 60 10
"""
import argparse
import ipaddress
import math


def describe(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    usable = max(net.num_addresses - 2, 0) if net.prefixlen < 31 else net.num_addresses
    hosts = list(net.hosts()) if net.num_addresses <= 2 ** 16 else None
    return {
        "network": str(net.network_address),
        "broadcast": str(net.broadcast_address),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "prefix": net.prefixlen,
        "total_addresses": net.num_addresses,
        "usable_hosts": usable,
        "first_host": str(hosts[0]) if hosts else str(net.network_address + 1),
        "last_host": str(hosts[-1]) if hosts else str(net.broadcast_address - 1),
        "private": net.is_private,
    }


def split(cidr, new_prefix):
    return [str(s) for s in ipaddress.ip_network(cidr, strict=False).subnets(new_prefix=new_prefix)]


def vlsm(cidr, host_counts):
    """Allocate subnets largest-first so each department gets the smallest block that fits."""
    free = [ipaddress.ip_network(cidr, strict=False)]
    plan = []
    for hosts in sorted(host_counts, reverse=True):
        prefix = 32 - math.ceil(math.log2(hosts + 2))
        # smallest free block that can still hold the subnet, lowest address first
        candidates = [b for b in free if b.prefixlen <= prefix]
        if not candidates:
            raise ValueError(f"not enough space for {hosts} hosts")
        block = min(candidates, key=lambda b: (-b.prefixlen, b.network_address))
        free.remove(block)
        sub = next(block.subnets(new_prefix=prefix))
        free.extend(block.address_exclude(sub))
        plan.append((hosts, str(sub)))
    return plan


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cidr")
    p.add_argument("--split", type=int, help="split into subnets of this prefix length")
    p.add_argument("--vlsm", type=int, nargs="+", help="host counts to allocate")
    a = p.parse_args()

    for k, v in describe(a.cidr).items():
        print(f"{k:>16}: {v}")
    if a.split:
        print(f"\n/{a.split} subnets:")
        for s in split(a.cidr, a.split):
            print("  ", s)
    if a.vlsm:
        print("\nVLSM plan:")
        for hosts, sub in vlsm(a.cidr, a.vlsm):
            print(f"  {hosts:>6} hosts -> {sub}")


if __name__ == "__main__":
    main()
