"""Scans a real attack pcap and prints likely attack windows, grouped by source IP,
using simple heuristics: packet-rate spikes and SYN-heavy bursts.
Usage: python find_attacks.py <attack.pcap>"""
import sys
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP

pcap = sys.argv[1]
WIN = 2.0  # seconds

buckets = defaultdict(lambda: defaultdict(lambda: {"syn":0,"pkts":0,"ports":set()}))
t0 = None
with PcapReader(pcap) as r:
    for p in r:
        if IP not in p: continue
        t = float(p.time)
        if t0 is None: t0 = t
        w = int((t - t0)//WIN)
        src = p[IP].src
        b = buckets[w][src]
        b["pkts"] += 1
        if TCP in p:
            if int(p[TCP].flags) & 0x02 and not int(p[TCP].flags) & 0x10:
                b["syn"] += 1
            b["ports"].add(p[TCP].dport)

print(f"{'win':>4} {'t(s)':>8} {'src':<16} {'pkts':>6} {'syn':>6} {'ports':>6}")
for w in sorted(buckets):
    for src, b in buckets[w].items():
        if b["pkts"] < 20 and b["syn"] < 10 and len(b["ports"]) < 10:
            continue  # skip quiet/benign-looking rows
        print(f"{w:>4} {w*WIN:>8.1f} {src:<16} {b['pkts']:>6} {b['syn']:>6} {len(b['ports']):>6}")