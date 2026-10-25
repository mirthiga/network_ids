"""Builds data/real_labels.json for a real captured attack pcap, using relative
offsets (seconds from the first packet) found via find_attacks.py.
Usage: python make_real_labels.py <attack.pcap> <benign.pcap>"""
import sys, json
from scapy.all import PcapReader, IP

attack_pcap, benign_pcap = sys.argv[1], sys.argv[2]
with PcapReader(attack_pcap) as r:
    t0 = float(next(iter(r)).time)

ATTACKER = "192.168.56.101"
# offsets in seconds from capture start, read off the find_attacks.py table
WINDOWS = [
    ("port_scan",      248, 256),
    ("dos_syn_flood",  278, 294),
    ("ssh_bruteforce", 290, 302),
]
labels = [{"src": ATTACKER, "type": t, "start": t0 + s, "end": t0 + e} for t, s, e in WINDOWS]
meta = {
    "real_attack": {"pcap": attack_pcap, "labels": labels},
    "real_benign": {"pcap": benign_pcap, "labels": []},
}
json.dump(meta, open("data/real_labels.json", "w"), indent=2)
print("wrote data/real_labels.json")
for l in labels:
    print(f"  {l['type']:<16} {l['start']:.1f} -> {l['end']:.1f}  ({l['end']-l['start']:.0f}s)")