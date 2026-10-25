"""Synthetic traffic generator (no root / no network needed).
Writes PCAPs + ground-truth labels.json for every scenario.
Packets are crafted with Scapy and timestamped, so runs are reproducible (seeded)."""
import json, random, os
from scapy.all import IP, TCP, UDP, Raw, wrpcap

OUT = "data"
WEB, DNS, SSH = "10.0.1.10", "10.0.1.20", "10.0.1.30"
CLIENTS = [f"10.0.0.{i}" for i in range(11, 21)]
ATTACKER = "10.0.0.66"


def pkt(t, src, dst, l4):
    p = IP(src=src, dst=dst) / l4
    p.time = t
    return p


def tcp_flow(t, c, s, dport, n_data=3, rtt=0.01, sport=None):
    """Full TCP conversation: handshake, small data exchange, FIN."""
    sp = sport or random.randint(1025, 65000)
    out = [pkt(t, c, s, TCP(sport=sp, dport=dport, flags="S")),
           pkt(t + rtt, s, c, TCP(sport=dport, dport=sp, flags="SA")),
           pkt(t + 2 * rtt, c, s, TCP(sport=sp, dport=dport, flags="A"))]
    tt = t + 3 * rtt
    for _ in range(n_data):
        n = random.randint(60, 1200)
        out.append(pkt(tt, c, s, TCP(sport=sp, dport=dport, flags="PA") / Raw(b"x" * n)))
        out.append(pkt(tt + rtt, s, c, TCP(sport=dport, dport=sp, flags="PA") / Raw(b"y" * random.randint(100, 1400))))
        tt += random.uniform(0.02, 0.3)
    out.append(pkt(tt, c, s, TCP(sport=sp, dport=dport, flags="FA")))
    return out


def benign(t0, dur, rate=0.6):
    pk = []
    for c in CLIENTS:
        t = t0 + random.uniform(0, 2)
        while t < t0 + dur:
            r = random.random()
            if r < 0.55:   pk += tcp_flow(t, c, WEB, 443, random.randint(2, 6))
            elif r < 0.80: pk += tcp_flow(t, c, WEB, 80, random.randint(1, 4))
            elif r < 0.95: pk += [pkt(t, c, DNS, UDP(sport=random.randint(1025, 65000), dport=53) / Raw(b"q" * 40)),
                                  pkt(t + .01, DNS, c, UDP(sport=53, dport=1234) / Raw(b"r" * 90))]
            else:          pk += tcp_flow(t, c, SSH, 22, random.randint(5, 15))  # a legit SSH session
            t += random.expovariate(rate)
    return pk


def port_scan(t0, rate=40, src=ATTACKER, dst=WEB, ports=None):
    ports = ports or random.sample(range(1, 1025), 1024)
    return [pkt(t0 + i / rate, src, dst, TCP(sport=random.randint(1025, 65000), dport=p, flags="S")) for i, p in enumerate(ports)]


def syn_flood(t0, dur=10, pps=1500, src=ATTACKER, dst=WEB):
    return [pkt(t0 + i / pps, src, dst, TCP(sport=random.randint(1025, 65000), dport=80, flags="S"))
            for i in range(int(dur * pps))]


def ssh_bruteforce(t0, dur=30, rate=4, src=ATTACKER, dst=SSH):
    pk, t = [], t0
    while t < t0 + dur:
        pk += tcp_flow(t, src, dst, 22, n_data=2, rtt=0.02)  # handshake + auth attempt + close
        t += random.expovariate(rate)
    return pk


def save(name, pkts, labels):
    pkts.sort(key=lambda p: float(p.time))
    wrpcap(f"{OUT}/{name}.pcap", pkts)
    return {"pcap": f"{OUT}/{name}.pcap", "labels": labels}


def main():
    random.seed(7)
    os.makedirs(OUT, exist_ok=True)
    T = 1_700_000_000.0
    meta = {}
    # training set: benign only (separate random draw from test benign)
    meta["train"] = save("train_benign", benign(T, 180), [])
    # S1 benign baseline
    meta["s1_benign"] = save("s1_benign", benign(T, 90), [])
    # S2 port scan (fast SYN scan of ports 1-1024, 40 pps)
    meta["s2_portscan"] = save("s2_portscan", benign(T, 90) + port_scan(T + 30),
                               [{"src": ATTACKER, "type": "port_scan", "start": T + 30, "end": T + 30 + 1024 / 40}])
    # S3 SYN flood
    meta["s3_dos"] = save("s3_dos", benign(T, 90) + syn_flood(T + 30, 10),
                          [{"src": ATTACKER, "type": "dos_syn_flood", "start": T + 30, "end": T + 40}])
    # S4 SSH brute force
    meta["s4_bruteforce"] = save("s4_bruteforce", benign(T, 90) + ssh_bruteforce(T + 30, 30),
                                 [{"src": ATTACKER, "type": "ssh_bruteforce", "start": T + 30, "end": T + 60}])
    # S5 ambiguous: (a) slow scan 1 probe / 2 s (malicious, evades windowed rules)
    #               (b) benign health-checker probing 30 ports in a burst (looks like a scan, is not)
    slow = port_scan(T + 5, rate=0.5, src="10.0.0.77", ports=random.sample(range(1, 1025), 40))
    health = port_scan(T + 40, rate=20, src="10.0.0.99", ports=list(range(8000, 8030)))
    meta["s5_ambiguous"] = save("s5_ambiguous", benign(T, 90) + slow + health,
                                [{"src": "10.0.0.77", "type": "port_scan", "start": T + 5, "end": T + 85}])
    json.dump(meta, open(f"{OUT}/labels.json", "w"), indent=2)
    print("generated:", ", ".join(meta))


if __name__ == "__main__":
    main()
