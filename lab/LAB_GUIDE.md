# Step 1 - Build your own real, labelled dataset

Goal: real packets from real tools (nmap / hping3 / hydra) in a lab YOU own, with exact ground-truth timestamps.
Only ever attack your own VMs on an isolated network. Never point these tools at anything you don't own.

## 1. Lab setup (30-45 min)
Use VirtualBox/VMware/UTM, or Docker. Two VMs on a **Host-Only** or **Internal** network:

| VM | OS | Role | Install |
|---|---|---|---|
| victim | Ubuntu Server | web + SSH target + capture point | `sudo apt install openssh-server apache2 tcpdump` |
| attacker | Kali (or Ubuntu) | attack tools | `sudo apt install nmap hping3 hydra` |

On victim: create an SSH user `testuser` with a weak password that IS in the wordlist head (so brute force is realistic).
Find IPs with `ip a` (e.g. victim 192.168.56.10, attacker 192.168.56.20). Check `ping` works both ways.

## 2. Capture benign traffic (training + Scenario 1)
Benign traffic must look like real use, not silence. On victim start the capture:
```bash
sudo tcpdump -i <iface> -w benign_train.pcap host 192.168.56.10 &
```
For ~15 minutes, from a THIRD source (your host machine or a second client VM) generate normal behaviour:
browse the Apache page (`curl`/browser, refresh often), `ssh testuser@victim` and run a few commands,
`scp` a file, `ping`, DNS lookups, and run a normal `wget` of a large file. Vary it - mix quiet and busy periods.
Stop with `sudo pkill tcpdump`. Repeat for 5 min as `benign_test.pcap` (a different session - used only for testing).

## 3. Capture the attacks
Victim: `sudo tcpdump -i <iface> -w attack_run.pcap host 192.168.56.10 &`
(keep a little benign browsing going from the other client during the attacks - realistic mixed traffic!)
Attacker: 
```bash
sudo ./lab/run_attacks.sh 192.168.56.10 192.168.56.10
```
This runs nmap SYN scan -> hping3 SYN flood -> hydra SSH brute force, 20 s apart, and writes `events.log`
with exact start/end epoch times. Copy `events.log` and the pcaps to your analysis machine.
Check `tcpdump` clocks: both VMs should be time-synced (`timedatectl`), or run both capture + attacks from the same VM clock reference.

## 4. Look at it in Wireshark (for your video + understanding)
Open `attack_run.pcap`. Screenshot: Statistics -> Conversations (scan = hundreds of tiny conversations),
Statistics -> I/O Graph (flood spike), filter `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.port==22` (brute force).
You'll explain these in the video: this is the "network understanding" the graders want.

## 5. Run the IDS on your real data
```bash
python ids.py train --pcap benign_train.pcap --model real_model.joblib      # learn YOUR benign baseline
python lab/make_labels.py events.log attack_run.pcap data/real_labels.json benign_test.pcap
python ids.py evaluate --meta data/real_labels.json --model real_model.joblib --tag _real
python ids.py detect attack_run.pcap      # (uses model.joblib; copy real_model.joblib over it to use yours)
```

## 6. What to expect and write down (this is your report material)
* Thresholds tuned on synthetic data (15 ports, 300 SYN, 12 attempts) may be wrong on real traffic: hping3 --flood may
  be far above 300; hydra's rate depends on `-t`; nmap -T4 vs -T2 changes rate. **Record what failed and fix it
  using a plot of your real benign feature distribution** - that is exactly the "iterate from evidence" story.
* Expect false positives from your benign training being small/too quiet. Capture more variety and retrain.
* Compare synthetic vs real results in one table.
* Optional extras: `nmap -T1` (slow scan) and `hydra -t 1` (slow brute force) as your Scenario 5 on real data.

## Optional: CICIDS2017
Its PCAPs are ~10 GB/day (too slow for Scapy) and the popular CSVs are flow-level (CICFlowMeter), a different feature
space. Treat it as a supplement: use a short time slice of the Tuesday (brute force) / Wednesday (DoS) PCAP via
`editcap -A "<start>" -B "<end>" in.pcap slice.pcap`, then run `ids.py detect` on the slice.
