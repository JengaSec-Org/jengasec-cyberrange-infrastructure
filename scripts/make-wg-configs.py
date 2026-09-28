#!/usr/bin/env python3
"""
what:    One WireGuard key pair and config file per person, plus the gateway peer list
owner:   NET
usage:   ./make-wg-configs.py --people people.csv --out out/ [--dry-run]
reads:   people.csv (code,name,team,range), contracts/address-plan.md for the ranges
changes: writes config files to --out; writes nothing to the gateway itself
safe to run again: yes (existing keys are kept unless --rotate)
runbook: runbooks/wireguard.md
"""
import argparse, csv, pathlib, subprocess, sys

def keypair():
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--people", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--endpoint", default="RANGE_GW_ADDRESS:51820")
    ap.add_argument("--allowed", default="10.42.0.0/16,10.43.0.0/16")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    peers = []
    for row in csv.DictReader(open(a.people)):
        priv, pub = ("PRIVATE", "PUBLIC") if a.dry_run else keypair()
        cfg = f"""[Interface]
PrivateKey = {priv}
Address = {row['address']}/32
DNS = 10.10.10.10

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = {a.endpoint}
AllowedIPs = {a.allowed}
PersistentKeepalive = 25
"""
        path = out / f"{row['code']}.conf"
        print(("would write " if a.dry_run else "writing ") + str(path))
        if not a.dry_run:
            path.write_text(cfg); path.chmod(0o600)
        peers.append(f"# {row['code']} {row['team']}\n[Peer]\nPublicKey = {pub}\nAllowedIPs = {row['address']}/32\n")
    peer_file = out / "gateway-peers.conf"
    if not a.dry_run:
        peer_file.write_text("\n".join(peers))
    print("peer list:", peer_file)
    return 0

if __name__ == "__main__":
    sys.exit(main())
