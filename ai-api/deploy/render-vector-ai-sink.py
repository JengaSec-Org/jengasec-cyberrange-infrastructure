#!/usr/bin/env python3
"""
what:    Render ai-api/deploy/vector-ai-sink.yaml for one environment (OBS VM, or the local rehearsal)
owner:   AIC (run by OBS when deploying, like their __WEBSITE_FEED_URL__ rendering)
usage:   render-vector-ai-sink.py --url https://192.168.40.11:8443/api/v1/ingest --ca-file /etc/vector/ai/ai-ca.crt \
             --secret-file /etc/vector/ai/ai-secret.json --out DIR/vector-ai-sink.yaml
         render-vector-ai-sink.py --url http://host.docker.internal:8766/api/v1/ingest --secret-file ... --out ...
         (an http:// URL is rehearsal only: the TLS block is dropped)
reads:   ai-api/deploy/vector-ai-sink.yaml
changes: writes --out only. It never sees the token: that lives in the secret file, which OBS creates
         (mode 0600, owned by the Vector user) with {"ingest_token": "..."}.
safe to run again: yes
"""
import argparse
import pathlib
import re
import sys

TEMPLATE = pathlib.Path(__file__).with_name("vector-ai-sink.yaml")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--secret-file", required=True, help="path INSIDE the Vector container/host")
    ap.add_argument("--ca-file", help="required for https://")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not re.fullmatch(r"https?://[A-Za-z0-9.\-:\[\]]+(:\d+)?/api/v1/ingest", a.url):
        print("--url must look like https://<host>:<port>/api/v1/ingest", file=sys.stderr)
        return 2
    https = a.url.startswith("https://")
    if https and not a.ca_file:
        print("--ca-file is required for an https:// URL", file=sys.stderr)
        return 2

    text = TEMPLATE.read_text(encoding="utf-8")
    if https:
        text = text.replace("__AI_CA_FILE__", a.ca_file)
        text = re.sub(r"[ \t]*# __AI_TLS_(BEGIN|END)__\n", "", text)
    else:
        text = re.sub(r"[ \t]*# __AI_TLS_BEGIN__\n.*?# __AI_TLS_END__\n", "", text, flags=re.S)
    text = text.replace("__AI_INGEST_URL__", a.url).replace("__AI_SECRET_FILE__", a.secret_file)
    leftover = re.findall(r"__AI_[A-Z_]+__", text)
    if leftover:
        print(f"unrendered placeholders: {leftover}", file=sys.stderr)
        return 1
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {out} ({'https' if https else 'http rehearsal, no TLS'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
