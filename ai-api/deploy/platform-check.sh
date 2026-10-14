#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Check that the platform VM (VM 101: website + AI API + scoring) can reach the other VMs and be
#         reached by them, flow by flow (docs/platform-vm.md section 3)
# owner:  AIC
# usage:  sudo ./platform-check.sh                 on VM 101: local services, outbound flows, routes, firewall
#         ./platform-check.sh probe <address>      from another VM or a WireGuard laptop: can I reach VM 101?
#         settings via environment (defaults from the server VM sheet):
#           OBS_IP=192.168.40.60 K8S_BLUE_IP=192.168.40.59 PG_IP=192.168.40.45 WG_VM_IP=192.168.40.47
#           VLAN109_IP=10.109.0.10 WG_NEXT_HOP=10.109.0.40 WEBSITE_LOCAL=http://127.0.0.1:8000
#           WEB_ENV=/etc/jengasec/web.env AI_ENV=/etc/jengasec-ai/ai-api.env KUBECONFIG_WEBSITE=~/website.kubeconfig
# reads:  the two env files above (for the database host and the feed settings); never prints secrets
# changes:nothing (read-only checks; one POST to /api/feed WITHOUT a token, which the website refuses)
# safe to run again: yes
# runbook: docs/platform-vm.md
# ---------------------------------------------------------------------------
set -uo pipefail

OBS_IP="${OBS_IP:-192.168.40.60}"
K8S_BLUE_IP="${K8S_BLUE_IP:-192.168.40.59}"
PG_IP="${PG_IP:-192.168.40.45}"
WG_VM_IP="${WG_VM_IP:-192.168.40.47}"
VLAN109_IP="${VLAN109_IP:-10.109.0.10}"
WG_NEXT_HOP="${WG_NEXT_HOP:-10.109.0.40}"
WEBSITE_LOCAL="${WEBSITE_LOCAL:-http://127.0.0.1:8000}"
WEB_ENV="${WEB_ENV:-/etc/jengasec/web.env}"
AI_ENV="${AI_ENV:-/etc/jengasec-ai/ai-api.env}"
KUBECONFIG_WEBSITE="${KUBECONFIG_WEBSITE:-$HOME/website.kubeconfig}"

PASS=0; WARN=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf '  warn  %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }
head_() { printf '\n%s\n' "$*"; }
tcp()  { timeout 4 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }          # host port -> 0 if it connects
code() { local c; c=$(curl -sk -o /dev/null -m 6 -w '%{http_code}' "$@" 2>/dev/null); echo "${c:-000}"; }
# A real PostgreSQL server answers an SSLRequest with one byte, S or N. A bare TCP connect is not proof:
# NAT boxes, proxies and Docker Desktop accept connections for hosts they cannot reach.
pg_ok() {
  python3 - "$1" "${2:-5432}" <<'PY' 2>/dev/null
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
s.sendall((8).to_bytes(4, "big") + (80877103).to_bytes(4, "big"))   # SSLRequest: length 8, code 1234<<16|5679
sys.exit(0 if s.recv(1) in (b"S", b"N") else 1)
PY
}
# The Kubernetes API answers /version over TLS (200, or 401/403 without a token).
k8s_ok() { case "$(code "https://$1:6443/version")" in 200|401|403) return 0 ;; *) return 1 ;; esac; }
envval() { [ -r "$1" ] && sed -n "s/^$2=//p" "$1" | tail -1; }       # file key -> value (not printed by callers)

probe() {
  local h="$1"
  echo "Probing the platform VM at $h from $(hostname) ($(hostname -I 2>/dev/null | awk '{print $1}'))"
  head_ "Website (flow I3 / I2)"
  if tcp "$h" 443; then ok "TCP 443 open"; else bad "TCP 443 unreachable: check the gateway, wireguard-vm's service rule, and VM 101's firewall"; fi
  local c; c=$(code "https://$h/healthz/")
  case "$c" in 200) ok "https://$h/healthz/ answers 200" ;; 000) bad "https://$h/healthz/ gave no answer" ;; *) warn "https://$h/healthz/ answered $c" ;; esac
  head_ "AI API (flow I1 / I4)"
  if tcp "$h" 8443; then ok "TCP 8443 open"; else warn "TCP 8443 unreachable (expected unless you are OBS, an AI team or staff)"; fi
  c=$(code "https://$h:8443/healthz")
  case "$c" in 200) ok "https://$h:8443/healthz answers 200" ;; 000) warn "AI API gave no answer" ;; *) warn "AI API answered $c" ;; esac
  head_ "Must NOT be reachable"
  for p in 8000 5432 11434; do
    if tcp "$h" "$p"; then bad "port $p is reachable from here: it must stay local to VM 101"; else ok "port $p closed from here"; fi
  done
}

local_checks() {
  [ "$(id -u)" = 0 ] || echo "(not root: firewall and env-file checks may be incomplete)"
  echo "Platform VM self-check on $(hostname): $(hostname -I 2>/dev/null)"

  head_ "Services on this VM"
  local c
  c=$(code "$WEBSITE_LOCAL/healthz/"); [ "$c" = 200 ] && ok "website (gunicorn) answers on $WEBSITE_LOCAL" || bad "website on $WEBSITE_LOCAL answered $c (is gunicorn running?)"
  c=$(code "https://127.0.0.1/healthz/"); [ "$c" = 200 ] && ok "nginx serves the website on 443" || warn "nginx on 443 answered $c (website docs/VENUE-HOSTING.md: nginx + TLS)"
  c=$(code "https://127.0.0.1:8443/healthz"); [ "$c" = 200 ] && ok "AI API answers on 8443" || bad "AI API on 8443 answered $c (systemctl status jengasec-ai-api)"
  c=$(code "http://127.0.0.1:11434/api/tags"); [ "$c" = 200 ] && ok "Ollama answers locally (proposal scoring)" || warn "Ollama not answering on 127.0.0.1:11434 (only needed for proposal scoring)"

  head_ "AI marks -> website (flow O5)"
  local feed tok
  feed=$(envval "$AI_ENV" WEBSITE_FEED_URL); tok=$(envval "$AI_ENV" WEBSITE_FEED_TOKEN)
  if [ -z "$feed" ]; then warn "WEBSITE_FEED_URL is empty in $AI_ENV: AI marks are not published"
  else
    [ -n "$tok" ] && ok "feed URL and token are set ($feed)" || bad "WEBSITE_FEED_TOKEN is empty in $AI_ENV"
    c=$(code -X POST -H 'Content-Type: application/json' --data '{}' "$feed")
    case "$c" in
      403) ok "website feed exists and refuses a request without the token (as it should)" ;;
      404) bad "website feed answered 404: DJANGO_FEED_TOKEN is not set on the website" ;;
      *)   bad "website feed answered $c at $feed" ;;
    esac
  fi

  head_ "Outbound flows"
  local dburl dbhost
  dburl=$(envval "$WEB_ENV" JENGASEC_DB_URL); dbhost=$(printf '%s' "$dburl" | sed -E 's#^[a-z]+://([^@]*@)?([^:/?]+).*#\2#')
  if [ -n "$dbhost" ]; then
    if pg_ok "$dbhost" 5432; then ok "O1 website database $dbhost:5432 answers as PostgreSQL"; else bad "O1 website database $dbhost:5432 does not answer as PostgreSQL (internet down? Neon?)"; fi
  else warn "O1 could not read JENGASEC_DB_URL from $WEB_ENV"; fi
  if k8s_ok "$K8S_BLUE_IP"; then ok "O2 k8s-blue API $K8S_BLUE_IP:6443 answers /version"; else bad "O2 k8s-blue API $K8S_BLUE_IP:6443 does not answer (website-access.sh grant on VM 106 opens it)"; fi
  if [ -r "$KUBECONFIG_WEBSITE" ] && command -v kubectl >/dev/null; then
    if kubectl --kubeconfig "$KUBECONFIG_WEBSITE" get ns >/dev/null 2>&1; then ok "website kubeconfig authenticates"; else bad "website kubeconfig rejected (website-access.sh rotate?)"; fi
  else warn "no $KUBECONFIG_WEBSITE or no kubectl: skipped the kubeconfig check"; fi
  if pg_ok "$PG_IP" 5432; then ok "O3 postgres-vm $PG_IP:5432 answers as PostgreSQL (NET pipeline database)"; else warn "O3 postgres-vm $PG_IP:5432 does not answer as PostgreSQL"; fi
  ping -c1 -W2 "$OBS_IP" >/dev/null 2>&1 && ok "OBS VM $OBS_IP answers ping" || warn "OBS VM $OBS_IP does not answer ping"
  ping -c1 -W2 "$WG_VM_IP" >/dev/null 2>&1 && ok "wireguard-vm $WG_VM_IP answers ping" || warn "wireguard-vm $WG_VM_IP does not answer ping"

  head_ "Participant network (VLAN 109)"
  if ip -4 addr show 2>/dev/null | grep -q "inet $VLAN109_IP/"; then
    ok "this VM has $VLAN109_IP"
    local r
    for ip in 10.60.2.13 10.62.1.10 10.64.1.10; do
      r=$(ip route get "$ip" 2>/dev/null | head -1)
      case "$r" in *"via $WG_NEXT_HOP"*|*"via 10.109.0.1 "*) ok "replies to $ip go back through the VPN ($r)" ;;
                   *) bad "replies to $ip would go: $r  (add the routes in docs/platform-vm.md section 4)" ;; esac
    done
  else
    warn "$VLAN109_IP is not configured here yet: participants cannot reach this VM until NET makes VLAN 109 live"
  fi

  head_ "Exposure and firewall"
  if command -v ss >/dev/null; then
    if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE '^(0\.0\.0\.0|\*|\[::\]):8000$'; then
      bad "gunicorn listens on all addresses (:8000): bind it to 127.0.0.1:8000 so only nginx reaches it"
    else ok "gunicorn is not exposed beyond this VM"; fi
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE ':11434$' && \
      { ss -ltnH | awk '{print $4}' | grep -qE '^127\.0\.0\.1:11434$' && ok "Ollama only on 127.0.0.1" || bad "Ollama listens beyond 127.0.0.1"; }
  fi
  if command -v nft >/dev/null && [ "$(id -u)" = 0 ]; then
    if nft list ruleset 2>/dev/null | grep -q 'dport 8443'; then ok "host firewall loaded (8443 rule present)"; else warn "no host firewall rule for 8443 (docs/platform-vm.md section 5)"; fi
  else warn "cannot read nftables (not root or nft missing)"; fi

  printf '\nNext: run "platform-check.sh probe 192.168.40.11" on the OBS VM, and "platform-check.sh probe %s" from a WireGuard laptop.\n' "$VLAN109_IP"
}

if [ "${1:-}" = probe ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 probe <platform-vm-address>" >&2; exit 2; }
  probe "$2"
else
  local_checks
fi
printf '\n%s ok, %s warnings, %s failed\n' "$PASS" "$WARN" "$FAIL"
[ "$FAIL" = 0 ]
