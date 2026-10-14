#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Install (or update) the AI API on a Debian 12 VM as a systemd service, HTTPS on :8443
# owner:  AIC
# usage:  sudo ./ai-api/deploy/install.sh [--no-tls] [--port N] [--bind ADDR] [--reset-db] [--no-systemd]
#         run from the root of the repository or of the bundle made by make-bundle.sh
# reads:  ai-api/, contracts/, scenarios/, scripts/cells.yaml, scripts/ai-teams.yaml
# changes:apt packages (python3-venv, openssl, curl); user jengasec-ai; /opt/jengasec-ai (code + venv);
#         /etc/jengasec-ai (ai-api.env, tokens.yaml, team-tokens.txt, tls/); /var/lib/jengasec-ai (database);
#         /etc/systemd/system/jengasec-ai-api.service, jengasec-ai-marks.{service,timer}
# safe to run again: yes — code and venv are refreshed; tokens, secrets, certificate and database are kept
#         (use --reset-db to start the database again; delete /etc/jengasec-ai/tokens.yaml to re-issue tokens)
# runbook: runbooks/ai-api-vm.md
# ---------------------------------------------------------------------------
set -euo pipefail

TLS=1; PORT=8443; BIND=0.0.0.0; RESET_DB=0; SYSTEMD=1
while [ $# -gt 0 ]; do
  case "$1" in
    --no-tls) TLS=0; [ "$PORT" = 8443 ] && PORT=8000 ;;
    --port) PORT="$2"; shift ;;
    --bind) BIND="$2"; shift ;;   # only for a dedicated AI VM; on the platform VM keep the default 0.0.0.0
    --reset-db) RESET_DB=1 ;;
    --no-systemd) SYSTEMD=0 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

LOCAL=127.0.0.1
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$BIND" = 0.0.0.0 ] || LOCAL="$BIND"   # health checks and the marks timer call the address the API listens on
[ "$(id -u)" = 0 ] || die "run as root (sudo)"
SRC="$(cd "$(dirname "$0")/../.." && pwd)"
for f in ai-api/app/main.py ai-api/requirements.txt contracts/telemetry-event.schema.json contracts/telemetry-event-catalogue.yaml scripts/cells.yaml scripts/ai-teams.yaml; do
  [ -e "$SRC/$f" ] || die "$SRC/$f missing: run this from the repository or the bundle"
done
# shellcheck source=/dev/null
. /etc/os-release
[ "${VERSION_ID:-}" = 12 ] || log "warning: built for Debian 12, this is ${PRETTY_NAME:-unknown}"

APP=/opt/jengasec-ai
ETC=/etc/jengasec-ai
VAR=/var/lib/jengasec-ai
SVC_USER=jengasec-ai

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip openssl curl ca-certificates >/dev/null

log "service account and folders"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 755 "$APP"
install -d -m 750 -o root -g "$SVC_USER" "$ETC" "$ETC/tls"
install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$VAR"

log "code -> $APP/repo (contracts and data travel with it; the API validates against them)"
rm -rf "$APP/repo.new"
install -d "$APP/repo.new/scripts"
cp -r "$SRC/ai-api" "$SRC/contracts" "$SRC/scenarios" "$APP/repo.new/"
cp "$SRC/scripts/cells.yaml" "$SRC/scripts/ai-teams.yaml" "$APP/repo.new/scripts/"
# answer keys are for judges: never on the box AI teams talk to
find "$APP/repo.new/scenarios" -name answer-key.yaml -delete
find "$APP/repo.new" \( -name __pycache__ -o -name '*.db' -o -name tokens.yaml -o -name .venv \) -prune -exec rm -rf {} +
rm -rf "$APP/repo"; mv "$APP/repo.new" "$APP/repo"
chmod -R a+rX "$APP/repo"

log "python environment"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/repo/ai-api/requirements.txt"

if [ ! -f "$ETC/ai-api.env" ]; then
  log "secrets -> $ETC/ai-api.env (new)"
  umask 027
  cat > "$ETC/ai-api.env" <<EOF
# JengaSec AI API settings (ai-api/README.md). Restart after editing: systemctl restart jengasec-ai-api
REPO_ROOT=$APP/repo
DATABASE_URL=sqlite:///$VAR/ai-api.db
TOKENS_FILE=$ETC/tokens.yaml
INGEST_TOKEN=jsingest_$(openssl rand -hex 24)
ADMIN_TOKEN=jsadmin_$(openssl rand -hex 24)
# 1 = load the scripted scenarios (sandbox). Set 0 for the competition, then run install.sh --reset-db.
SANDBOX_SEED=1
ACTION_BUDGET=20
RATE_LIMIT_PER_MINUTE=600
# The website's POST /api/feed (docs/ai-integration.md). Leave empty until the website owner gives you
# the URL and its DJANGO_FEED_TOKEN; the marks timer does nothing while these are empty.
WEBSITE_FEED_URL=
WEBSITE_FEED_TOKEN=
WEBSITE_COMPETITION=
WEBSITE_CA_FILE=
# Engagement days as UTC dates, e.g. 1=2026-10-20,2=2026-10-21,3=2026-10-22 (marks are published per day)
ENGAGEMENT_DAYS=
EOF
  umask 022
fi
chown root:"$SVC_USER" "$ETC/ai-api.env"; chmod 640 "$ETC/ai-api.env"

if [ ! -f "$ETC/tokens.yaml" ]; then
  log "AI team tokens (new) -> $ETC/team-tokens.txt (root only); hashes -> $ETC/tokens.yaml"
  "$APP/venv/bin/python" "$APP/repo/ai-api/scripts/issue-tokens.py" \
    --teams "$APP/repo/scripts/ai-teams.yaml" --out "$ETC/tokens.yaml" --print-to "$ETC/team-tokens.txt" >/dev/null
fi
chown root:"$SVC_USER" "$ETC/tokens.yaml"; chmod 640 "$ETC/tokens.yaml"
chmod 600 "$ETC/team-tokens.txt" 2>/dev/null || true

SCHEME=http
TLS_ARGS=""
if [ "$TLS" = 1 ]; then
  SCHEME=https
  if [ ! -f "$ETC/tls/server.crt" ]; then
    log "TLS: self-signed certificate (replace with one from the range's internal CA, ADR 0003)"
    SAN="DNS:ai.range.jengasec.lan,DNS:jengasec.range,DNS:localhost,DNS:$(hostname),IP:127.0.0.1,IP:192.168.40.11,IP:10.109.0.10"
    [ "$BIND" = 0.0.0.0 ] || SAN="$SAN,IP:$BIND"
    for ip in $(hostname -I 2>/dev/null); do case "$ip" in *:*) ;; *) SAN="$SAN,IP:$ip" ;; esac; done
    openssl req -x509 -newkey rsa:2048 -sha256 -days 90 -nodes -subj "/CN=ai.range.jengasec.lan" \
      -addext "subjectAltName=$SAN" -keyout "$ETC/tls/server.key" -out "$ETC/tls/server.crt" 2>/dev/null
  fi
  chown root:"$SVC_USER" "$ETC/tls/server.key" "$ETC/tls/server.crt"
  chmod 640 "$ETC/tls/server.key"; chmod 644 "$ETC/tls/server.crt"
  TLS_ARGS="--ssl-keyfile $ETC/tls/server.key --ssl-certfile $ETC/tls/server.crt"
fi

if [ "$RESET_DB" = 1 ]; then
  log "database reset"
  rm -f "$VAR/ai-api.db"
fi

EXEC="$APP/venv/bin/uvicorn app.main:app --app-dir $APP/repo/ai-api --host $BIND --port $PORT --no-access-log --proxy-headers $TLS_ARGS"
cat > "$ETC/run.sh" <<EOF
#!/bin/sh
# Start the API in the foreground with the installed settings (what the systemd unit runs).
set -a; . $ETC/ai-api.env; set +a
exec $EXEC
EOF
chmod 750 "$ETC/run.sh"; chown root:"$SVC_USER" "$ETC/run.sh"

if [ "$SYSTEMD" = 1 ]; then
  log "systemd unit jengasec-ai-api.service"
  cat > /etc/systemd/system/jengasec-ai-api.service <<EOF
[Unit]
Description=JengaSec AI API (telemetry for AI teams, shadow-mode action gateway)
Documentation=file://$APP/repo/ai-api/README.md
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ETC/ai-api.env
ExecStart=$EXEC
Restart=on-failure
RestartSec=3
# hardening: the service can write only its database folder
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$VAR
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
  log "systemd timer jengasec-ai-marks.timer (pushes proposed AI marks to the website every 5 minutes)"
  cat > /etc/systemd/system/jengasec-ai-marks.service <<EOF
[Unit]
Description=Publish JengaSec AI marks to the competition website
After=jengasec-ai-api.service

[Service]
Type=oneshot
User=$SVC_USER
EnvironmentFile=$ETC/ai-api.env
ExecStart=$APP/venv/bin/python $APP/repo/ai-api/scripts/publish-marks.py --api $SCHEME://$LOCAL:$PORT/api/v1 --cacert $ETC/tls/server.crt
EOF
  cat > /etc/systemd/system/jengasec-ai-marks.timer <<EOF
[Unit]
Description=Publish JengaSec AI marks every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --quiet jengasec-ai-api
  systemctl restart jengasec-ai-api
  systemctl enable --quiet --now jengasec-ai-marks.timer
  for _ in $(seq 1 30); do
    curl -fsk "$SCHEME://$LOCAL:$PORT/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsk "$SCHEME://$LOCAL:$PORT/healthz" >/dev/null || { journalctl -u jengasec-ai-api -n 30 --no-pager; die "service did not come up"; }
  log "running: $SCHEME://$([ "$BIND" = 0.0.0.0 ] && hostname -I | awk '{print $1}' || echo "$BIND"):$PORT  (systemctl status jengasec-ai-api)"
else
  log "no systemd: start it with  sudo -u $SVC_USER $ETC/run.sh"
fi

cat <<EOF

Done.
  Team tokens (give each team only its own):  sudo cat $ETC/team-tokens.txt
  Staff and Vector tokens:                    sudo grep -E 'ADMIN|INGEST' $ETC/ai-api.env
  Certificate for clients (--cacert):         $ETC/tls/server.crt
  Check everything:                           sudo $APP/repo/ai-api/deploy/smoke.sh
  Logs (one JSON line per request):           journalctl -u jengasec-ai-api -f
EOF
