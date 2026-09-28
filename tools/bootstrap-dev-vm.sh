#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Set up a JengaSec development machine on a fresh Debian 12 VM
# owner:  anyone
# usage:  ./bootstrap-dev-vm.sh          (run as your normal user, not root)
# changes: installs tools, creates an SSH key if you have none, clones nothing
# safe to run again: yes
# ---------------------------------------------------------------------------
set -euo pipefail

echo "== JengaSec dev VM setup (Debian 12) =="
[ "$(id -u)" -ne 0 ] || { echo "Run as your own user, not root."; exit 1; }

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl git gnupg jq make python3 python3-pip python3-venv \
  shellcheck unzip vim wireguard-tools

# kubectl
if ! command -v kubectl >/dev/null; then
  curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl
fi

# helm
if ! command -v helm >/dev/null; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# ansible, yamllint, pre-commit (user install)
python3 -m pip install --user --upgrade ansible-core yamllint pre-commit requests PyYAML

# ssh key
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
  read -r -p "Your JengaSec code (e.g. NET-A2): " code
  ssh-keygen -t ed25519 -C "${code}@jengasec" -f "$HOME/.ssh/id_ed25519"
fi

cat <<'EOF'

Done. Next:
  1. Add ~/.ssh/id_ed25519.pub to ansible/group_vars/all/users.yml in a pull request.
  2. Add yourself to docs/people.md in the same pull request.
  3. Run: pre-commit install     (inside your clone of jengasec-infra)

Want a cluster to test against on this VM?
  curl -sfL https://get.k3s.io | sh -      # single-node k3s, same as the real one
  sudo k3s kubectl get nodes
EOF
