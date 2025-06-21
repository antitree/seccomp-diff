#!/usr/bin/env bash
# Extract kubeconfig from the master node and patch it for host usage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

vagrant ssh master -c 'sudo cat /etc/rancher/k3s/k3s.yaml' > kubeconfig

# Replace localhost with master IP
sed -i 's/127.0.0.1/192.168.56.10/' kubeconfig
# Remove certificate authority data to avoid TLS validation
sed -i '/certificate-authority-data/d' kubeconfig
# Disable TLS verification
sed -i "/server: https:\/\/192.168.56.10:6443/a\    insecure-skip-tls-verify: true" kubeconfig

echo "Kubeconfig written to $(pwd)/kubeconfig"

