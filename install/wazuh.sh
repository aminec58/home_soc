#!/usr/bin/env bash
# Installation Wazuh all-in-one (manager + indexer + dashboard)
# VM wazuh-manager — Ubuntu 22.04, 8 Go RAM / 2 vCPU mini
set -euo pipefail

echo "[*] Mise à jour + curl"
apt update && apt install -y curl

echo "[*] Téléchargement du script officiel Wazuh 4.9"
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

echo "[*] Installation all-in-one (10-15 min)"
bash ./wazuh-install.sh -a

echo "[*] Activation du démarrage automatique"
systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard

echo "[+] Terminé. Mots de passe : wazuh-install-files/wazuh-passwords.txt"
echo "[+] Dashboard : https://<IP_VM> (utilisateur admin)"
