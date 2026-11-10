#!/usr/bin/env bash
# Installation Wazuh all-in-one (manager + indexer + dashboard)
# VM wazuh — Ubuntu 22.04, 8 Go RAM / 2 vCPU mini
#
# Version : le lab tourne en 4.9.2. Les agents doivent être de version
# inférieure ou égale au manager : les installer en 4.9.2-1 et les épingler
# (apt-mark hold), voir docs/vms/build-victime-ubuntu.md.
#
# Usage : sudo ./install/wazuh.sh
# Ensuite : sudo ./scripts/deploy-wazuh-config.sh (règles, agent.conf, Active Response)
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] À lancer en root : sudo $0" >&2; exit 1; }

WAZUH_BRANCH="4.9"
CREDS_FILE="/root/wazuh-credentials.txt"

echo "[*] Mise à jour + curl"
apt update && apt install -y curl tar

echo "[*] Téléchargement du script officiel Wazuh ${WAZUH_BRANCH}"
cd /root
curl -sO "https://packages.wazuh.com/${WAZUH_BRANCH}/wazuh-install.sh"

echo "[*] Installation all-in-one (10-15 min)"
bash ./wazuh-install.sh -a

echo "[*] Activation du démarrage automatique"
systemctl enable wazuh-indexer wazuh-manager wazuh-dashboard

echo "[*] Extraction des mots de passe générés vers ${CREDS_FILE}"
umask 077
tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt > "$CREDS_FILE"

echo "[+] Terminé. Version installée : $(/var/ossec/bin/wazuh-control info -v)"
echo "[+] Mots de passe : ${CREDS_FILE} (hors dépôt)"
echo "[+] Dashboard : https://<IP_VM> (utilisateur admin)"
