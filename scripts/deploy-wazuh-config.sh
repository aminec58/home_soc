#!/usr/bin/env bash
# Déploie la configuration de détection du dépôt sur le manager Wazuh :
#   - wazuh/local_rules.xml  → /var/ossec/etc/rules/local_rules.xml
#   - wazuh/shared/agent.conf → /var/ossec/etc/shared/default/agent.conf
# Valide avec wazuh-analysisd -t avant de redémarrer ; restaure l'ancienne
# version en cas d'échec.
#
# Les blocs à placer dans ossec.conf (wazuh/manager/active-response.xml,
# wazuh/manager/integration-thehive.xml) restent à intégrer à la main : ils
# s'insèrent dans un fichier existant et contiennent des valeurs propres au lab.
#
# Usage, depuis la racine du dépôt sur le manager :
#   sudo ./scripts/deploy-wazuh-config.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] À lancer en root : sudo $0" >&2; exit 1; }
cd "$(dirname "$0")/.."

OSSEC=/var/ossec
STAMP=$(date +%Y%m%d-%H%M%S)
declare -A FILES=(
  [wazuh/local_rules.xml]="$OSSEC/etc/rules/local_rules.xml"
  [wazuh/shared/agent.conf]="$OSSEC/etc/shared/default/agent.conf"
)

for src in "${!FILES[@]}"; do
  dst=${FILES[$src]}
  [[ -f $dst ]] && cp -p "$dst" "$dst.bak.$STAMP"
  install -o root -g wazuh -m 660 "$src" "$dst"
  echo "[*] $src → $dst"
done

if "$OSSEC/bin/wazuh-analysisd" -t; then
  systemctl restart wazuh-manager
  echo "[+] Configuration déployée, manager redémarré ($(systemctl is-active wazuh-manager))."
else
  echo "[!] wazuh-analysisd -t en échec : restauration des sauvegardes" >&2
  for dst in "${FILES[@]}"; do
    [[ -f $dst.bak.$STAMP ]] && cp -p "$dst.bak.$STAMP" "$dst"
  done
  exit 1
fi
