#!/usr/bin/env bash
# Installation Elasticsearch + Kibana (noeud unique)
# VM elastic — 192.168.56.20 (host-only) — Ubuntu 22.04, 4 Go RAM / 2 vCPU
#
# Reproduit l'installation validée manuellement le 13/09/2026, complétée par
# le chiffrement TLS de Kibana le 17/09/2026 (HOMESOC-11) :
# Elasticsearch 8.19.21 + Kibana 8.19.21, sécurité auto-configurée par le
# paquet (TLS + mot de passe elastic générés automatiquement), heap JVM
# plafonnée à 1200 Mo pour laisser de la marge à Kibana sur une VM à 4 Go.
#
# Elasticsearch expose déjà du HTTPS dès l'installation (certificats générés
# par le paquet). Kibana, lui, démarre en clair : ce script lui génère un
# certificat auto-signé et bascule son écoute en HTTPS. Le certificat porte
# l'IP dans son subjectAltName, faute de quoi les navigateurs le rejettent
# (ils ignorent le champ CN depuis longtemps).
#
# Recevra les alertes Wazuh via Filebeat sur le port 9200 (HOMESOC-13) et
# expose Kibana sur le port 5601. Voir docs/architecture.md pour les flux.
#
# Usage :  sudo ./install/elastic.sh
# Notes :
#  - Le mot de passe du compte « elastic » et le certificat CA HTTP sont
#    générés par Elasticsearch lui-même à l'installation ; ce script les
#    affiche à l'écran et les recopie dans /root/elastic-credentials.txt
#    (jamais dans le dépôt Git — voir .gitignore).
#  - Le jeton d'enrôlement Kibana n'est valable que quelques minutes ; ce
#    script l'utilise immédiatement après génération.
#  - Prérequis : IP host-only statique. Ubuntu régénère
#    /etc/netplan/50-cloud-init.yaml au démarrage, donc la config statique
#    doit vivre dans un fichier séparé avec cloud-init neutralisé — sinon
#    la VM reprend une adresse DHCP au reboot et le certificat ne
#    correspond plus. Voir README.md.
set -euo pipefail

ELASTIC_VERSION="8.19.21"   # figé — voir docs/architecture.md
NODE_IP="${NODE_IP:-192.168.56.20}"
LAB_SUBNET="192.168.56.0/24"
HEAP_SIZE="${HEAP_SIZE:-1200m}"
CREDS_FILE="/root/elastic-credentials.txt"
CA_FILE="/etc/elasticsearch/certs/http_ca.crt"
KIBANA_CERT_DIR="/etc/kibana/certs"

[[ $EUID -eq 0 ]] || { echo "[!] À lancer en root : sudo $0" >&2; exit 1; }

echo "[*] Mise à jour + dépendances"
apt update
apt install -y curl gnupg apt-transport-https ca-certificates jq openssl

echo "[*] Paramètre noyau requis par Elasticsearch (vm.max_map_count)"
echo "vm.max_map_count=262144" > /etc/sysctl.d/99-elasticsearch.conf
sysctl -q -w vm.max_map_count=262144

echo "[*] Ajout du dépôt Elastic 8.x"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
cat > /etc/apt/sources.list.d/elastic-8.x.list <<EOF
deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main
EOF
apt update

echo "[*] Installation d'Elasticsearch ${ELASTIC_VERSION}"
echo "    (le mot de passe du compte elastic va s'afficher ci-dessous — il sera aussi enregistré dans ${CREDS_FILE})"
apt install -y "elasticsearch=${ELASTIC_VERSION}"

# Elasticsearch 8.x auto-configure sécurité + TLS à l'installation (le paquet
# écrit déjà xpack.security.* et les certificats dans elasticsearch.yml) :
# on n'écrase donc PAS ce fichier, on se contente d'ajouter l'écoute réseau.
echo "[*] Ouverture de l'écoute réseau (network.host)"
if ! grep -q '^network.host:' /etc/elasticsearch/elasticsearch.yml; then
  echo "network.host: 0.0.0.0" >> /etc/elasticsearch/elasticsearch.yml
fi

echo "[*] Plafonnement de la heap JVM à ${HEAP_SIZE} (laisse de la marge pour Kibana)"
mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options <<EOF
-Xms${HEAP_SIZE}
-Xmx${HEAP_SIZE}
EOF

echo "[*] Activation et démarrage d'Elasticsearch"
systemctl daemon-reload
systemctl enable elasticsearch.service
systemctl restart elasticsearch.service

echo "[*] Attente de la disponibilité du noeud (9200)"
for i in $(seq 1 60); do
  [[ -f "$CA_FILE" ]] && curl -s --cacert "$CA_FILE" "https://localhost:9200" >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && { echo "[!] Elasticsearch n'a pas démarré. journalctl -u elasticsearch" >&2; exit 1; }
  sleep 5
done

# Le mot de passe généré à l'installation n'est affiché qu'une seule fois
# dans la sortie d'apt : s'il n'a pas été récupéré, on le regénère proprement.
if [[ ! -f "$CREDS_FILE" ]]; then
  echo "[*] Réinitialisation du mot de passe elastic (capture pour ce script)"
  ELASTIC_PASSWORD="$(/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b -s)"
else
  ELASTIC_PASSWORD="$(grep '^elastic_password=' "$CREDS_FILE" | cut -d= -f2)"
fi

echo "[*] Installation de Kibana ${ELASTIC_VERSION}"
apt install -y "kibana=${ELASTIC_VERSION}"

echo "[*] Ouverture de l'écoute réseau pour Kibana"
if ! grep -q '^server.host:' /etc/kibana/kibana.yml; then
  echo "server.host: 0.0.0.0" >> /etc/kibana/kibana.yml
fi

echo "[*] Enrôlement de Kibana auprès d'Elasticsearch"
TOKEN="$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)"
/usr/share/kibana/bin/kibana-setup --enrollment-token "$TOKEN"

# ------------------------------------------------------- TLS Kibana (HS-11) --
echo "[*] Génération du certificat auto-signé de Kibana"
# subjectAltName avec l'IP : indispensable, les navigateurs modernes ignorent
# le champ CN et ne valident que ce champ-là.
mkdir -p "$KIBANA_CERT_DIR"
if [[ ! -f "${KIBANA_CERT_DIR}/kibana.crt" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "${KIBANA_CERT_DIR}/kibana.key" \
    -out "${KIBANA_CERT_DIR}/kibana.crt" \
    -subj "/C=FR/ST=Bourgogne/L=Auxerre/O=Home SOC/CN=${NODE_IP}" \
    -addext "subjectAltName=IP:${NODE_IP}"
fi
# Kibana tourne sous son propre utilisateur et doit pouvoir lire la clé.
chown -R root:kibana "$KIBANA_CERT_DIR"
chmod 640 "${KIBANA_CERT_DIR}/kibana.key"
chmod 644 "${KIBANA_CERT_DIR}/kibana.crt"

echo "[*] Activation du TLS sur Kibana"
if ! grep -q '^server.ssl.enabled:' /etc/kibana/kibana.yml; then
  cat >> /etc/kibana/kibana.yml <<EOF

# TLS (HOMESOC-11) — certificat auto-signé
server.ssl.enabled: true
server.ssl.certificate: ${KIBANA_CERT_DIR}/kibana.crt
server.ssl.key: ${KIBANA_CERT_DIR}/kibana.key
EOF
fi

echo "[*] Activation et démarrage de Kibana"
systemctl daemon-reload
systemctl enable kibana.service
systemctl restart kibana.service

echo "[*] Attente de la disponibilité de Kibana (5601, HTTPS) — peut prendre 30-60s"
for i in $(seq 1 24); do
  LEVEL="$(curl -sk https://localhost:5601/api/status 2>/dev/null | jq -r '.status.overall.level' 2>/dev/null || true)"
  [[ "$LEVEL" == "available" ]] && break
  [[ $i -eq 24 ]] && { echo "[!] Kibana n'a pas démarré à temps. journalctl -u kibana" >&2; exit 1; }
  sleep 5
done

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "[*] Ouverture des ports 9200 et 5601 depuis ${LAB_SUBNET}"
  ufw allow from "$LAB_SUBNET" to any port 9200 proto tcp
  ufw allow from "$LAB_SUBNET" to any port 5601 proto tcp
fi

umask 077
cat > "$CREDS_FILE" <<EOF
# Lab Home SOC — VM elastic (${NODE_IP})
# Généré le $(date '+%F %T') par install/elastic.sh
# NE JAMAIS COMMITTER CE FICHIER (voir .gitignore : *password*, *secret*, *credential*)
elastic_version=${ELASTIC_VERSION}
elastic_user=elastic
elastic_password=${ELASTIC_PASSWORD}
kibana_url=https://${NODE_IP}:5601
elasticsearch_url=https://${NODE_IP}:9200
http_ca=${CA_FILE}
kibana_cert=${KIBANA_CERT_DIR}/kibana.crt
# NB pour HOMESOC-13 (Filebeat sur wazuh-manager) : cibler explicitement
# ${NODE_IP}:9200, l'auto-decouverte peut renvoyer l'IP NAT (10.0.2.15)
# qui n'est pas routable depuis les autres VMs.
EOF

echo
echo "===================== VÉRIFICATION ====================="
curl -s --cacert "$CA_FILE" -u "elastic:${ELASTIC_PASSWORD}" \
  "https://localhost:9200/_cluster/health?pretty" | jq '{cluster_name, status, number_of_nodes}'
curl -sk "https://localhost:5601/api/status" | jq -r '"Kibana : " + .status.overall.level + " (version " + .version.number + ")"'
echo "========================================================"
echo
echo "[+] Terminé. Elasticsearch ${ELASTIC_VERSION} + Kibana ${ELASTIC_VERSION} installés."
echo "[+] Kibana        : https://${NODE_IP}:5601  (utilisateur elastic)"
echo "[+] Elasticsearch : https://${NODE_IP}:9200"
echo "[+] Identifiants  : ${CREDS_FILE}"
echo
echo "    Les deux certificats sont auto-signés : le navigateur affichera"
echo "    NET::ERR_CERT_AUTHORITY_INVALID au premier accès, c'est attendu."
