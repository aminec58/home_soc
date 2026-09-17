#!/usr/bin/env bash
# Installation TheHive 5 + Cortex (noeud unique)
# VM thehive — 192.168.56.30 (host-only) — Ubuntu 22.04, 6 Go RAM / 2 vCPU / 50 Go
#
# Reproduit l'installation validée manuellement le 17/09/2026 :
# Cassandra 4.1.12 (base de données) + Elasticsearch 7.17.29 (index de
# recherche, instance dédiée à cette VM) + TheHive 5.8.0 + Cortex 4.1.0,
# les deux applications tournant côte à côte sur la même VM.
#
# Points d'attention découverts pendant l'installation manuelle :
#  - TheHive 5 et Cortex 4 utilisent Pekko (fork d'Akka) : les clés de
#    configuration sont « pekko.* » et non « akka.* », sinon l'application
#    reste bloquée au démarrage sans écrire la moindre ligne de log.
#  - play.http.secret.key doit faire 256 bits minimum (64 caractères hexa),
#    sinon Play refuse de démarrer (« application secret is too short »).
#  - Les deux applications forment chacune un cluster Pekko d'un seul noeud :
#    il leur faut deux ports distincts (2551 pour TheHive, 2552 pour Cortex).
#  - Le dépôt APT historique deb.thehive-project.org est ABANDONNÉ : les
#    paquets se téléchargent directement, l'URL étant publiée dans un
#    manifeste JSON par StrangeBee.
#  - Dans Cortex, le compte superadmin ne peut PAS lister ni lancer
#    d'analyseurs. La liaison TheHive→Cortex exige un utilisateur créé dans
#    une organisation de travail avec les rôles « read » et « analyze ».
#    Cette partie se fait dans l'interface web (voir l'étape finale).
#
# Usage :
#   sudo ./install/thehive.sh                      # installation complète
#   sudo CORTEX_API_KEY=xxxxx ./install/thehive.sh # + liaison TheHive↔Cortex
#
# Voir docs/architecture.md pour la place de cette VM dans le lab.
set -euo pipefail

THEHIVE_VERSION="5.8.0"      # figé — voir README.md
CORTEX_VERSION="4.1.0"       # figé — voir README.md
CASSANDRA_SERIES="41x"       # dépôt Apache Cassandra 4.1.x
ELASTIC_VERSION="7.17.29"    # 7.x : TheHive 5 n'est pas compatible ES 8.x

NODE_IP="${NODE_IP:-192.168.56.30}"
LAB_SUBNET="192.168.56.0/24"
CASSANDRA_CLUSTER="${CASSANDRA_CLUSTER:-Test Cluster}"  # nom par défaut, conservé
CASSANDRA_HEAP="${CASSANDRA_HEAP:-1G}"
ELASTIC_HEAP="${ELASTIC_HEAP:-1g}"
CREDS_FILE="/root/thehive-credentials.txt"
CORTEX_API_KEY="${CORTEX_API_KEY:-}"

[[ $EUID -eq 0 ]] || { echo "[!] À lancer en root : sudo $0" >&2; exit 1; }

echo "[*] Mise à jour + dépendances"
apt update
apt install -y curl wget gnupg apt-transport-https ca-certificates jq openssl

echo "[*] Installation de Java 11 (requis par TheHive 5 et Cortex 4)"
apt install -y openjdk-11-jre-headless

# ---------------------------------------------------------------- Cassandra --
echo "[*] Ajout du dépôt Apache Cassandra ${CASSANDRA_SERIES}"
curl -fsSL https://downloads.apache.org/cassandra/KEYS \
  | gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
cat > /etc/apt/sources.list.d/cassandra.sources.list <<EOF
deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org ${CASSANDRA_SERIES} main
EOF
apt update

echo "[*] Installation de Cassandra"
apt install -y cassandra

echo "[*] Plafonnement de la heap Cassandra à ${CASSANDRA_HEAP}"
# Par défaut Cassandra se sert ~1/4 de la RAM et grossit avec la machine :
# on fige la valeur pour laisser de la place à Elasticsearch + 2 JVM applicatives.
if ! grep -q '^-Xms' /etc/cassandra/jvm-server.options; then
  cat >> /etc/cassandra/jvm-server.options <<EOF

# Lab Home SOC — heap figée (VM 6 Go partagée avec ES + TheHive + Cortex)
-Xms${CASSANDRA_HEAP}
-Xmx${CASSANDRA_HEAP}
EOF
fi

systemctl enable cassandra
systemctl restart cassandra

echo "[*] Attente de Cassandra (peut prendre 1 à 2 minutes)"
for i in $(seq 1 60); do
  nodetool status 2>/dev/null | grep -q '^UN' && break
  [[ $i -eq 60 ]] && { echo "[!] Cassandra n'a pas démarré. journalctl -u cassandra" >&2; exit 1; }
  sleep 5
done
echo "[+] Cassandra opérationnel (cluster « ${CASSANDRA_CLUSTER} »)"

# ------------------------------------------------------------ Elasticsearch --
echo "[*] Ajout du dépôt Elastic 7.x"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
cat > /etc/apt/sources.list.d/elastic-7.x.list <<EOF
deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main
EOF
apt update

echo "[*] Installation d'Elasticsearch ${ELASTIC_VERSION} (index TheHive + Cortex)"
apt install -y "elasticsearch=${ELASTIC_VERSION}"

# Cette instance ne sert QU'aux index internes de TheHive et Cortex : elle
# n'écoute que sur la boucle locale et n'a rien à voir avec l'Elasticsearch 8.x
# de la VM elastic (192.168.56.20) qui reçoit les alertes Wazuh.
echo "[*] Configuration d'Elasticsearch (noeud unique, écoute locale)"
cat > /etc/elasticsearch/elasticsearch.yml <<EOF
# Lab Home SOC — index interne de TheHive et Cortex (VM thehive)
cluster.name: thehive
node.name: thehive-1
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
EOF

echo "[*] Plafonnement de la heap Elasticsearch à ${ELASTIC_HEAP}"
mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options <<EOF
-Xms${ELASTIC_HEAP}
-Xmx${ELASTIC_HEAP}
EOF

systemctl daemon-reload
systemctl enable elasticsearch
systemctl restart elasticsearch

echo "[*] Attente d'Elasticsearch (9200)"
for i in $(seq 1 60); do
  curl -s "http://127.0.0.1:9200/_cluster/health" >/dev/null 2>&1 && break
  [[ $i -eq 60 ]] && { echo "[!] Elasticsearch n'a pas démarré. journalctl -u elasticsearch" >&2; exit 1; }
  sleep 5
done
echo "[+] Elasticsearch ${ELASTIC_VERSION} opérationnel"

# ------------------------------------------------------------------ TheHive --
echo "[*] Résolution de l'URL du paquet TheHive ${THEHIVE_VERSION}"
# Le dépôt APT est abandonné : StrangeBee publie les URLs dans un manifeste.
THEHIVE_URL="$(curl -s https://thehive.download.strangebee.com/manifest.json \
  | jq -r --arg v "$THEHIVE_VERSION" '.products.thehive.all_versions[$v].deb.url')"
[[ -n "$THEHIVE_URL" && "$THEHIVE_URL" != "null" ]] \
  || { echo "[!] Version TheHive ${THEHIVE_VERSION} introuvable dans le manifeste" >&2; exit 1; }

echo "[*] Téléchargement et installation de TheHive ${THEHIVE_VERSION} (~350 Mo)"
wget -q --show-progress "$THEHIVE_URL" -O "/tmp/thehive_${THEHIVE_VERSION}.deb"
dpkg -i "/tmp/thehive_${THEHIVE_VERSION}.deb" || true
apt install -f -y

echo "[*] Configuration de TheHive"
THEHIVE_SECRET="$(openssl rand -hex 32)"   # 256 bits — exigé par Play
mkdir -p /opt/thp/thehive/files
cat > /etc/thehive/application.conf <<EOF
## Stockage des pièces jointes
storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/files
}

## Base de données (Cassandra) + index de recherche (Elasticsearch local)
db.janusgraph {
  storage {
    backend = cql
    hostname = ["127.0.0.1"]
    cql.cluster-name = "${CASSANDRA_CLUSTER}"
    cql.keyspace = thehive
  }
  index.search {
    backend = elasticsearch
    hostname = ["127.0.0.1"]
    index-name = thehive
  }
}

## Clé secrète de l'application (générée à l'installation)
play.http.secret.key = "${THEHIVE_SECRET}"

## Cluster applicatif Pekko — une seule instance, port 2551
pekko.cluster.seed-nodes = ["pekko://application@127.0.0.1:2551"]
pekko.remote.artery.canonical.hostname = "127.0.0.1"
pekko.remote.artery.canonical.port = 2551
EOF

chown -R thehive:thehive /opt/thp/thehive
chown thehive:thehive /etc/thehive/application.conf

systemctl daemon-reload
systemctl enable thehive
systemctl restart thehive

echo "[*] Attente de TheHive (9000) — premier démarrage : création du schéma, 2 à 3 min"
for i in $(seq 1 60); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9000)" == "200" ]] && break
  [[ $i -eq 60 ]] && { echo "[!] TheHive n'a pas démarré. tail /var/log/thehive/application.log" >&2; exit 1; }
  sleep 10
done
echo "[+] TheHive ${THEHIVE_VERSION} opérationnel"

# ------------------------------------------------------------------- Cortex --
echo "[*] Résolution de l'URL du paquet Cortex ${CORTEX_VERSION}"
CORTEX_URL="$(curl -s https://cortex.download.strangebee.com/manifest.json \
  | jq -r --arg v "$CORTEX_VERSION" '.products.cortex.all_versions[$v].deb.url')"
[[ -n "$CORTEX_URL" && "$CORTEX_URL" != "null" ]] \
  || { echo "[!] Version Cortex ${CORTEX_VERSION} introuvable dans le manifeste" >&2; exit 1; }

echo "[*] Téléchargement et installation de Cortex ${CORTEX_VERSION} (~120 Mo)"
wget -q --show-progress "$CORTEX_URL" -O "/tmp/cortex_${CORTEX_VERSION}.deb"
dpkg -i "/tmp/cortex_${CORTEX_VERSION}.deb" || true
apt install -f -y

echo "[*] Configuration de Cortex"
CORTEX_SECRET="$(openssl rand -hex 32)"
mkdir -p /opt/thp/cortex/files
cat > /etc/cortex/application.conf <<EOF
## Stockage des rapports et artefacts d'analyse
storage {
  provider = localfs
  localfs.location = /opt/thp/cortex/files
}

## Index de recherche (même Elasticsearch que TheHive, index distinct)
search {
  index = cortex
  uri = "http://127.0.0.1:9200"
}

## Clé secrète de l'application (générée à l'installation)
play.http.secret.key = "${CORTEX_SECRET}"

## Cluster applicatif Pekko — port 2552 (2551 est pris par TheHive)
pekko.cluster.seed-nodes = ["pekko://application@127.0.0.1:2552"]
pekko.remote.artery.canonical.hostname = "127.0.0.1"
pekko.remote.artery.canonical.port = 2552
EOF

chown -R cortex:cortex /opt/thp/cortex
chown cortex:cortex /etc/cortex/application.conf

systemctl daemon-reload
systemctl enable cortex
systemctl restart cortex

echo "[*] Attente de Cortex (9001)"
for i in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:9001 && break
  [[ $i -eq 30 ]] && { echo "[!] Cortex n'a pas démarré. tail /var/log/cortex/application.log" >&2; exit 1; }
  sleep 10
done
echo "[+] Cortex ${CORTEX_VERSION} opérationnel"

# ------------------------------------------------- Liaison TheHive ↔ Cortex --
if [[ -n "$CORTEX_API_KEY" ]]; then
  echo "[*] Configuration du connecteur Cortex dans TheHive"
  if ! grep -q '^cortex {' /etc/thehive/application.conf; then
    cat >> /etc/thehive/application.conf <<EOF

## Connecteur Cortex (même VM, port 9001)
## La clé doit appartenir à un utilisateur d'organisation ayant les rôles
## « read » et « analyze » — un compte superadmin ne peut pas lister les
## analyseurs (erreur « List Cortex analyzers fails »).
cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://127.0.0.1:9001"
      auth {
        type = "bearer"
        key = "${CORTEX_API_KEY}"
      }
    }
  ]
}
EOF
    systemctl restart thehive
    echo "[+] Connecteur Cortex configuré, TheHive redémarré"
  else
    echo "[=] Un connecteur Cortex est déjà présent, fichier laissé tel quel"
  fi
fi

# ----------------------------------------------------------- Pare-feu + fin --
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  echo "[*] Ouverture des ports 9000 et 9001 depuis ${LAB_SUBNET}"
  ufw allow from "$LAB_SUBNET" to any port 9000 proto tcp
  ufw allow from "$LAB_SUBNET" to any port 9001 proto tcp
fi

umask 077
cat > "$CREDS_FILE" <<EOF
# Lab Home SOC — VM thehive (${NODE_IP})
# Généré le $(date '+%F %T') par install/thehive.sh
# NE JAMAIS COMMITTER CE FICHIER (voir .gitignore : *password*, *secret*)
thehive_version=${THEHIVE_VERSION}
thehive_url=http://${NODE_IP}:9000
thehive_secret_key=${THEHIVE_SECRET}
cortex_version=${CORTEX_VERSION}
cortex_url=http://${NODE_IP}:9001
cortex_secret_key=${CORTEX_SECRET}
cortex_api_key=${CORTEX_API_KEY:-<à générer, voir ci-dessous>}
cassandra_cluster=${CASSANDRA_CLUSTER}
elasticsearch_url=http://127.0.0.1:9200 (local, index thehive + cortex)
EOF

echo
echo "===================== VÉRIFICATION ====================="
nodetool status | grep '^UN' | awk '{print "Cassandra     : " $1 " " $2 " (" $3 ")"}'
curl -s "http://127.0.0.1:9200" | jq -r '"Elasticsearch : " + .version.number + " (cluster " + .cluster_name + ")"'
echo "TheHive       : HTTP $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9000) sur le port 9000"
echo "Cortex        : HTTP $(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9001) sur le port 9001"
echo "========================================================"
echo
echo "[+] Terminé. Identifiants et clés : ${CREDS_FILE}"
echo
echo "    ÉTAPES MANUELLES RESTANTES (interface web, une seule fois) :"
echo
echo "    1. Cortex — http://${NODE_IP}:9001"
echo "       a. « Update Database », puis créer le compte superadmin"
echo "       b. Organizations → créer l'organisation « home-soc »"
echo "       c. Dans home-soc → Users → créer un utilisateur avec les rôles"
echo "          « read » et « analyze » (PAS superadmin), puis Create API Key"
echo "       d. Relancer ce script avec la clé pour câbler le connecteur :"
echo "             sudo CORTEX_API_KEY=<clé> $0"
echo
echo "    2. TheHive — http://${NODE_IP}:9000"
echo "       Se connecter avec admin@thehive.local / secret, puis changer"
echo "       immédiatement ce mot de passe par défaut."
echo
