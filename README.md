#  Home SOC — Security Operations Center

> Projet étudiant de cybersécurité — IUT Auxerre, Réseaux & Télécommunications  
> Équipe : Amine Cherif · Adem Romdhane

---

## Objectif

Construire un SOC (Security Operations Center) complet en environnement virtualisé, capable de détecter, alerter et investiguer sur 10 scénarios d'attaques réels. Le projet couvre l'ensemble de la chaîne : collecte de logs, corrélation, détection, gestion d'incidents et réponse.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Réseau Host-Only                   │
│                  192.168.56.0/24                     │
│                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────┐ │
│  │  VM Wazuh    │   │  VM Windows  │   │ VM Linux │ │
│  │  (Ubuntu     │   │  (Victime)   │   │ (Victime)│ │
│  │  22.04)      │   │  + Sysmon    │   │          │ │
│  │              │   │              │   │          │ │
│  │  - Wazuh     │◄──│  Agent Wazuh │   │ Agent    │ │
│  │  - Elastic   │◄──┤              │◄──│ Wazuh    │ │
│  │  - Kibana    │   └──────────────┘   └──────────┘ │
│  │  - TheHive   │                                   │
│  │  - Cortex    │   ┌──────────────┐                │
│  │  - Suricata  │◄──│   VM Kali    │                │
│  └──────────────┘   │  (Attaquant) │                │
│                     └──────────────┘                │
└─────────────────────────────────────────────────────┘
```

**Stack SOC :**

| Composant | Rôle | Version |
|-----------|------|---------|
| Wazuh Manager | SIEM / collecte agents | 4.x |
| Wazuh Indexer | Stockage (OpenSearch) | 4.x |
| Wazuh Dashboard | Visualisation | 4.x |
| Suricata | IDS réseau | 7.x |
| TheHive | Gestion d'incidents | 5.8.0 |
| Cortex | Analyseurs automatiques | 4.1.0 |
| Elasticsearch | Indexation & stockage des logs Wazuh | 8.19.21 |
| Kibana | Visualisation & dashboards | 8.19.21 |
| Cassandra | Base de données TheHive | 4.1.12 |
| Elasticsearch (TheHive) | Index interne TheHive & Cortex | 7.17.29 |
| nginx | Terminaison TLS TheHive & Cortex | 1.18 |

**Accès aux interfaces :**

| Service | URL | VM |
|---------|-----|----|
| Wazuh Dashboard | `https://192.168.56.10` | wazuh |
| Kibana | `https://192.168.56.20:5601` | elastic |
| Elasticsearch | `https://192.168.56.20:9200` | elastic |
| TheHive | `https://192.168.56.30:9443` | thehive |
| Cortex | `https://192.168.56.30:9444` | thehive |

Tous les certificats sont auto-signés : le navigateur affiche `NET::ERR_CERT_AUTHORITY_INVALID` au premier accès, c'est attendu.

---

## Prérequis

- VirtualBox 7.x (ou VMware)
- RAM hôte : 16 Go minimum (32 Go recommandé)
- Stockage : 150 Go libres
- Connexion internet (téléchargement des paquets)

> **Windows 11 :** si VirtualBox plante ou si les VMs se bloquent au démarrage sur `Loading essential drivers`, c'est la cohabitation avec Hyper-V. Vérifier avec `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning` : si la commande renvoie autre chose que `0`, désactiver l'intégrité de la mémoire dans Sécurité Windows → Sécurité de l'appareil → Isolation du noyau.

---

## Reproduire le lab en 5 étapes

### 1. Cloner le dépôt

```bash
git clone https://github.com/aminec58/home_soc.git
cd home_soc
```

### 2. Créer les VMs (Ubuntu Server 22.04)

- Réseau : Adaptateur 1 = NAT · Adaptateur 2 = Host-Only (192.168.56.0/24)
- Pendant l'installation, penser à **redimensionner `ubuntu-lv` au maximum** : le partitionnement LVM guidé ne alloue que la moitié du disque par défaut

**Fixer l'IP host-only** (sinon la VM reprend une adresse DHCP à chaque redémarrage et les certificats TLS ne correspondent plus). Ubuntu régénère `/etc/netplan/50-cloud-init.yaml` au démarrage, il faut donc neutraliser cloud-init et écrire la configuration dans un fichier séparé :

```bash
echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg

sudo tee /etc/netplan/60-static-hostonly.yaml > /dev/null <<'EOF'
network:
  version: 2
  ethernets:
    enp0s8:
      dhcp4: false
      addresses: [192.168.56.XX/24]
EOF

sudo chmod 600 /etc/netplan/60-static-hostonly.yaml
sudo netplan apply
```

Pas de passerelle sur cette interface : l'accès internet passe par l'adaptateur NAT.

| VM | IP | RAM | vCPU | Disque |
|----|----|-----|------|--------|
| wazuh | 192.168.56.10 | 8 Go | 2 | 50 Go |
| elastic | 192.168.56.20 | 4 Go | 2 | 40 Go |
| thehive | 192.168.56.30 | 6 Go | 2 | 50 Go |

### 3. Installer Wazuh all-in-one

```bash
# Depuis la VM Wazuh, une fois Ubuntu installé
chmod +x install/wazuh.sh
sudo ./install/wazuh.sh
```

Accéder au dashboard : `https://<IP_HOST_ONLY>` (identifiants dans `/root/wazuh-credentials.txt` sur la VM, hors dépôt)

### 4. Installer Elasticsearch/Kibana puis TheHive/Cortex

```bash
# Depuis la VM elastic
sudo ./install/elastic.sh

# Depuis la VM thehive
sudo ./install/thehive.sh
# puis, après avoir créé la clé API dans Cortex :
sudo CORTEX_API_KEY=<clé> ./install/thehive.sh
```

### 5. Déployer les VMs victimes et vérifier la détection

```bash
# VM Windows : installer l'agent Wazuh via install/agent-windows.ps1
# VM Linux   : installer l'agent Wazuh via install/agent-linux.sh
# VM Windows : installer Sysmon via install/sysmon.ps1
```

Chaque cas d'attaque est documenté dans `docs/runbooks/`. Rejouer un cas, vérifier l'alerte dans le dashboard Wazuh et ouvrir un ticket dans TheHive.

---

## Sécurité du lab

**Secrets.** Aucun mot de passe ni clé n'est versionné. Les scripts d'installation génèrent les secrets et les écrivent dans `/root/<service>-credentials.txt` sur la VM concernée, hors du dépôt. Le fichier `.env.example` documente quels secrets existent et où les retrouver, sans jamais contenir de valeur réelle.

**Chiffrement.** Toutes les interfaces web sont en HTTPS avec des certificats auto-signés portant l'IP de la VM dans leur `subjectAltName` — les navigateurs modernes ignorent le champ `CN` et rejettent un certificat qui n'a que celui-ci. Elasticsearch génère les siens à l'installation, Kibana chiffre nativement, tandis que TheHive 5 et Cortex 4 n'ont pas de HTTPS intégré : la documentation StrangeBee ne prévoit qu'un reverse proxy, d'où nginx sur la VM thehive.

**Filtrage.** TheHive et Cortex continuent d'écouter en clair sur 9000 et 9001 pour que nginx puisse les joindre en local. Sans filtrage, on pourrait donc contourner le HTTPS en s'y connectant directement : ufw n'autorise que 22, 9443 et 9444 depuis le sous-réseau du lab, et refuse tout le reste. Le trafic passant par `127.0.0.1` n'est pas filtré, ce qui laisse nginx travailler.

---

## Cas d'attaques simulés

| # | Nom | ATT&CK | Porteur |
|---|-----|--------|---------|
| 1 | Brute force SSH | T1110.001 | Amine |
| 2 | Brute force RDP/SMB | T1110.001 | Amine |
| 3 | Scan nmap | T1046 | Adem |
| 4 | Création user / ajout admin | T1136 · T1098 | Amine |
| 5 | PowerShell suspect | T1059.001 | Amine |
| 6 | Mimikatz / accès LSASS | T1003.001 | Amine |
| 7 | Persistance Run / tâche planifiée | T1547.001 · T1053.005 | Adem |
| 8 | Web shell | T1505.003 | Adem |
| 9 | Exfiltration DNS | T1071.004 · T1048 | Adem |
| 10 | FIM fichier sensible | T1565.001 | Adem |

Suivi complet : [`docs/detection-cases.md`](docs/detection-cases.md)

---

## Structure du dépôt

```
home_soc/
├── README.md
├── .env.example                 # Secrets attendus (jamais de valeur réelle)
├── docs/
│   ├── architecture.md          # Schéma détaillé de l'archi
│   ├── detection-cases.md       # Tableau des 10 cas
│   └── runbooks/                # Runbook par cas d'attaque
│       ├── cas-01-brute-force-ssh.md
│       ├── ...
│       └── cas-10-fim.md
└── install/
    ├── wazuh.sh                 # Script install Wazuh all-in-one
    ├── agent-linux.sh           # Script install agent Linux
    ├── agent-windows.ps1        # Script install agent Windows
    ├── sysmon.ps1               # Script install + config Sysmon
    ├── elastic.sh               # Script install Elasticsearch + Kibana
    └── thehive.sh               # Script install TheHive + Cortex
```

---

## Auteurs

- **Amine Cherif** — [@aminec58](https://github.com/aminec58)
- **Adem Romdhane** — IUT Auxerre, RT3
