# 🛡️ Home SOC — Security Operations Center

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
|
| Kibana | Visualisation & dashboards | 8.19.21 |
| Cassandra | Base de données TheHive | 4.1.12 |
| Elasticsearch (TheHive) | Index interne TheHive & Cortex | 7.17.29 |

---

## Prérequis

- VirtualBox 7.x (ou VMware)
- RAM hôte : 16 Go minimum (32 Go recommandé)
- Stockage : 150 Go libres
- Connexion internet (téléchargement des paquets)

---

## Reproduire le lab en 5 étapes

### 1. Cloner le dépôt

```bash
git clone https://github.com/aminec58/home_soc.git
cd home_soc
```

### 2. Créer la VM Wazuh (Ubuntu Server 22.04)

- RAM : 8 Go · CPU : 2 cœurs · Disque : 50 Go
- Réseau : Adaptateur 1 = NAT · Adaptateur 2 = Host-Only (192.168.56.0/24)
- Installer Ubuntu Server 22.04 LTS

### 3. Installer Wazuh all-in-one

```bash
# Depuis la VM Wazuh, une fois Ubuntu installé
chmod +x install/wazuh.sh
sudo ./install/wazuh.sh
```

Accéder au dashboard : `https://<IP_HOST_ONLY>` (identifiants dans `/root/wazuh-credentials.txt` sur la VM, hors dépôt)

### 4. Déployer les VMs victimes et agents

```bash
# VM Windows : installer l'agent Wazuh via install/agent-windows.ps1
# VM Linux   : installer l'agent Wazuh via install/agent-linux.sh
# VM Windows : installer Sysmon via install/sysmon.ps1
```

### 5. Vérifier la détection

Chaque cas d'attaque est documenté dans `docs/runbooks/`. Rejouer un cas, vérifier l'alerte dans le dashboard Wazuh et ouvrir un ticket dans TheHive.

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
