# Home SOC — Détections & cas d'usage

Documentation de la partie détection du projet **Home SOC** (SOC maison monté à des fins d'apprentissage et pour le portfolio).
Chaîne de collecte : agents **Wazuh** → manager → **Filebeat** → **Elasticsearch / Kibana**, avec **Suricata** en IDS réseau sur la victime.

---

## 1. Architecture

| VM | Rôle | IP (host-only) | Composants |
|----|------|----------------|------------|
| **Wazuh** | Manager SIEM | `192.168.56.10` | wazuh-manager + indexer + dashboard, **Filebeat 8** (envoi vers Elastic) |
| **Elastic** | Stockage / visualisation | `192.168.56.20` | Elasticsearch 8.19.21 + Kibana (TLS) |
| **DC01** | Victime Windows | `192.168.56.106` | Windows + **Sysmon** + agent Wazuh (001) |
| **victime-ubuntu** | Victime Linux | `192.168.56.110` | Ubuntu 24.04 + **Apache** + **Suricata** + agent Wazuh (002) |
| **Kali** | Attaquant | `192.168.56.109` | Outils offensifs (nmap, dig, curl) |
| **TheHive / Cortex** | Réponse à incident | `192.168.56.30` | TheHive 5.8 + Cortex 4.1 |

Réseau : VirtualBox **host-only** `192.168.56.0/24` (+ NAT pour l'accès Internet des VMs).

### Pipeline de données

```
[DC01]  agent Wazuh ─┐
[Ubuntu] agent Wazuh ─┤→ wazuh-manager (192.168.56.10) ─→ alerts.json
[Suricata] eve.json ─┘                                         │
                                                     Filebeat 8 (filebeat-es)
                                                               │
                                                     Elasticsearch (192.168.56.20)
                                                               │
                                                          Kibana (dashboards)
```

> Remarque : Filebeat 7.10 (livré avec Wazuh) est incompatible avec Elasticsearch 8.
> On a donc déployé un **second Filebeat 8.19** dédié (`filebeat-es`) pointant sur le cluster Elastic 8.

---

## 2. Dashboards Kibana

Quatre dashboards construits sous Kibana Lens, data view `wazuh-alerts` :

| Dashboard | Contenu |
|-----------|---------|
| **Authentification** | Connexions / échecs d'authentification |
| **Processus** | Événements processus & Sysmon (par règle, par machine) |
| **Réseau** | Alertes IDS Suricata : évolution, IP sources (`data.src_ip`), règles déclenchées |
| **FIM** | Intégrité fichiers : chronologie, `syscheck.path`, `syscheck.event` (added/modified/deleted) |

Export : `elastic/dashboards/homesoc-dashboards.ndjson`
Import : Kibana → Stack Management → Saved objects → Import.
*(Spécifique à Kibana 8.x — ne s'importe pas dans le dashboard Wazuh natif, qui est basé sur OpenSearch.)*

---

## 3. Cas d'attaque & détections

Cas **1, 2, 4** réalisés par Amine ; cas **3, 7, 8, 9, 10** réalisés par Adem (détaillés ci-dessous).

### Cas 10 — FIM (modification de fichier sensible)
- **Cible :** DC01 (`C:\soc-test`) / Ubuntu (`/var/www`)
- **Attaque :** création / modification / suppression d'un fichier dans un dossier surveillé.
- **Détection :** FIM Wazuh (`syscheck`) en temps réel.
  - Règles natives `554` (ajout), `550` (modif), `553` (suppression), groupe `syscheck`.
- **Config agent :**
  ```xml
  <directories realtime="yes" check_all="yes" report_changes="yes">C:\soc-test</directories>
  ```
- **MITRE :** T1565 (Data Manipulation) / surveillance d'intégrité.

### Cas 7 — Persistance (clé Run + tâche planifiée)
- **Cible :** DC01 (Windows)
- **Attaque :** création d'une clé de registre `HKLM\...\CurrentVersion\Run` et d'une tâche planifiée.
- **Détection :** Sysmon **event 13** (RegistryEvent).
  - Tâche planifiée : détectée nativement via son empreinte registre (`...\Schedule\TaskCache\Tree\...`).
  - Clé Run : **non détectée initialement** → deux correctifs (voir §4).
- **MITRE :** T1547.001 (Registry Run Keys / Startup Folder).

### Cas 3 — Scan réseau (nmap)
- **Cible :** victime-ubuntu (`192.168.56.110`), depuis Kali (`192.168.56.109`)
- **Attaque :** `nmap -A -T4 192.168.56.110`
- **Détection :** **Suricata** (IDS) sniffant `enp0s8`, logs `eve.json` lus par l'agent Wazuh.
  - Alertes groupe `ids,suricata`.
- **MITRE :** T1046 (Network Service Discovery).

### Cas 8 — Web shell
- **Cible :** victime-ubuntu (Apache, `/var/www/html`)
- **Attaque :** dépôt d'un fichier `.php` dans le webroot + requêtes web malveillantes (SQLi / XSS / traversée de répertoire).
  - *(En labo, fichier PHP inoffensif : seule compte la détection de l'apparition du fichier et des accès.)*
- **Détection :**
  1. **FIM** : nouveau fichier dans `/var/www` (`syscheck_entry_added`).
  2. **Logs d'accès Apache** : règles web natives (groupes `web,accesslog,attack`) sur les motifs d'attaque.
- **Config agent :**
  ```xml
  <directories realtime="yes" check_all="yes" report_changes="yes">/var/www</directories>
  <localfile><log_format>apache</log_format><location>/var/log/apache2/access.log</location></localfile>
  ```
- **MITRE :** T1505.003 (Web Shell).

### Cas 9 — Exfiltration DNS
- **Cible / source :** requêtes DNS depuis Kali vers `192.168.56.110`
- **Attaque :** rafale de requêtes DNS vers des sous-domaines aléatoires longs (simulation de tunneling/exfil).
  ```bash
  for i in $(seq 1 60); do dig +tries=1 +time=1 $(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 25).exfil.lab @192.168.56.110 >/dev/null; done
  ```
- **Détection :** Suricata logge les requêtes DNS (`eve.json`), **2 règles personnalisées** (voir §4).
- **MITRE :** T1048.003 (Exfiltration Over Alternative Protocol: DNS).

---

## 4. Règles de détection personnalisées

Fichier : `/var/ossec/etc/rules/local_rules.xml` (manager Wazuh).

### 100100 — Persistance par clé Run (Cas 7)
Problème identifié : la config Sysmon par défaut ne surveillait pas les clés `Run` (angle mort), et la règle Wazuh de base de l'event 13 (`61615`) est de niveau 0 (pas d'alerte).
Correctifs :
1. Config Sysmon enrichie (SwiftOnSecurity) pour surveiller les clés `Run`.
2. Règle Wazuh dédiée qui alerte sur ces modifications :

```xml
<group name="sysmon,persistence,">
  <rule id="100100" level="10">
    <if_sid>61615</if_sid>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)\\CurrentVersion\\Run</field>
    <description>Persistance : cle de demarrage Run ajoutee ($(win.eventdata.targetObject))</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>
</group>
```
> Piste d'amélioration : affiner pour réduire les faux positifs (ex. ignorer les écritures légitimes par `svchost.exe`/`System32`).

### 100200 & 100201 — Exfiltration DNS (Cas 9)
Les événements Suricata `dns` ne génèrent pas d'alerte par défaut (règle de base `86603`, niveau 0). Deux règles maison :

```xml
<group name="ids,suricata,exfiltration,">
  <!-- Signature : sous-domaine anormalement long -->
  <rule id="100200" level="10">
    <if_sid>86603</if_sid>
    <field name="dns.rrname" type="pcre2">[a-zA-Z0-9]{20,}\.</field>
    <description>Exfiltration DNS possible : sous-domaine anormalement long ($(dns.rrname))</description>
    <mitre><id>T1048.003</id></mitre>
  </rule>

  <!-- Volume : trop de requetes DNS en peu de temps -->
  <rule id="100201" level="12" frequency="20" timeframe="30">
    <if_matched_sid>86603</if_matched_sid>
    <description>Exfiltration DNS possible : volume anormal de requetes DNS (plus de 20 en 30s)</description>
    <mitre><id>T1048.003</id></mitre>
  </rule>
</group>
```

---

## 5. Notes d'exploitation

- **Au démarrage de la VM Wazuh**, le manager ne se relance pas toujours entièrement → exécuter :
  ```bash
  sudo systemctl restart wazuh-manager
  ```
  puis vérifier : `sudo /var/ossec/bin/wazuh-control status` (wazuh-db, analysisd, remoted doivent tourner).
- **Agents** : vérifier la connexion avec `sudo /var/ossec/bin/agent_control -l` (000 manager, 001 DC01, 002 victime-ubuntu en *Active*).
- **Budget RAM (hôte 16 Go)** : travailler par phases, une seule victime allumée à la fois (Wazuh 4 + Elastic 4 + victime + Kali).
- **Pièges rencontrés & résolus :**
  - Agents pointant vers l'ancien manager VMware `192.168.159.141` → corriger `<address>` vers `192.168.56.10`.
  - IP des VMs qui repassaient en DHCP → cloud-init désactivé + netplan statique par adresse MAC.
  - Suricata : interface à régler sur `enp0s8` (host-only) dans `/etc/suricata/suricata.yaml`.

---

## 6. Compétences SOC démontrées

- Déploiement d'une chaîne SIEM complète (Wazuh + Elastic/Kibana) et d'un IDS réseau (Suricata).
- Construction de dashboards de détection (Lens).
- **Écriture de règles de détection personnalisées** (persistance registre, exfiltration DNS) avec mapping MITRE ATT&CK.
- **Identification et correction d'un angle mort** de détection (Sysmon / clés Run).
- Simulation d'attaques et validation de bout en bout des détections.
