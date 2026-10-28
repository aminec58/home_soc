# Runbook — Cas 1 : Scan réseau / reconnaissance (Suricata NIDS)

| | |
|---|---|
| **Cas** | 1 |
| **Hôte sonde** | victime-ubuntu (`192.168.159.20`, Suricata AF_PACKET sur `ens33`) |
| **Source de log** | Suricata → `/var/log/suricata/eve.json` → agent Wazuh |
| **Règle(s) Wazuh** | 86601 (alerte Suricata, native) |
| **Niveau** | 3 |
| **MITRE ATT&CK** | T1046 — Network Service Discovery (*tag à ajouter via règle custom*) |
| **Requête dashboard** | `rule.groups:suricata` |

## Description

Détection d'une activité de **scan réseau** (découverte d'hôtes, de ports ou de services) par la sonde Suricata. C'est une phase de **reconnaissance**, généralement préalable à une exploitation. Les signatures `ET SCAN` d'Emerging Threats se déclenchent sur les motifs de balayage (nmap SYN, sondes SSH/VNC…).

> Toutes les alertes Suricata remontent actuellement au **niveau 3** (règle native 86601) tant qu'aucune règle custom de rehaussement n'est en place. L'alerte est donc un signal faible : elle sert de déclencheur de triage, pas de preuve d'incident.

## Détection

- **Chaîne :** Suricata (capture `ens33`) → `eve.json` → logcollector de l'agent → manager (décodeur JSON natif) → dashboard.
- Seuls les événements `event_type: alert` produisent une alerte (règle **86601**, niveau 3). Les `flow`, `dns`, `http`, `tls`… sont décodés mais restent au niveau 0 (non indexés).
- **Signatures typiques :** `ET SCAN Suspicious inbound to <port>`, `ET SCAN Potential SSH Scan`, `ET SCAN Potential VNC …`.
- **Dashboard :** Threat Hunting → Events, filtre `rule.groups:suricata`.

## Procédure d'investigation

1. **Identifier origine et cible** — champs `data.src_ip`, `data.dest_ip`, `data.alert.signature`. En direct sur la sonde :
   ```bash
   sudo tail -f /var/log/suricata/eve.json \
     | jq 'select(.event_type=="alert") | {sig: .alert.signature, src: .src_ip, dst: .dest_ip}'
   ```
2. **Qualifier l'ampleur** — nombre d'alertes, fenêtre de temps, ports et hôtes visés. Un balayage large et rapide depuis une seule IP = scan actif en cours.
3. **Qualifier la source** — IP interne ou externe ? Scanner légitime (audit de vulnérabilités planifié, outil de supervision) ou origine inconnue/hostile ?
4. **Chercher la suite** — après la reconnaissance, rechercher des tentatives de connexion ou d'exploitation vers les services découverts : corréler avec les autres détections (p. ex. brute force SSH — cas 2) sur la même `src_ip`.

## Remédiation

- **Si hostile :** bloquer l'IP source au pare-feu ; vérifier et réduire l'exposition des services sur l'hôte visé.
- **Si scanner légitime non déclaré :** documenter la source et, le cas échéant, l'exclure du périmètre d'alerte.
- **Durcissement / prévention :**
  - Déployer une **sonde dédiée** sur port SPAN ou TAP — la sonde actuelle tourne sur la victime et ne voit que son propre trafic.
  - Écrire une **règle custom** (niveau relevé, MITRE **T1046**) pour promouvoir la détection de scan au-dessus du niveau 3.
