# Cas de détection — tableau de synthèse

> Projet : **Home SOC** · Stack : Wazuh 4.9.2 · Sysmon · Suricata · Elasticsearch/Kibana 8.19 · TheHive 5 · Cortex 4
> Mise à jour : 10/11/2026 — **10 cas validés**, plus la corrélation et la réponse automatique.

## Cas d'attaque

| # | Cas | ATT&CK | Source de log | Règle(s) Wazuh | Niveau | Porteur | Doc | Runbook | Démo |
|---|-----|--------|---------------|----------------|--------|---------|-----|---------|------|
| 1 | Brute force SSH | T1110 | `auth.log` (sshd) | 100110 · **100120** | 12 | Amine | [doc](bruteforce-ssh.md) | [cas 1](../runbooks/cas-01-bruteforce-ssh.md) | 02 |
| 2 | Brute force RDP/SMB | T1110 | Security 4625 | 100111 | 12 | Amine | [doc](bruteforce-rdp-smb-wazuh.md) | [cas 2](../runbooks/cas-02-bruteforce-rdp-smb.md) | — |
| 3 | Scan réseau nmap | T1046 | Suricata `eve.json` | 86601 (natif) | 3 | Adem · Amine | [doc](detections.md#cas-3--scan-réseau-nmap) · [sonde](../install/suricata.md) | [3a](../runbooks/cas-03a-scan-nmap.md) · [3b](../runbooks/cas-03b-scan-suricata.md) | 01 · 09 |
| 4 | Création de compte / ajout admin | T1136 · T1098 | Security 4720 / 4732 | 60109 (natif) · 100113 | 8 · 12 | Amine | [doc](user-admin-wazuh.md) | [cas 4](../runbooks/cas-04-user-admin-windows.md) | — |
| 5 | PowerShell suspect | T1059.001 · T1027 · T1105 | Sysmon EID 1 · PowerShell 4104 | 100114 · 100115 | 12 | Amine | [doc](powershell-suspect-wazuh.md) | [cas 5](../runbooks/cas-05-powershell-suspect.md) | 05 |
| 6 | Mimikatz / accès LSASS | T1003.001 | Sysmon EID 10 | 100116 | 14 | Amine | [doc](mimikatz-lsass-wazuh.md) | [cas 6](../runbooks/cas-06-mimikatz-lsass.md) | 06 |
| 7 | Persistance clé Run / tâche planifiée | T1547.001 · T1053.005 | Sysmon EID 13 | 100100 | 10 | Adem | [doc](detections.md#cas-7--persistance-clé-run--tâche-planifiée) | [cas 7](../runbooks/cas-07-persistance-run-tache.md) | 10 |
| 8 | Web shell | T1505.003 | FIM `/var/www` · logs Apache | 554 (natif) · règles web natives | natif | Adem | [doc](detections.md#cas-8--web-shell) | [cas 8](../runbooks/cas-08-web-shell.md) | 11 |
| 9 | Exfiltration DNS | T1048.003 | Suricata (événements `dns`) | 100200 · 100201 | 10 · 12 | Adem | [doc](detections.md#cas-9--exfiltration-dns) | [cas 9](../runbooks/cas-09-exfiltration-dns.md) | 12 |
| 10 | FIM fichier sensible | T1565.001 | Wazuh syscheck | 550 / 553 / 554 (natifs) | natif | Adem | [doc](detections.md#cas-10--fim-modification-de-fichier-sensible) | [cas 10](../runbooks/cas-10-fim-fichier-sensible.md) | 13 |

## Au-delà de la détection unitaire

| Capacité | Règle(s) | Niveau | Porteur | Doc | Démo |
|----------|----------|--------|---------|-----|------|
| Corrélation brute force SSH → connexion réussie | 100117 | 14 | Amine | [doc](correlation-wazuh.md) | 03 |
| Corrélation création de compte → ajout admin | 100118 | 14 | Amine | [doc](correlation-wazuh.md) | — |
| Méta-règle kill chain (3 étapes en 15 min) | 100119 | 15 | Amine | [doc](correlation-wazuh.md) | 07 |
| Active Response — blocage de l'IP (`firewall-drop`) | 100110 · 100120 · 5712 | — | Amine | [doc](active-response-wazuh.md) | 04 |
| Export vers Elasticsearch / dashboards Kibana | — | — | Amine · Adem | [doc](filebeat-elastic.md) · [dashboards](detections.md#2-dashboards-kibana) | — |
| Vue de synthèse (dashboard Threat Hunting Wazuh) | — | — | Amine | — | 08 |
| Escalade vers TheHive + enrichissement Cortex | niveau ≥ 10 | — | Adem | [doc](thehive-integration.md) | 14 |

La colonne « Démo » renvoie à la numérotation de la section « Démos vidéo » du [README](../README.md#démos-vidéo).

## Machines impliquées

| Machine | Cas |
|---------|-----|
| Kali (attaquant) | 1, 2, 3, 9 |
| victime-ubuntu | 1, 3, 8, 9, 10 |
| DC01 (Windows Server + Sysmon) | 2, 4, 5, 6, 7, 10 |

## Outils d'attaque

| Cas | Outil |
|-----|-------|
| 1 | hydra |
| 2 | Metasploit `auxiliary/scanner/smb/smb_login` |
| 3 | nmap |
| 4 | `net user` / `net localgroup` |
| 5 | PowerShell natif (`-EncodedCommand`, `DownloadString`) |
| 6 | mimikatz |
| 7 | `reg.exe` / `schtasks.exe` |
| 8 | curl + dépôt d'un fichier PHP inoffensif |
| 9 | `dig` en rafale vers des sous-domaines aléatoires |
| 10 | création / modification / suppression manuelle |
