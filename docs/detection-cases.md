# detection-cases.md — Tableau de suivi des cas d'attaque

> Projet : **Home SOC** | Mise à jour : 2026-09-08  
> Stack : Wazuh · Suricata · ELK/Kibana · Sysmon · TheHive · Cortex

---

| ID | Nom du cas | Technique ATT&CK | Source de log | Porteur | Statut |
|----|-----------|-----------------|---------------|---------|--------|
| Cas 1 | Brute force SSH | T1110.001 – Brute Force: Password Guessing | Wazuh (règles 5710 / 5716) | Amine | 🔲 Backlog |
| Cas 2 | Brute force RDP/SMB | T1110.001 – Brute Force | Windows Security Event 4625 | Amine | 🔲 Backlog |
| Cas 3 | Scan nmap | T1046 – Network Service Discovery | Suricata / Wazuh | Adem | 🔲 Backlog |
| Cas 4 | Création user / ajout admin | T1136 – Create Account · T1098 – Account Manipulation | Windows Security Events 4720 + 4732 | Amine | 🔲 Backlog |
| Cas 5 | PowerShell suspect | T1059.001 – Command and Scripting Interpreter: PowerShell | Sysmon Event 1 · Windows Security 4104 (Script Block Logging) | Amine | 🔲 Backlog |
| Cas 6 | Mimikatz / accès LSASS | T1003.001 – OS Credential Dumping: LSASS Memory | Sysmon Event 10 (ProcessAccess lsass.exe) | Amine | 🔲 Backlog |
| Cas 7 | Persistance Run / tâche planifiée | T1547.001 – Registry Run Keys · T1053.005 – Scheduled Task | Sysmon Event 13 · Windows Security Event 4698 | Adem | 🔲 Backlog |
| Cas 8 | Web shell | T1505.003 – Server Software Component: Web Shell | Wazuh syscheck (/var/www) · Apache access logs | Adem | 🔲 Backlog |
| Cas 9 | Exfiltration DNS | T1071.004 – Application Layer Protocol: DNS · T1048 – Exfiltration Over Alternative Protocol | Sysmon Event 22 · Suricata | Adem | 🔲 Backlog |
| Cas 10 | FIM fichier sensible | T1565.001 – Stored Data Manipulation | Wazuh syscheck (/etc/passwd, /etc/shadow, confs) | Adem | 🔲 Backlog |

---

## Légende des statuts

| Emoji | Statut |
|-------|--------|
| 🔲 | Backlog — pas encore démarré |
| 🔄 | In Progress — en cours |
| ✅ | Done — terminé et validé |
| ❌ | Bloqué |

---

## Répartition par porteur

| Porteur | Cas |
|---------|-----|
| **Amine** | Cas 1, 2, 4, 5, 6 |
| **Adem** | Cas 3, 7, 8, 9, 10 |

---

## Notes techniques

### VM impliquées
- **Kali** (attaquant) → Cas 1, 3, 9
- **VM Linux** (victime) → Cas 1, 3, 8, 9, 10
- **VM Windows + Sysmon** (victime) → Cas 2, 4, 5, 6, 7

### Outils d'attaque utilisés
| Cas | Outil |
|-----|-------|
| Cas 1 | hydra |
| Cas 2 | hydra / crackmapexec |
| Cas 3 | nmap |
| Cas 5 | PowerShell natif (-enc / DownloadString) |
| Cas 6 | mimikatz |
| Cas 7 | reg.exe / schtasks.exe |
| Cas 8 | curl / upload PHP |
| Cas 9 | iodine / dnscat2 |
| Cas 10 | nano / echo (modification manuelle) |
