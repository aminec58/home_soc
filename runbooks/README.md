# Runbooks — procédures de réponse par cas

Un runbook par cas d'attaque : ce qui déclenche l'alerte, comment l'investiguer, comment y remédier. La numérotation suit le tableau [`docs/detection-cases.md`](../docs/detection-cases.md).

| Cas | Runbook | Règle(s) clé(s) | Lab |
|-----|---------|-----------------|-----|
| 1 | [Brute force SSH](cas-01-bruteforce-ssh.md) | 100120 · 100110 · 100117 | VMware |
| 2 | [Brute force RDP/SMB](cas-02-bruteforce-rdp-smb.md) | 100111 | VMware |
| 3a | [Scan réseau nmap](cas-03a-scan-nmap.md) | 86601 | VirtualBox |
| 3b | [Scan réseau — sonde Suricata](cas-03b-scan-suricata.md) | 86601 | VMware |
| 4 | [Création de compte / ajout admin](cas-04-user-admin-windows.md) | 100113 · 100118 | VMware |
| 5 | [PowerShell suspect](cas-05-powershell-suspect.md) | 100114 · 100115 | VMware |
| 6 | [Mimikatz / accès LSASS](cas-06-mimikatz-lsass.md) | 100116 | VMware |
| 7 | [Persistance Run / tâche planifiée](cas-07-persistance-run-tache.md) | 100100 | VirtualBox |
| 8 | [Web shell](cas-08-web-shell.md) | 554 + règles web natives | VirtualBox |
| 9 | [Exfiltration DNS](cas-09-exfiltration-dns.md) | 100200 · 100201 | VirtualBox |
| 10 | [FIM fichier sensible](cas-10-fim-fichier-sensible.md) | 550 / 553 / 554 | VirtualBox |

« VMware » = lab `192.168.159.0/24`, « VirtualBox » = lab `192.168.56.0/24` (voir [`docs/architecture.md`](../docs/architecture.md#4-les-deux-labs)).

Les guides de construction des machines (DC01, victime-ubuntu, Kali) sont dans [`docs/vms/`](../docs/vms/).
