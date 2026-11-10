# Intégration Wazuh → TheHive (+ Cortex)

**Statut :** intégration en service sur le lab d'Adem (démo vidéo 14). Cette page documente la mise en place côté manager Wazuh ; l'installation de TheHive et de Cortex reste manuelle (voir § 5).

> **À valider par Adem :** la procédure ci-dessous reconstitue la configuration à partir des fichiers du dépôt (`thehive/integration-wazuh.py`, seuil `<level>10</level>` cité dans les runbooks). Les valeurs réelles de son lab (URL, nom de l'intégration, version de thehive4py) sont à confirmer.

```
alerte Wazuh (niveau ≥ 10) → wazuh-integratord → custom-w2thive (script Python)
   → API TheHive : alerte « wazuh_alert » + observables (IP, URL, domaines)
   → analyste : alerte → cas → analyseurs Cortex (AbuseIPDB, VirusTotal…)
```

## 1. Ce que fait le script

[`thehive/integration-wazuh.py`](../thehive/integration-wazuh.py) reçoit le fichier JSON de l'alerte Wazuh, puis :

- met toute l'alerte en forme de tableaux Markdown dans la description de l'alerte TheHive ;
- extrait les **observables** par expression régulière : adresses IP, URL et domaines ;
- étiquette l'alerte : `wazuh`, `rule=<id>`, `agent_name=…`, `agent_id=…`, `agent_ip=…` ;
- n'envoie que les alertes au-dessus du seuil : niveau ≥ 10 (`lvl_threshold`), et pour les alertes Suricata pures (groupes `ids,suricata`), sévérité Suricata ≤ 3.

Le filtrage principal est fait **avant** l'appel du script, par `<level>10</level>` dans le bloc `<integration>` : les alertes de niveau inférieur n'atteignent jamais le script.

## 2. Installation sur le manager

```bash
# dépendance dans l'interpréteur Python embarqué de Wazuh
# (thehive4py 1.x : API historique, encore acceptée par TheHive 5)
sudo /var/ossec/framework/python/bin/pip3 install "thehive4py<2"

# script + lanceur
sudo cp thehive/integration-wazuh.py /var/ossec/integrations/custom-w2thive.py
sudo cp thehive/custom-w2thive        /var/ossec/integrations/custom-w2thive
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive*
sudo chmod 750        /var/ossec/integrations/custom-w2thive*
```

## 3. Configuration du manager

Ajouter le bloc versionné dans [`wazuh/manager/integration-thehive.xml`](../wazuh/manager/integration-thehive.xml) à `/var/ossec/etc/ossec.conf`, en remplaçant l'URL et la clé API :

```xml
<integration>
  <name>custom-w2thive</name>
  <hook_url>https://IP_THEHIVE:9443</hook_url>
  <api_key>CLE_API_THEHIVE</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/integrations.log      # « Create TheHive alert: … » à chaque envoi
```

La clé API n'est jamais versionnée (voir [`.env.example`](../.env.example)). TheHive étant servi en HTTPS par nginx avec un certificat auto-signé, le script désactive la vérification du certificat (`cert=False`) : acceptable dans un lab isolé, à remplacer par le CA du lab sinon.

## 4. Quelles détections arrivent dans TheHive

| Cas | Règle | Niveau | Transmis |
|-----|-------|--------|----------|
| 1 — brute force SSH | 100110 · 100120 | 12 | oui |
| 2 — brute force RDP/SMB | 100111 | 12 | oui |
| 3 — scan nmap | 86601 | 3 | non (création manuelle du cas) |
| 4 — ajout admin | 100113 | 12 | oui |
| 5 — PowerShell suspect | 100114 · 100115 | 12 | oui |
| 6 — accès LSASS | 100116 | 14 | oui |
| 7 — persistance clé Run | 100100 | 10 | oui |
| 8 — web shell | 554 + règles web | < 10 | non, sauf règle de rehaussement |
| 9 — exfiltration DNS | 100200 · 100201 | 10 · 12 | oui |
| 10 — FIM | 550 / 553 / 554 | < 10 | non, sauf règle de rehaussement |
| Corrélation | 100117 · 100118 · 100119 | 14 · 14 · 15 | oui |

## 5. Installation de TheHive et Cortex

Pas encore scriptée dans le dépôt. Éléments de configuration retenus sur le lab (voir aussi la section « Sécurité du lab » du [README](../README.md#sécurité-du-lab)) :

| Élément | Valeur |
|---------|--------|
| Versions | TheHive 5.8.0, Cortex 4.1.0, Cassandra 4.1.12, Elasticsearch 7.17.29 (index interne) |
| TLS | nginx en reverse proxy : TheHive sur 9443, Cortex sur 9444 |
| Filtrage | ufw : seuls 22, 9443 et 9444 ouverts depuis le sous-réseau du lab ; 9000 / 9001 restent en local pour nginx |
| Clé Cortex | compte avec les rôles `read` + `analyze` (un superadmin ne peut pas lister les analyseurs) |
| Analyseurs utilisés | AbuseIPDB_2_0, VirusTotal_GetReport_3_1 |
