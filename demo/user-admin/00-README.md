# demo/user-admin — captures du cas « création user / ajout admin »

Captures déjà renommées pour les références de `docs/user-admin-wazuh.md`.

| Fichier | Contenu |
|---|---|
| `01-auditpol-subcategories.png` | `auditpol /get` : sous-catégories « Gestion des comptes d'utilisateur » et « Gestion des groupes de sécurité » en Réussite (DC01) |
| `02-dc01-create-add-admin.png` | `net user pirate /add` + `net localgroup Administrateurs pirate /add` + liste des membres du groupe Administrateurs |
| `03-wazuh-dashboard-privesc.png` | Dashboard Threat Hunting : carte « Level 12 or above = 1 » + donut MITRE « Account Manipulation » (règle 100113) |
| `04-alerts-4720-native-60109.png` | `jq` sur `alerts.json` : 4720 couvert par la règle native 60109 (niveau 8) |
