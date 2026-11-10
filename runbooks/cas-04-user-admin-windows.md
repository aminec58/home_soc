# Runbook — Cas 4 : Création de compte et élévation de privilèges (Windows)

| | |
|---|---|
| **Cas** | 4 |
| **Hôte cible** | DC01 — Windows Server 2025, domaine `lab.local` (`192.168.159.10`) |
| **Source de log** | canal **Security** (eventchannel) → agent Wazuh |
| **Événements Windows** | 4720 (création de compte) · 4732 (ajout à un groupe local) |
| **Règle(s) Wazuh** | 60109 (4720, native, niveau 8) · 60103/60113 (4732, native) → **100113** (custom, niveau 12) |
| **Niveau** | 12 (custom, sur l'ajout aux Administrateurs) |
| **MITRE ATT&CK** | T1136 (création de compte) · **T1098** — Account Manipulation (custom) |
| **Requête dashboard** | `rule.id:100113` |

## Description

Création d'un compte puis **ajout au groupe Administrateurs** (builtin, SID `S-1-5-32-544`). Séquence classique de **persistance + élévation de privilèges**. La détection vise spécifiquement la promotion d'un compte au groupe Administrateurs, promue en **alerte « changement de privilèges » de niveau élevé** — là où la native 60113 (niveau 5) est un signal trop faible.

> Sur un DC, les cmdlets *LocalAccounts* ne fonctionnent pas (pas de SAM local) : l'attaquant passe par `net user` / `net localgroup`, qui opèrent sur l'annuaire et le groupe builtin.

## Détection

- **Chaîne :** DC01 (`net user` + `net localgroup`) → journal Security (4720 + 4732) → agent (eventchannel) → manager → dashboard.
- Le canal **Security est collecté par défaut** par l'agent Windows — rien à ajouter côté agent. Seule condition : l'audit *Gestion des comptes d'utilisateur* et *Gestion des groupes de sécurité* en **Réussite** (défaut d'un DC).
- Comportement natif :

  | Événement | Règle | Niveau |
  |---|---|---|
  | 4720 — compte créé | 60109 (*user account enabled or created*, T1136) | 8 |
  | 4732 — ajout à un groupe local | 60103 → 60113 (*group management*, T1484) | 0 → 5 |

- Le **4720 reste couvert par le natif** (60109, niveau 8). Règle custom **100113** sur le 4732 : `if_sid 60103` + `win.system.eventID ^4732$` + `targetSid ^S-1-5-32-544$` → restreinte au builtin **Administrateurs**, `level 12`, tag **T1098**. Ce filtre sur le SID la rend plus spécifique que la native 60113, donc elle l'emporte.

## Procédure d'investigation

1. **Confirmer l'élévation** — dashboard Threat Hunting → Dashboard, requête `rule.id:100113`. Attendu : alerte niveau 12, carte *Level 12 or above*, tag **Account Manipulation (T1098)**.
2. **Identifier l'acteur** — champ `data.win.eventdata.subjectUserName` (qui a fait l'ajout). En labo : `Administrateur`.
3. **Identifier le compte promu** — l'événement 4732 ne porte côté *Membre* que le **SID** du compte ajouté (nom = `-`). Corréler ce SID avec le 4720 correspondant pour retrouver le nom du compte :
   ```bash
   sudo tail -n 800 /var/ossec/logs/alerts/alerts.json \
     | jq -r 'select(.data.win.system.eventID=="4720") | "\(.timestamp)  rule \(.rule.id)  \(.rule.description)"'
   ```
4. **Reconstituer la séquence** — rapprocher 4720 (création) et 4732 (promotion) pour la même cible : compte fraîchement créé **puis** promu admin = fort signal de persistance/priv-esc.
5. **Contrôle direct dans le journal (DC01) :**
   ```bat
   wevtutil qe Security /q:"*[System[(EventID=4720 or EventID=4732)]]" /c:5 /rd:true /f:text
   ```

> ⚠ **Décalage d'horloge** : si le dashboard est vide en « Last 15 minutes » alors que l'action a eu lieu, suspecter une désynchro DC01/manager (le 4732 peut être tamponné ~2 h après). Élargir à « Last 24 hours » et synchroniser l'heure (NTP).

## Remédiation

- **Immédiat :** si le compte est illégitime — le retirer du groupe Administrateurs, désactiver/supprimer le compte (`net user <compte> /delete`), invalider ses sessions. Identifier comment l'acteur a obtenu les droits d'ajout.
- **Durcissement :** limiter les comptes autorisés à modifier les groupes privilégiés ; surveiller/alerter sur toute modification du groupe Administrateurs ; principe du moindre privilège.
- **Prévention / suite :**
  - **Active Response** (`disable-account` ou retrait du groupe) sur 100113.
  - **Synchroniser l'heure (NTP)** DC01 ↔ manager (fiabilise plages, timelines, corrélations).
  - Règle de corrélation **4720 → 4732** même cible (délicat en natif : SID du nouveau compte en `targetSid` côté 4720 vs `memberSid` côté 4732).
  - Étendre aux groupes de **domaine** privilégiés : **4728** (groupe global, ex. *Admins du domaine*) et **4756** (groupe universel, ex. *Admins de l'entreprise/du schéma*), non couverts par le filtre builtin `S-1-5-32-544`.
