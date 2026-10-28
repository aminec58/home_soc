# Runbook — Cas 6 : Mimikatz / accès à la mémoire LSASS (credential dumping)

| | |
|---|---|
| **Cas** | 6 |
| **Hôte cible** | DC01 — Windows Server 2025, domaine `lab.local` (`192.168.159.10`) |
| **Source de log** | Sysmon (`Microsoft-Windows-Sysmon/Operational`) |
| **Événement Windows** | Sysmon EID 10 — ProcessAccess |
| **Règle(s) Wazuh** | `sysmon_event_10` (natif, niveau 0) → **100116** (custom, niveau 14) |
| **Niveau** | 14 (critique) |
| **MITRE ATT&CK** | T1003.001 — OS Credential Dumping : LSASS Memory |
| **Requête dashboard** | `rule.id:100116` |

## Description

Exécution de **Mimikatz** (`sekurlsa::logonpasswords`) et détection de l'**accès à la mémoire de `lsass.exe`** via l'**ouverture d'un handle** (Sysmon EID 10). Point clé : l'Event 10 se déclenche sur **l'ouverture du handle**, pas sur l'extraction réussie des secrets — la détection tient donc **même quand le dump échoue** (ici bloqué par la LSA Protection). L'accès est promu en **alerte critique (niveau 14)**.

> **L'Event 10 est le plus volumineux de Sysmon** et beaucoup de configs le filtrent fortement. S'il ne logue pas l'accès à `lsass`, aucune télémétrie → aucune détection. La config sysmon-modular en place **couvre déjà lsass** (`TargetImage = lsass.exe` + masques `GrantedAccess` du credential dumping) → rien à modifier côté Sysmon.

## Détection

- **Chaîne :** DC01 (mimikatz) → ouverture handle sur lsass (`GrantedAccess 0x1010`) → Sysmon EID 10 → agent (eventchannel) → manager → dashboard.
- Canal Sysmon **déjà collecté** — rien à ajouter côté agent/collecte.
- Comportement natif :

  | Événement | Règle native | Niveau |
  |---|---|---|
  | Sysmon EID 10 — ProcessAccess | groupe `sysmon_event_10` | 0 (décodé, pas d'alerte) |

- Règle custom **100116** (niveau 14) : `if_group sysmon_event_10` + `targetImage …lsass\.exe$` (filtre **indispensable** : le groupe seul couvre tous les ProcessAccess) + `grantedAccess` dans l'ensemble des masques de lecture du credential dumping (`0x1010` observé, plus `0x1410`, `0x143A`, `0x1FFFFF`…), tag **T1003.001**.

## Procédure d'investigation

1. **Confirmer** — dashboard Threat Hunting, filtre `rule.id:100116` → alerte **niveau 14**, carte *Level 12 or above*, **MITRE : LSASS Memory**.
2. **Contrôle direct côté manager :**
   ```bash
   sudo grep lsass /var/ossec/logs/alerts/alerts.json \
     | jq -R 'fromjson? | select(.rule.id=="100116")
         | "\(.timestamp)  niveau \(.rule.level)  \(.data.win.eventdata.sourceImage)  \(.data.win.eventdata.grantedAccess)"'
   ```
3. **Lire les champs forensiques** (Events → ligne dépliée) :
   - `sourceImage` — le binaire qui accède à lsass (en labo `C:\lab\x64\mimikatz.exe`).
   - `grantedAccess` — le masque (`0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ`).
   - `sourceUser` — l'acteur (`LAB\amine`), `sourceProcessId`.
4. **Deux signaux renforçant la qualification :**
   - un `callTrace` contenant des modules `mimikatz.exe+…` ou `UNKNOWN` / image non signée (lecture depuis une image non signée = signal fort).
   - le `ruleName` posé par Sysmon : `technique_id=T1003,technique_name=Credential Dumping`.
5. **Évaluer l'impact** — le dump a-t-il réussi ? Une erreur `acquireLSA` indique la **LSA Protection (RunAsPPL)** : l'extraction a échoué, mais l'accès a eu lieu. En l'absence de RunAsPPL, considérer les secrets du DC comme compromis → procédure d'incident (rotation krbtgt, mots de passe, etc.).

## Remédiation

- **Immédiat (compromission d'un DC = critique) :** isoler l'hôte ; tuer le `sourceImage` ; si le dump a pu réussir, lancer la procédure de compromission d'annuaire (rotation des secrets, double reset `krbtgt`, audit des tickets).
- **Durcissement / prévention :**
  - **RunAsPPL (LSA Protection)** comme mesure préventive — a ici neutralisé l'extraction. À documenter comme durcissement.
  - **Credential Guard**, restriction des droits de debug, réduction des comptes à privilèges sur le DC.
  - **Active Response** (`kill` du `sourceImage`, voire isolation de l'hôte) sur 100116.
- **Faux positifs / contournements (suite) :**
  - Des accès LSASS **légitimes** existent (AV, `wmiprvse.exe`, processus Windows) → durcir via `callTrace` (modules `UNKNOWN`/non signés) et/ou whitelist de `sourceImage` connus (`level 0`).
  - **Contournements à couvrir :** dump via `comsvcs.dll`/`rundll32` (toujours un Event 10, mais `sourceImage = rundll32.exe`), duplication de handle, driver signé pouvant éviter l'Event 10 → compléter avec l'**Event 25 (ProcessTampering)** et, à terme, un EDR.
  - ⚠ **Limite de couverture connue** : le vidage LSASS via Gestionnaire des tâches **ne lève aucune alerte** — la config Sysmon exclut `SourceImage …taskmgr.exe`, l'Event 10 est supprimé à la source.
  - Corréler avec l'**Event 1** du même `sourceProcessGUID`/`processID` pour relier l'accès à son processus initiateur.
