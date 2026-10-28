# Runbook — Cas 5 : PowerShell suspect (encodé / obfusqué)

| | |
|---|---|
| **Cas** | 5 |
| **Hôte cible** | DC01 — Windows Server 2025, domaine `lab.local` (`192.168.159.10`) |
| **Sources de log** | Sysmon (`Microsoft-Windows-Sysmon/Operational`) · PowerShell Script Block Logging (`Microsoft-Windows-PowerShell/Operational`) |
| **Événements Windows** | Sysmon EID 1 (création de processus) · PowerShell 4104 (script block) |
| **Règle(s) Wazuh** | `sysmon_event1` → **100114** · 91837 (native, niveau 4) → **100115** |
| **Niveau** | 12 (les deux custom) |
| **MITRE ATT&CK** | T1059.001 (PowerShell) · T1027 (obfuscation) · T1105 (ingress tool transfer) |
| **Requête dashboard** | `rule.id:100114 or rule.id:100115` |

## Description

Exécution d'une commande PowerShell **encodée (`-enc`) ou obfusquée** (téléchargement via `DownloadString`/`Net.WebClient`, `IEX`…). Détection sur **deux télémétries complémentaires** :
- **Sysmon EID 1** — la ligne de commande telle que passée au processus (**100114**).
- **PowerShell 4104** — le script **déchiffré** à la compilation (**100115**), robuste contre l'obfuscation base64 : le `-enc` est défait, donc le motif suspect réapparaît en clair.

> **Sysmon EID 1 dépend du mode de lancement.** La ligne de commande complète part sur le processus **qui reçoit les arguments**. Lancé depuis un shell `cmd` (défaut d'OpenSSH sur le DC), tout va sur le parent `cmd.exe` et le `powershell.exe` enfant n'a que `powershell` → 100114 est aveugle. Reproduire un lancement **réaliste en processus unique** (tâche planifiée, service, macro) pour que `powershell.exe` reçoive toute sa ligne. La **100115 (4104) reste le filet robuste** — elle matche quel que soit le mode d'invocation.

## Détection

- **Chaîne :** DC01 → Sysmon + PowerShell/Operational → agent (eventchannel) → manager → dashboard.
- **Deux pré-requis sur DC01** (contrairement au canal Security, natif) :
  - **a. Activer le Script Block Logging** (source du 4104, désactivé par défaut) :
    ```powershell
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    New-Item $k -Force | Out-Null
    Set-ItemProperty $k -Name EnableScriptBlockLogging -Value 1 -Type DWord
    ```
  - **b. Collecter le canal PowerShell/Operational** côté agent (`localfile` à ajouter) :
    ```xml
    <localfile>
      <location>Microsoft-Windows-PowerShell/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    ```
  - Le canal **Sysmon est déjà collecté** et la native EID 1 déjà active.
- Comportement natif :

  | Événement | Règle native | Niveau |
  |---|---|---|
  | Sysmon EID 1 — `powershell.exe` | groupe `sysmon_event1` | 0 (décodé, pas d'alerte) |
  | PowerShell 4104 — script block | 91837 (*Possible string execution as code*) | 4 |

- Règles custom (niveau 12, plus spécifiques → l'emportent) :
  - **100114** `if_group sysmon_event1` + regex sur `commandLine` (encodage `-e`/`-enc` + blob base64 **et** `DownloadString`, `Net.WebClient`, `IEX`, `FromBase64String`).
  - **100115** `if_sid 91837` + regex sur `scriptBlockText` (mêmes indicateurs + `invoke-mimikatz`, `reflection.assembly`).

> **Ancrage ruleset 4.9.2 :** le 4104 remonte via **91837** (pas `91801`), et l'EID 1 via le **groupe `sysmon_event1`** (pas `61603`). Diagnostiquer avec `wazuh-logtest` sur un event réel + `grep` dans `/var/ossec/ruleset/rules/`.

## Procédure d'investigation

1. **Confirmer** — dashboard Threat Hunting → Events, **Last 1 hour**, requête `rule.id:100114 or rule.id:100115`. Tag attendu **T1059.001**.
2. **Lire la charge** :
   - `data.win.eventdata.commandLine` (100114) — la ligne de commande.
   - `data.win.eventdata.scriptBlockText` (100115) — le script **déchiffré**. Sur une commande `-enc`, c'est ici que `DownloadString` réapparaît en clair alors que la ligne de commande ne portait que du base64.
3. **Décoder manuellement un `-enc`** si besoin : base64 → UTF-16LE. Identifier l'intention (téléchargement, exécution en mémoire, dump…).
4. **Repérer un cradle de téléchargement** — URL dans `DownloadString`/`DownloadFile`. Noter que le motif est capturé **même si la connexion échoue** (le 4104 journalise à la compilation, avant le réseau).
5. **Contrôle direct côté manager :**
   ```bash
   sudo grep DownloadString /var/ossec/logs/alerts/alerts.json \
     | jq -R 'fromjson? | select(.rule.id=="100114" or .rule.id=="100115") | "\(.timestamp)  \(.rule.id)  niveau \(.rule.level)"'
   ```
6. **Relier au processus et à l'acteur** — corréler 4104 → Sysmon EID 1 (même `processID`, courte fenêtre). ⚠ Le 4104 ne remonte pas l'utilisateur en clair à Wazuh (SID dans `System/Security/UserID`, non décodé).

## Remédiation

- **Immédiat :** isoler l'hôte si exécution confirmée hostile ; tuer le processus ; récupérer et analyser toute charge téléchargée ; auditer ce que le script a fait (persistance, comptes, connexions).
- **Durcissement :** `ExecutionPolicy` restrictive (contournable, défense en profondeur seulement) ; PowerShell en **Constrained Language Mode** ; **AMSI** + Defender actifs ; journalisation complète (Script Block + Module + transcription).
- **Prévention / suite :**
  - **Active Response** (kill du processus, voire isolation de l'hôte) sur 100114/100115.
  - Règle sœur 100114 sur `parentImage`/`parentCommandLine` pour couvrir le cas `cmd.exe → powershell`.
  - Durcir 100114 contre le **renommage du binaire** : matcher aussi `win.eventdata.originalFileName` (`PowerShell.EXE`).
  - **Faux positifs 100115** : des scripts d'admin légitimes utilisent `Invoke-WebRequest`/`IEX` → restreindre aux indicateurs forts ou exclure les scripts connus (`level 0`).
  - Sources complémentaires : Module Logging (4103), transcription, **AMSI** (Defender 1116/1117).
