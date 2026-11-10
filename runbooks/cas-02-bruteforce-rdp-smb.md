# Runbook — Cas 2 : Brute force RDP/SMB (Windows)

| | |
|---|---|
| **Cas** | 2 |
| **Hôte cible** | DC01 — Windows Server 2025, domaine `lab.local` (`192.168.159.10`) |
| **Source de log** | canal **Security** (eventchannel), collecté par défaut par l'agent Windows |
| **Événement Windows** | 4625 — échec d'ouverture de session |
| **Règle(s) Wazuh** | 60122 (unitaire, niveau 5) → **100111** (custom, niveau 12) |
| **Niveau** | 12 |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Requête dashboard** | `rule.id:100111` (ou `rule.id:60122` pour les échecs unitaires) |

## Description

Tentative d'accès par **force brute** sur les services d'authentification Windows (SMB, RDP, et SSH s'il est activé sur le DC). Chaque échec produit un **4625**. L'objectif défensif est de lever une alerte agrégée sur la rafale plutôt que sur chaque échec.

## Détection

- **Chaîne :** Kali (Metasploit `smb_login`) → SMB DC01 → 4625 → agent Wazuh → manager → dashboard.
- **Prérequis :** audit des échecs d'ouverture de session activé (`auditpol`, sous-catégorie `{0CCE9215-69AE-11D9-BED3-505054503030}`).
- Règle custom **100111** : 6 × 60122 en 120 s (`if_matched_sid` + `frequency` / `timeframe`), puis `ignore="900"` (une alerte au plus toutes les 15 min). Agrège tous les vecteurs (SMB, RDP, SSH) puisqu'elle porte sur le 4625.
- Doc technique : [`docs/bruteforce-rdp-smb-wazuh.md`](../docs/bruteforce-rdp-smb-wazuh.md).

## Procédure d'investigation

1. **Confirmer l'attaque** — `rule.id:100111` sur **Last 15 minutes**. Attendu : alertes niveau 12 taguées **Brute Force (T1110)**.
2. **Identifier la source** — champ `data.win.eventdata.ipAddress` (l'IP n'est pas dans `srcip` côté Windows). En labo : `192.168.159.50` (Kali).
3. **Identifier le vecteur** — `data.win.eventdata.logonType` : **3** = réseau (SMB), **10** = RDP.
4. **Comptes ciblés** — `data.win.eventdata.targetUserName`. Un compte valide visé en rafale peut provoquer un verrouillage (**4740**).
5. **Évaluer la réussite** — rechercher un **4624** (ouverture réussie) depuis la même IP juste après les échecs.
6. **Contrôle direct côté manager :**
   ```bash
   sudo tail -n 500 /var/ossec/logs/alerts/alerts.json \
     | jq -r 'select(.rule.id=="60122" or .rule.id=="100111") | "\(.timestamp)  \(.rule.id)  src \(.data.win.eventdata.ipAddress)"' | tail -n 30
   ```

## Remédiation

- **Immédiat :** bloquer l'IP source ; si un compte a été compromis, réinitialiser son mot de passe et auditer ses sessions.
- **Durcissement :** politique de verrouillage de compte, NLA obligatoire sur RDP, RDP non exposé hors VPN, SMB restreint au réseau d'administration.
- **Limites :** le vecteur RDP n'a pas pu être rejoué (module `rdp` d'hydra expérimental + NLA) ; la détection est validée sur SMB. Pas encore de corrélation « échecs puis 4624 » (équivalent Windows de 100117).
