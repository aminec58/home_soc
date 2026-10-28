# Runbook — Cas 2 : Brute force SSH

| | |
|---|---|
| **Cas** | 2 |
| **Hôte cible** | victime-ubuntu (`192.168.159.20`, SSH actif) |
| **Source de log** | `sshd` → journald → agent Wazuh |
| **Règle(s) Wazuh** | 5710 / 5716 / 5760 (unitaires, niveau 5) → 5712 (native, niveau 10) + **100110** (custom, niveau 12) |
| **Niveau** | 12 (custom) |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Requête dashboard** | `rule.id:100110` (ou `rule.groups:sshd` pour la vue d'ensemble) |

## Description

Tentative d'accès **SSH par force brute** : un attaquant teste en rafale de nombreux couples identifiant/mot de passe contre le service `sshd`. L'objectif défensif n'est pas d'alerter sur chaque échec (bruit), mais d'obtenir **une alerte agrégée de niveau élevé** quand plusieurs échecs surviennent en peu de temps depuis la même source.

> La règle native 5712 n'agrège que les échecs 5710 (utilisateur inexistant) ; or hydra provoque surtout des **5760** (coupures en preauth). D'où la règle custom **100110**, qui agrège tous les échecs du groupe `authentication_failed`.

## Détection

- **Chaîne :** Kali (hydra) → `sshd` victime-ubuntu → journald → logcollector de l'agent → manager → dashboard.
- L'agent 4.9 collecte **journald par défaut** (couvre `sshd`) — aucun bloc `localfile` à ajouter côté agent. Il ne lit **pas** `/var/log/auth.log`.
- Comportement natif :

  | Événement `sshd` | Règle | Niveau |
  |---|---|---|
  | « Failed password for invalid user … » | 5710 | 5 |
  | « Failed password for \<user> … » | 5716 | 5 |
  | 8× 5710, même IP, < 120 s | 5712 | 10 |

- Règle custom **100110** : `if_matched_group authentication_failed`, `frequency 6` / `timeframe 120`, `level 12`. Alerte dès le 6ᵉ échec en 120 s, quelle que soit la nature de l'échec.

## Procédure d'investigation

1. **Confirmer l'attaque** — dashboard Threat Hunting → Events, **Last 15 minutes**, requête `rule.id:100110`. Attendu : paquet d'alertes niveau 12 taguées **Brute Force (T1110)**.
2. **Identifier la source** — champ `data.srcip`. En labo : `192.168.159.30` (Kali).
3. **Contrôle direct côté manager :**
   ```bash
   sudo tail -n 300 /var/ossec/logs/alerts/alerts.json \
     | jq -r 'select(.rule.id=="100110") | "\(.timestamp)  niveau \(.rule.level)"'
   ```
4. **Évaluer la réussite** — le point critique : y a-t-il eu un **succès** après les échecs ? Chercher un « Accepted password » depuis la même `srcip` → bascule vers **T1078** (compromission réelle, voir Limites et suite). Vérifier les comptes ciblés (utilisateur valide vs inexistant : 5716 vs 5710).
5. **Qualifier la source** — IP interne/externe, connue/inconnue, volume et rythme des tentatives.

## Remédiation

- **Immédiat :** bloquer l'IP source au pare-feu. Si un compte a été compromis : réinitialiser son mot de passe, invalider les sessions, auditer son activité.
- **Durcissement :** authentification SSH **par clé** (désactiver l'auth par mot de passe) ; restreindre l'accès SSH (ACL / VPN) ; `fail2ban` en complément.
- **Prévention / suite :**
  - **Active Response** Wazuh (`firewall-drop`) sur 5712/100110 pour bloquer automatiquement l'IP.
  - Réactiver `<same_source_ip />` dans la règle 100110 (retiré pendant le diagnostic du bug journald) pour une agrégation stricte par IP source — plus propre en multi-hôtes.
  - Règle de corrélation « échecs puis succès » (→ T1078).
  - ⚠ Un brute force **distribué** (IP multiples) échappe à `same_source_ip`.
