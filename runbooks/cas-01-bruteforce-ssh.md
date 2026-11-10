# Runbook — Cas 1 : Brute force SSH

| | |
|---|---|
| **Cas** | 1 |
| **Hôte cible** | victime-ubuntu (`192.168.159.20`, SSH actif) |
| **Source de log** | `sshd` → `/var/log/auth.log` (rsyslog) → agent Wazuh |
| **Règle(s) Wazuh** | 5710 / 5760 (unitaires, niveau 5) → 5712 / 5763 (natives, niveau 10) → **100110** / **100120** (custom, niveau 12) |
| **Niveau** | 12 (custom) · 14 si suivi d'une connexion réussie (corrélation 100117) |
| **MITRE ATT&CK** | T1110 — Brute Force |
| **Réponse automatique** | Active Response `firewall-drop` (blocage de l'IP 120 s) |
| **Requête dashboard** | `rule.id:(100110 OR 100120)` (ou `rule.groups:sshd` pour la vue d'ensemble) |

## Description

Tentative d'accès **SSH par force brute** : un attaquant teste en rafale de nombreux couples identifiant/mot de passe contre le service `sshd`. L'objectif défensif n'est pas d'alerter sur chaque échec (bruit), mais d'obtenir **une alerte agrégée de niveau élevé** quand plusieurs échecs surviennent en peu de temps depuis la même source.

## Détection

- **Chaîne :** Kali (hydra) → `sshd` victime-ubuntu → `/var/log/auth.log` → logcollector de l'agent → manager → dashboard.
- Comportement natif et escalade :

  | Événement `sshd` | Unitaire | Agrégée (8 échecs / 120 s, même IP) | Custom |
  |---|---|---|---|
  | « Failed password for invalid user … » (compte **inexistant**) | 5710 (niv. 5) | 5712 (niv. 10) | **100110** (niv. 12) |
  | « Failed password for \<user> … » (compte **existant**) | 5760 (niv. 5) | 5763 (niv. 10) | **100120** (niv. 12) |

- **100120 est la plus importante** : seul un brute force sur un compte existant peut aboutir. Une connexion réussie depuis la même IP juste après déclenche la corrélation **100117** (niveau 14, T1110 + T1078).
- Doc technique : [`docs/bruteforce-ssh.md`](../docs/bruteforce-ssh.md) · réponse automatique : [`docs/active-response-wazuh.md`](../docs/active-response-wazuh.md).

## Procédure d'investigation

1. **Confirmer l'attaque** — dashboard Threat Hunting → Events, **Last 15 minutes**, requête `rule.id:(100110 OR 100120)`. Attendu : alertes niveau 12 taguées **Brute Force (T1110)**.
2. **Identifier la source** — champ `data.srcip`. En labo : `192.168.159.50` (Kali).
3. **Contrôle direct côté manager :**
   ```bash
   sudo tail -n 300 /var/ossec/logs/alerts/alerts.json \
     | jq -r 'select(.rule.id=="100110" or .rule.id=="100120") | "\(.timestamp)  \(.rule.id)  \(.data.srcip)  \(.data.dstuser)"'
   ```
4. **Évaluer la réussite** — le point critique. Rechercher `rule.id:100117` : une alerte signifie une connexion réussie après le brute force (compromission probable). À défaut, chercher un « Accepted password » depuis la même `srcip` dans `auth.log`.
5. **Vérifier la réponse automatique** — `rule.id:651` (Active Response lancée) et, sur la victime, `sudo iptables -S INPUT | grep DROP`.
6. **Qualifier la source** — IP interne/externe, connue/inconnue, volume et rythme des tentatives, comptes ciblés.

## Remédiation

- **Immédiat :** le blocage automatique ne dure que 120 s ; bloquer durablement l'IP si elle est hostile. Si un compte a été compromis (100117) : réinitialiser son mot de passe, invalider les sessions, auditer son activité.
- **Durcissement :** authentification SSH **par clé** (désactiver l'auth par mot de passe) ; restreindre l'accès SSH (ACL / VPN) ; `fail2ban` en complément.
- **Limites :** un brute force **distribué** (IP multiples, faible débit par IP) ou **lent** (moins de 8 échecs / 120 s) échappe aux règles natives agrégées.
