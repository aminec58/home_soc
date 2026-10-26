# Active Response — blocage automatique de l'IP source (firewall-drop)

**Statut :** validé le 26/10/2026

Les cas précédents s'arrêtent à la **détection**. Ici, Wazuh **réagit** : quand un brute force SSH est détecté, le manager ordonne à l'agent `victime-ubuntu` de bloquer l'IP de l'attaquant au pare-feu (`firewall-drop`, iptables), puis de lever le blocage automatiquement après 120 s. Aucune règle de détection n'est ajoutée : la réponse se configure dans l'`ossec.conf` du manager, et le prochain ID custom libre reste **100120**.

```
Kali (hydra) → sshd victime-ubuntu → agent → manager (5712 native / 100110 custom)
   → <active-response> firewall-drop (location local) → wazuh-execd sur victime-ubuntu
   → iptables : DROP de l'IP source → timeout 120 s → firewall-drop delete (levée)
```

## Environnement

| Élément | Valeur |
|---|---|
| Manager | Wazuh 4.9.2, `192.168.159.141` — porte la conf Active Response |
| Agent (cible) | victime-ubuntu — Ubuntu 24.04, `192.168.159.20`, agent ID 002 — exécute le DROP |
| Attaquant | Kali — `192.168.159.30`, hydra 9.7 |
| Déclencheur | règle native **5712** (niveau 10) / règle custom **100110** (niveau 12) |
| Réponse | `firewall-drop` (iptables), `location local`, `timeout` 120 s |

## 1. Principe

Une Active Response associe une **commande** (ce qu'on exécute) à des **règles** (quand on l'exécute) :

| Balise | Rôle |
|---|---|
| `command` | `firewall-drop` est **prédéfinie** dans l'`ossec.conf` du manager, avec `timeout_allowed yes` : rien à ajouter côté agent |
| `location local` | la commande s'exécute sur l'agent qui a remonté l'alerte (victime-ubuntu), pas sur le manager |
| `rules_id` | les règles qui déclenchent le blocage |
| `timeout` | durée du blocage ; la levée est gérée localement par `wazuh-execd` sur l'agent |

L'IP bloquée est le `srcip` de l'alerte : la règle déclencheuse doit donc en porter un (c'est le cas de 5712 et 100110).

## 2. Configuration du manager

Bloc ajouté dans `/var/ossec/etc/ossec.conf`, dans `<ossec_config>`, juste avant `<!-- Log analysis -->` (versionné dans [`wazuh/manager/active-response.xml`](../wazuh/manager/active-response.xml)) :

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100110,5712</rules_id>
  <timeout>120</timeout>
</active-response>
```

Vérifications préalables :

```bash
sudo grep -n white_list /var/ossec/etc/ossec.conf                          # 192.168.159.30 absente → Kali peut être bloquée
sudo grep -n -A4 '<name>firewall-drop</name>' /var/ossec/etc/ossec.conf    # timeout_allowed yes
```

L'`ossec.conf` par défaut contient déjà un exemple `<active-response>`, mais **en commentaire** : pas de doublon. Le bloc a été inséré avec un script Python (sauvegarde `.bak`, validation XML par un parseur), puis validé **avant** redémarrage :

```bash
sudo /var/ossec/bin/wazuh-analysisd -t   # doit se terminer sans ERROR
sudo systemctl restart wazuh-manager
```

![Bloc active-response et analysisd -t](../demo/active-response/01-ossec-active-response-block.png)

## 3. Rejeu de l'attaque depuis Kali

La réponse n'est pas rétroactive : l'attaque est rejouée **après** le redémarrage du manager. Le brute force vise un utilisateur **inexistant**, ce qui produit des 5710 que 5712 agrège (voir §6) :

```bash
hydra -l aaa -P passlist.txt -t 4 ssh://192.168.159.20
```

Dès le déclenchement, hydra passe en timeout : la victime ne répond plus à Kali (ping/ssh KO).

La victime est surveillée depuis **sa console** (ou en SSH depuis le poste Windows), **pas depuis Kali** : le DROP couperait la session.

## 4. Validation — blocage

Sur **victime-ubuntu** — l'AR s'exécute sur l'agent, le journal est donc celui de l'agent, pas du manager :

```bash
sudo grep -a firewall-drop /var/ossec/logs/active-responses.log | tail -n 4
sudo iptables -S INPUT
```

Résultat : une ligne `"command":"add"` portant l'alerte **5712** (niveau 10, T1110), `srcip 192.168.159.30`, agent `victime-ubuntu`, suivie de l'échange `check_keys` → `continue` → `Ended` (firewall-drop vérifie auprès d'`execd` que l'IP n'est pas déjà bloquée).

![active-responses.log — add](../demo/active-response/02-active-responses-log-add.png)

```
-A INPUT -s 192.168.159.30/32 -j DROP
```

![Règle DROP active sur la victime](../demo/active-response/03-iptables-drop.png)

## 5. Validation — levée automatique

Environ **120 s après la dernière alerte** (09:06:46 → 09:08:47 lors du test), `wazuh-execd` rappelle `firewall-drop` avec `"command":"delete"` : la règle DROP disparaît et Kali est de nouveau joignable. Cycle complet rejoué plusieurs fois.

![active-responses.log — delete](../demo/active-response/04-active-responses-log-delete.png)

```
-P INPUT ACCEPT
```

![iptables INPUT vide après la levée](../demo/active-response/05-iptables-leve.png)

## 6. Règle 100110 réécrite en escalade de 5712

Pendant le test, la règle custom **100110** du cas brute force SSH ne se déclenchait plus : 5712 partait, 100110 jamais. `wazuh-logtest -v` montrait pourtant 100110 **essayée** sous 5710 et 5760, sans jamais valider sa condition de fréquence (`frequency="6"` + `if_matched_group authentication_failed`).

Plutôt que de recompter les échecs, 100110 est réécrite en **escalade** de la native 5712 (qui, elle, part de façon fiable) — sans `frequency`, elle se déclenche dès que 5712 se déclenche :

```xml
<group name="syslog,sshd,">
  <rule id="100110" level="12">
    <if_sid>5712</if_sid>
    <description>SSH brute force : échecs d'authentification répétés depuis $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_11.4,</group>
  </rule>
</group>
```

Validée avec `wazuh-analysisd -t` avant redémarrage. Description, MITRE et groupes sont inchangés ; seul le déclencheur change. Pendant le diagnostic, l'AR avait été branchée sur `100110,5712` pour rester opérationnelle ; 5712 est conservée en filet.

## 7. Vue dashboard

**Threat Hunting → Events** : l'alerte de brute force puis l'événement de l'Active Response sur l'agent `victime-ubuntu`.

![Threat Hunting — brute force et active response](../demo/active-response/06-wazuh-threat-hunting.png)

## Problèmes rencontrés

| Symptôme | Cause | Solution |
|---|---|---|
| Aucun blocage après l'attaque, aucune alerte sshd de la victime | l'agent ne lisait plus journald (`ERROR (1611): Failed to get the message from the journal`) | `usermod -aG systemd-journal wazuh`, purge de `/var/ossec/queue/logcollector/file_status.json`, redémarrage de l'agent |
| Événements SSH comptés en double | un `localfile` `/var/log/auth.log` ajouté en plus de journald, collecté par défaut par l'agent 4.9 | retirer le bloc `auth.log`, garder journald seul |
| Règle 100110 ne se déclenche plus (5712 native OK) | condition de fréquence `if_matched_group` jamais satisfaite, bien que la règle soit chargée et essayée (`logtest -v`) — cause exacte non établie | réécriture en escalade de 5712 (§6) |
| AR muette pendant le diagnostic de 100110 | l'AR ne visait que 100110 | contournement : `rules_id 100110,5712` |
| Heures incohérentes entre machines, logs introuvables par plage horaire | horloge du manager non synchronisée (NTP sans DNS), jusqu'à ~3 h 45 de retard sur la victime | `vmware-toolbox-cmd timesync enable` sur le manager ; lire les logs par règle et en direct (`tail -f`), pas par l'heure |
| Session de surveillance figée | victime surveillée en SSH depuis Kali → coupée par le DROP | surveiller depuis la console de la victime ou le poste Windows |
| Attaque « invisible » juste après un redémarrage du manager | le logcollector de l'agent est en pause tant que le manager ne répond pas | attendre la reconnexion de l'agent (`Agent is now online`) avant de rejouer |

## Limites et suite

- **100110 ne couvre plus que les utilisateurs inexistants** (5710 → 5712). Un brute force sur un compte **valide** produit des 5760, agrégées par la native **5763** : ajouter une règle sœur sur 5763 (ID 100120) et l'inclure dans `rules_id`.
- **Impact sur la corrélation** : 100117 (brute force puis login réussi) s'appuie sur `if_matched_sid 100110`. Le scénario réaliste — brute force sur un compte valide puis connexion — ne déclenche plus 100110, donc plus 100117. La règle sœur ci-dessus rétablirait la couverture.
- Maintenant que 100110 part de façon fiable, l'AR peut revenir sur `rules_id 100110` seul (100110 supplante 5712 dans l'alerte).
- Bloquer sur un simple brute force coupe aussi un utilisateur légitime qui se trompe de mot de passe, et un attaquant peut faire bloquer une IP usurpée : déclencher sur 100117 (compromission probable) serait plus ciblé.
- Kali partage l'adresse `192.168.159.30` avec la VM elastic : à réaligner.
- `repeated_offenders` pour des bans progressifs sur les IP récidivistes.
- Étendre l'AR : scan Suricata, et côté Windows (`netsh` / `route-null`) pour le brute force RDP/SMB (100111).
- En production, bloquer sur un pare-feu ou un routeur plutôt que sur chaque hôte.
