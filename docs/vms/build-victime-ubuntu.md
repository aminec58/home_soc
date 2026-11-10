# Construction — VM victime Ubuntu (agent Wazuh)

## Contexte
- Objectif : ajouter une VM Linux victime instrumentée, remontée dans Wazuh.
- Environnement : VMware Workstation Pro, réseau NAT VMnet8.
- Manager Wazuh : 192.168.159.141 (version 4.9.2).
- Victime : Ubuntu, IP fixe 192.168.159.20, agent `victime-ubuntu` (ID 002).

## Installation de l'agent Wazuh
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
```

Installer **directement la version du manager** (4.9.2) et l'épingler, avec un nom d'agent propre, évite les problèmes 1 à 3 ci-dessous :

```bash
sudo WAZUH_MANAGER=192.168.159.141 WAZUH_AGENT_NAME=victime-ubuntu \
  apt-get install -y wazuh-agent=4.9.2-1
sudo apt-mark hold wazuh-agent
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```

Collecte SSH : ajouter le bloc `localfile` sur `/var/log/auth.log` (voir [`bruteforce-ssh.md`](../bruteforce-ssh.md#1-collecte)).

## Problèmes rencontrés et solutions

### 1. Version de l'agent supérieure au manager
- Symptôme : `ERROR: Agent version must be lower or equal to manager version`.
- Cause : agent 4.14.7 tiré par défaut, manager en 4.9.2 (règle Wazuh : manager ≥ agent).
- Solution :
```bash
sudo systemctl stop wazuh-agent
sudo apt-get install -y --allow-downgrades wazuh-agent=4.9.2-1
sudo apt-mark hold wazuh-agent
```

### 2. Nom d'agent refusé
- Symptôme : `ERROR: Invalid agent name: amin-VMware-Virtual-Platform`.
- Cause : hostname VMware par défaut non accepté par le manager.
- Solution :
```bash
sudo /var/ossec/bin/agent-auth -m 192.168.159.141 -A victime-ubuntu
```

### 3. Erreur de configuration après downgrade
- Symptôme : `wazuh-modulesd: ERROR: No such tag 'users' / 'groups'` → service en échec.
- Cause : `ossec.conf` conservé (4.14) avec des balises `syscollector` inconnues de la 4.9.2.
- Solution : réinitialiser le bloc `syscollector` aux balises valides
  (`hardware`, `os`, `network`, `packages`, `ports`, `processes`).

## Résultat
```bash
sudo /var/ossec/bin/wazuh-control status   # 6 démons "running"
```
Agent `victime-ubuntu` (ID 002) visible et **Active** dans le dashboard.

## Détections portées par cette VM
- **Brute force SSH** (cas 1) : natives 5712 / 5763 escaladées en 100110 / 100120, corrélation 100117, Active Response `firewall-drop`.
- **Suricata** (cas 3, 9) : sonde sur `ens33`, `eve.json` collecté par l'agent — voir [`install/suricata.md`](../../install/suricata.md).
- **FIM** (cas 8, 10) : `/etc` et `/var/www` surveillés par syscheck.
