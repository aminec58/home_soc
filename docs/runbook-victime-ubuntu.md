# Runbook — VM victime Ubuntu (agent Wazuh)

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

## Détection validée
- **Bruteforce SSH** : attaque `hydra` depuis Kali → règle native **5712 "sshd: brute force"**
  (niveau 10) remontée dans le dashboard.
- MITRE ATT&CK : **T1110 – Brute Force** (tactique *Credential Access*).
- Vérification : filtre `rule.id:5712` sur l'agent `victime-ubuntu` → 1 alerte.

## Prochaines étapes
- [ ] Test FIM / auditd (*who-data*) : modification de `/etc/passwd`, `/etc/sudoers`.
- [ ] Rédiger une ou deux règles de détection custom.
