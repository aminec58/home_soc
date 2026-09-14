# Runbook — DC01 : contrôleur de domaine instrumenté

Déploiement d'un endpoint Windows produisant de la télémétrie Sysmon
consommée par le manager Wazuh.

## Environnement

| Élément | Valeur |
|---|---|
| Hyperviseur | VMware Workstation Pro 17 |
| OS | Windows Server 2025 Evaluation (180 jours) |
| Ressources | 2 vCPU / 4 Go RAM / 60 Go / UEFI |
| Réseau | NAT — VMnet8, `192.168.159.0/24` |
| DC01 | `192.168.159.10` — domaine `lab.local` |
| Manager Wazuh | `192.168.159.141` |

## 1. Création de la VM

L'ISO d'évaluation de Server 2025 n'est pas détectée par VMware : renseigner
le système invité manuellement (*Microsoft Windows → Windows Server 2022*).
Sans cela, l'installation des VMware Tools reste grisée.

Installer l'édition **Standard (expérience de bureau)**.

## 2. Réseau et promotion Active Directory

```powershell
.\setup-dc01.ps1 -Password 'VotreMotDePasse'
```

Le script fixe l'adressage, définit le mot de passe du compte Administrateur
local, renomme la machine et promeut le serveur en contrôleur de domaine.
Redémarrage automatique en fin d'exécution.

Contrôle :

```powershell
Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode
```

## 3. Sysmon

```powershell
.\install-sysmon.ps1
```

## 4. Agent Wazuh

Commande d'enrôlement générée depuis le dashboard
(*Server management → Endpoints Summary → Deploy new agent*) :

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi `
  -OutFile $env:tmp\wazuh-agent
msiexec.exe /i $env:tmp\wazuh-agent /q `
  WAZUH_MANAGER='192.168.159.141' WAZUH_AGENT_NAME='DC01'
NET START WazuhSvc
```

## 5. Collecte du canal Sysmon

L'agent ne remonte pas Sysmon par défaut. La configuration est poussée
depuis le manager via `wazuh/shared/agent.conf`, plutôt qu'éditée
localement sur chaque endpoint :

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
sudo systemctl restart wazuh-manager
```

## 6. Validation

Sur DC01 — l'agent doit déclarer le canal :

```powershell
type "C:\Program Files (x86)\ossec-agent\ossec.log" | findstr /i sysmon
```

> `INFO: (1951): Analyzing event log: 'Microsoft-Windows-Sysmon/Operational'`

Sur le manager :

```bash
sudo /var/ossec/bin/agent_control -l
```

> `ID: 001, Name: DC01, Status: Active`

Dans le dashboard, filtrer sur `agent.name: "DC01"` : les groupes `sysmon`,
`windows_security` et `windows_system` doivent apparaître.

## Pièges rencontrés

| Symptôme | Cause | Correctif |
|---|---|---|
| La VM boote sur l'EFI Boot Manager | ISO `SERVER_LOF_PACKAGES_OEM` téléchargée au lieu du support d'installation | Récupérer l'ISO `SERVER_EVAL` |
| *Install VMware Tools* grisé | Système invité non renseigné à la création | Le définir dans *Options → General* |
| Promotion AD refusée | Mot de passe du compte Administrateur local vide | `net user Administrateur <mdp>` avant promotion |
| Aucune alerte Sysmon malgré un agent `Active` | Bloc `localfile` absent de `ossec.conf` | Passer par la configuration centralisée `agent.conf` |
| Erreurs `(1216) Unable to connect ... 1514` | Redémarrage du manager en cours | Transitoire, l'agent se reconnecte seul |
