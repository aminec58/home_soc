<#
  Déploiement du contrôleur de domaine DC01 - lab SOC
  Windows Server 2025 Eval / VMware Workstation / réseau NAT VMnet8

  Usage (PowerShell administrateur) :
    .\setup-dc01.ps1
    .\setup-dc01.ps1 -Subnet 192.168.56 -HostId 106 -Gateway 192.168.56.1

  Le mot de passe est demandé de façon masquée : il n'apparaît ni à l'écran
  ni dans l'historique PowerShell. La machine redémarre à la fin de la
  promotion AD.
#>
param(
    [string]$Subnet    = "192.168.159",
    [string]$HostId    = "10",          # pas $Host : variable automatique en lecture seule de PowerShell
    [string]$Gateway   = "",            # par défaut <Subnet>.2 (passerelle NAT VMware)
    [string]$Domain    = "lab.local",
    [string]$Interface = "Ethernet0"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "À lancer dans une session PowerShell administrateur."
}

if (-not $Gateway) { $Gateway = "$Subnet.2" }
$pw = Read-Host -AsSecureString "Mot de passe Administrateur / DSRM"

# Adressage statique - le DC doit être son propre DNS
Set-NetIPInterface  -InterfaceAlias $Interface -Dhcp Disabled
Remove-NetIPAddress -InterfaceAlias $Interface -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute     -InterfaceAlias $Interface -Confirm:$false -ErrorAction SilentlyContinue

New-NetIPAddress -InterfaceAlias $Interface -IPAddress "$Subnet.$HostId" `
    -PrefixLength 24 -DefaultGateway $Gateway | Out-Null
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses 127.0.0.1

# Le compte Administrateur local (RID 500) devient admin du domaine : mot de passe obligatoire
$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
Set-LocalUser -Name $admin.Name -Password $pw

Rename-Computer -NewName "DC01" -Force

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $Domain -InstallDns `
    -SafeModeAdministratorPassword $pw -Force
