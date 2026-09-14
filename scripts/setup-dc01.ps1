<#
  Déploiement du contrôleur de domaine DC01 - lab SOC
  Windows Server 2025 Eval / VMware Workstation / réseau NAT VMnet8
  Usage : .\setup-dc01.ps1 -Password 'VotreMotDePasse'
#>
param(
    [Parameter(Mandatory)][string]$Password,
    [string]$Subnet = "192.168.159",
    [string]$Host    = "10",
    [string]$Domain  = "lab.local"
)

$pw = ConvertTo-SecureString $Password -AsPlainText -Force

# Adressage statique - le DC doit être son propre DNS
Set-NetIPInterface  -InterfaceAlias "Ethernet0" -Dhcp Disabled
Remove-NetIPAddress -InterfaceAlias "Ethernet0" -Confirm:$false -EA SilentlyContinue
Remove-NetRoute     -InterfaceAlias "Ethernet0" -Confirm:$false -EA SilentlyContinue

New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress "$Subnet.$Host" `
    -PrefixLength 24 -DefaultGateway "$Subnet.2"
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1

# Le compte Administrateur local devient admin du domaine : mot de passe obligatoire
$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
Set-LocalUser -Name $admin.Name -Password $pw

Rename-Computer -NewName "DC01"

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName $Domain -InstallDns `
    -SafeModeAdministratorPassword $pw -Force
