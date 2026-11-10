<#
  Installation de Sysmon avec la configuration sysmon-modular (Olaf Hartong)

  Usage (PowerShell administrateur, sur DC01) :
    .\install-sysmon.ps1                                   # config du dépôt si présente, sinon sysmon-modular figée
    .\install-sysmon.ps1 -ConfigPath ..\sysmon\sysmonconfig.xml

  La configuration est figée (fichier versionné ou commit précis) pour que le
  lab soit reproductible : la branche master de sysmon-modular évolue et peut
  changer ce qui est journalisé (ex. couverture de l'EID 10 sur lsass).
#>
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\sysmon\sysmonconfig.xml"),
    [string]$ModularCommit = "a45dedb13a43c0d8ea1fc6b580a0ac396fa74457"
)

$ErrorActionPreference = "Stop"
$dir = "C:\sysmon"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip `
    -OutFile "$dir\Sysmon.zip" -UseBasicParsing
Expand-Archive "$dir\Sysmon.zip" $dir -Force

if (Test-Path $ConfigPath) {
    Copy-Item $ConfigPath "$dir\sysmonconfig.xml" -Force
    Write-Host "[*] Configuration du dépôt : $ConfigPath"
} else {
    $url = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/$ModularCommit/sysmonconfig.xml"
    Invoke-WebRequest $url -OutFile "$dir\sysmonconfig.xml" -UseBasicParsing
    Write-Host "[*] Configuration sysmon-modular figée au commit $ModularCommit"
}
(Get-FileHash "$dir\sysmonconfig.xml" -Algorithm SHA256).Hash | ForEach-Object { Write-Host "[*] SHA256 config : $_" }

if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    & "$dir\Sysmon64.exe" -c "$dir\sysmonconfig.xml"      # mise à jour de la config
} else {
    & "$dir\Sysmon64.exe" -accepteula -i "$dir\sysmonconfig.xml"
}

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1
