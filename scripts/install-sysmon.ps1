<#
  Installation de Sysmon avec la configuration sysmon-modular (Olaf Hartong)
#>
$dir = "C:\sysmon"
New-Item -ItemType Directory -Path $dir -Force | Out-Null

Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip `
    -OutFile "$dir\Sysmon.zip" -UseBasicParsing
Expand-Archive "$dir\Sysmon.zip" $dir -Force

Invoke-WebRequest https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml `
    -OutFile "$dir\sysmonconfig.xml" -UseBasicParsing

& "$dir\Sysmon64.exe" -accepteula -i "$dir\sysmonconfig.xml"

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1
