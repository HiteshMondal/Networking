@echo off
REM ==============================================================================
REM Windows System Enumeration & Network Recon Script
REM Purpose : System inventory, network visibility, user/process enumeration,
REM           and optional penetration-testing style recon against a target
REM Usage   : enum.bat [TARGET_IP_or_HOSTNAME]
REM WARNING : Some commands are noisy and may trigger security alerts
REM ==============================================================================

REM BASIC SYSTEM INFORMATION

systeminfo

wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
wmic computersystem get Manufacturer,Model,Name,TotalPhysicalMemory
wmic bios get Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber
wmic memorychip get Capacity,Speed,Manufacturer,SerialNumber
wmic diskdrive get Model,Size,InterfaceType,SerialNumber
wmic baseboard get Manufacturer,Product,SerialNumber

REM NETWORK INTERFACES & IP CONFIGURATION

wmic nic where "NetEnabled=true" get Name,MACAddress,Speed,AdapterType
wmic nicconfig get Description,IPAddress,IPSubnet,DefaultIPGateway,DNSDomain,DNSHostName

ipconfig /all
getmac /v /fo list
route print
netstat -ano
arp -a

nslookup

netsh interface ipv4 show interfaces
netsh wlan show interfaces

REM STORAGE & POWER INFORMATION

wmic logicaldisk get DeviceID,VolumeName,FileSystem,FreeSpace,Size
powercfg /batteryreport 2>nul || true

type C:\Windows\System32\drivers\etc\hosts

wmic product get Name,Version 2>nul || true

REM POWERSHELL-BASED ENUMERATION

powershell -Command "Get-NetIPAddress -AddressFamily IPv4 | Format-Table -AutoSize"
powershell -Command "Get-NetAdapter | Format-List"
powershell -Command "Get-PhysicalDisk | Format-List"

REM PENETRATION TESTING / DEEP ENUMERATION SECTION

set TARGET=%1

REM --- Identity & User Context ---
systeminfo
hostname
whoami

net user
wmic useraccount get Name,SID,Disabled
net localgroup administrators

REM --- Hardware (Repeated for standalone execution clarity) ---
wmic computersystem get Manufacturer,Model,Name,TotalPhysicalMemory
wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
wmic bios get Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber

REM --- Network Enumeration ---
ipconfig /all
getmac /v /fo list
route print
arp -a
netstat -ano
netstat -r

tasklist /v
sc queryex type= service state= all
schtasks /query /fo LIST /v

REM TARGET-BASED ENUMERATION (if TARGET provided)

nslookup %TARGET%

if "%TARGET%"=="" (
    nbtstat -n
) else (
    nbtstat -A %TARGET%
)

nbtstat -a %TARGET% 2>nul || true
net view \\%COMPUTERNAME% 2>nul || true

REM FILES, SERVICES & PERSISTENCE POINTS

type C:\Windows\System32\drivers\etc\hosts

powershell -Command "Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-Table -AutoSize"
powershell -Command "Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Format-Table -AutoSize"

powershell -Command "Get-NetRoute | Format-Table -AutoSize"
powershell -Command "Get-WmiObject -Class Win32_LogicalDisk | Format-Table DeviceID,VolumeName,FileSystem,FreeSpace,Size -AutoSize"

powershell -Command "Get-EventLog -LogName System -Newest 200 | Format-Table TimeGenerated,EntryType,Source,EventID -AutoSize"

powershell -Command "Get-LocalUser | Format-Table Name,Enabled,LastLogon -AutoSize"
powershell -Command "Get-LocalGroup | Format-Table Name -AutoSize"

powershell -Command "Get-ScheduledTask | Where-Object {($_.State -eq 'Ready') -or ($_.State -eq 'Disabled')} | Format-Table TaskName,State -AutoSize"

REM --- Startup Persistence ---
powershell -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Format-Table -AutoSize"

REM CREDENTIAL & KEY HUNTING (HIGH SIGNAL)

powershell -Command ^
"Get-ChildItem -Path C:\Users -Recurse -Force -ErrorAction SilentlyContinue | ^
 Where-Object { $_.Name -match 'id_rsa|id_dsa|.*\.pem|.*\.key' } | ^
 Select-Object FullName -First 200"

powershell -Command ^
"Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | ^
 Where-Object {($_.Attributes -band [IO.FileAttributes]::System) -or `
               ($_.Attributes -band [IO.FileAttributes]::Archive)} | ^
 Select-Object FullName -First 200" 2>nul || true

REM SMB ENUMERATION

powershell -Command "Get-SmbShare | Format-Table -AutoSize" 2>nul || true
powershell -Command "Get-SmbSession | Format-Table -AutoSize" 2>nul || true
powershell -Command "Get-SmbOpenFile | Format-Table -AutoSize" 2>nul || true

REM OPTIONAL NETWORK SCANNING TOOLS (IF INSTALLED)

where nmap >nul 2>&1 && nmap -Pn -sS -sV -O -p- -oA nmap_full %TARGET% || true
where nbtscan >nul 2>&1 && nbtscan %TARGET% || true
where snmpwalk >nul 2>&1 && snmpwalk -v2c -c public %TARGET% || true
where curl >nul 2>&1 && curl -I http://%TARGET% > curl_head.out 2>nul || true
where nikto >nul 2>&1 && nikto -h http://%TARGET% -o nikto.out || true
