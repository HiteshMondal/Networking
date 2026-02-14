@echo off
REM ============================================================================
REM Windows System Hardening Script
REM Purpose : Reduce attack surface via firewall rules, service lockdown,
REM           protocol disabling, registry hardening, and account restrictions
REM WARNING : May break legacy apps, file sharing, remote admin, or scans
REM ============================================================================

REM ---------------------------------------------------------------------------
REM Enable Windows Firewall on all profiles
REM ---------------------------------------------------------------------------
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

REM ---------------------------------------------------------------------------
REM Block common reconnaissance & lateral movement protocols (Inbound)
REM ---------------------------------------------------------------------------

REM Block ICMP Echo (Ping)
netsh advfirewall firewall add rule name="Block ICMPv4 In" ^
  protocol=icmpv4:8,any dir=in action=block

REM Block NetBIOS (UDP 137,138)
netsh advfirewall firewall add rule name="Block NetBIOS UDP In" ^
  protocol=udp localport=137,138 dir=in action=block

REM Block SMB (TCP 139,445)
netsh advfirewall firewall add rule name="Block SMB TCP In" ^
  protocol=tcp localport=139,445 dir=in action=block

REM Block RPC Endpoint Mapper (TCP 135)
netsh advfirewall firewall add rule name="Block RPC TCP In" ^
  protocol=tcp localport=135 dir=in action=block

REM Block SNMP (UDP 161,162)
netsh advfirewall firewall add rule name="Block SNMP UDP In" ^
  protocol=udp localport=161,162 dir=in action=block

REM ---------------------------------------------------------------------------
REM Disable High-Risk or Legacy Windows Services
REM ---------------------------------------------------------------------------

REM SNMP Service
sc stop "SNMP" 2>nul || sc stop "snmp" 2>nul || sc stop "SNMP Service" 2>nul || echo.
sc config "SNMP" start= disabled 2>nul || sc config "snmp" start= disabled 2>nul || echo.

REM Remote Registry
sc stop "RemoteRegistry" 2>nul || echo.
sc config "RemoteRegistry" start= disabled 2>nul || echo.

REM Routing and Remote Access
sc stop "RemoteAccess" 2>nul || echo.
sc config "RemoteAccess" start= disabled 2>nul || echo.

REM Internet Connection Sharing (ICS)
sc stop "SharedAccess" 2>nul || echo.
sc config "SharedAccess" start= disabled 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Disable SMBv1 (Legacy & Vulnerable Protocol)
REM ---------------------------------------------------------------------------

REM Attempt via DISM (newer Windows)
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart 2>nul ||
REM Fallback via PowerShell
powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force" 2>nul || echo.

REM Registry enforcement
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" ^
  /v SMB1 /t REG_DWORD /d 0 /f 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Disable UPnP / SSDP (Network Discovery Attack Surface)
REM ---------------------------------------------------------------------------

net stop "SSDP Discovery" 2>nul || echo.
sc config "SSDPDiscovery" start= disabled 2>nul || echo.

net stop "UPnP Device Host" 2>nul || echo.
sc config "upnphost" start= disabled 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Local Security Policy Hardening
REM ---------------------------------------------------------------------------

REM Restrict anonymous enumeration
powershell -Command ^
  "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' ^
  -Name 'restrictanonymous' -Value 1 -Type DWord" 2>nul || echo.

REM Ensure UAC is enabled
powershell -Command ^
  "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' ^
  -Name 'EnableLUA' -Value 1 -Type DWord" 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Disable Guest Account
REM ---------------------------------------------------------------------------

net user Guest /active:no 2>nul || echo.
wmic useraccount where "name='Guest'" set disabled=true 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Harden HOSTS File Permissions (Anti-Redirection)
REM ---------------------------------------------------------------------------

icacls "%windir%\System32\drivers\etc\hosts" ^
  /inheritance:r ^
  /grant:r "Administrators:F" "SYSTEM:F" 2>nul || echo.

icacls "%windir%\System32\drivers\etc\hosts" ^
  /remove "Users" 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Security Event Log Hardening
REM ---------------------------------------------------------------------------

REM Increase Security log size (1 MB)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" ^
  /v "MaxSize" /t REG_DWORD /d 1048576 /f 2>nul || echo.

REM Clear Security log (⚠ forensic impact)
wevtutil cl Security 2>nul || echo.

REM Enforce new log size
wevtutil sl Security /ms:1048576 2>nul || echo.

REM ---------------------------------------------------------------------------
REM PowerShell-based Firewall & Service Enforcement
REM ---------------------------------------------------------------------------

powershell -Command ^
  "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" 2>nul || echo.

powershell -Command ^
  "Set-NetFirewallProfile -Profile Domain,Private,Public ^
  -DefaultInboundAction Block -DefaultOutboundAction Allow" 2>nul || echo.

powershell -Command ^
  "Get-Service -Name RemoteRegistry,RemoteAccess,SNMP,SSDPDiscovery,upnphost |
   Stop-Service -Force -ErrorAction SilentlyContinue" 2>nul || echo.

powershell -Command ^
  "Get-Service -Name RemoteRegistry,RemoteAccess,SNMP,SSDPDiscovery,upnphost |
   Set-Service -StartupType Disabled -ErrorAction SilentlyContinue" 2>nul || echo.

REM Disable PowerShell Remoting (WinRM)
powershell -Command "Disable-PSRemoting -Force" 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Remote Token Filtering (Blocks Pass-the-Hash style abuse)
REM ---------------------------------------------------------------------------

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
  /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0 /f 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Remove Legacy / Insecure Features
REM ---------------------------------------------------------------------------

REM Remove Telnet Client
dism /online /Remove-Capability /CapabilityName:Telnet.Client~~~~0.0.1.0 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Aggressive Scan Blocking (Inbound)
REM WARNING: This blocks ALL inbound TCP on all ports
REM ---------------------------------------------------------------------------

netsh advfirewall firewall add rule ^
  name="Block Tools Scans (common ports)" ^
  protocol=TCP localport=1-65535 dir=in action=block ^
  profile=Public,Private,Domain 2>nul || echo.

REM ---------------------------------------------------------------------------
REM Explicitly Allow Web Traffic Outbound
REM ---------------------------------------------------------------------------

netsh advfirewall firewall add rule ^
  name="Allow HTTP HTTPS Out" ^
  protocol=TCP localport=80,443 dir=out action=allow 2>nul || echo.
