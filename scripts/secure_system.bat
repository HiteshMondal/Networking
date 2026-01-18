@echo off
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
netsh advfirewall firewall add rule name="Block ICMPv4 In" protocol=icmpv4:8,any dir=in action=block
netsh advfirewall firewall add rule name="Block NetBIOS UDP In" protocol=udp localport=137,138 dir=in action=block
netsh advfirewall firewall add rule name="Block SMB TCP In" protocol=tcp localport=139,445 dir=in action=block
netsh advfirewall firewall add rule name="Block RPC TCP In" protocol=tcp localport=135 dir=in action=block
netsh advfirewall firewall add rule name="Block SNMP UDP In" protocol=udp localport=161,162 dir=in action=block
sc stop "SNMP" 2>nul || sc stop "snmp" 2>nul || sc stop "SNMP Service" 2>nul || echo.
sc config "SNMP" start= disabled 2>nul || sc config "snmp" start= disabled 2>nul || echo.
sc stop "RemoteRegistry" 2>nul || echo.
sc config "RemoteRegistry" start= disabled 2>nul || echo.
sc stop "RemoteAccess" 2>nul || echo.
sc config "RemoteAccess" start= disabled 2>nul || echo.
sc stop "SharedAccess" 2>nul || echo.
sc config "SharedAccess" start= disabled 2>nul || echo.
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart 2>nul || powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force" 2>nul || echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f 2>nul || echo.
net stop "SSDP Discovery" 2>nul || echo.
sc config "SSDPDiscovery" start= disabled 2>nul || echo.
net stop "UPnP Device Host" 2>nul || echo.
sc config "upnphost" start= disabled 2>nul || echo.
powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'restrictanonymous' -Value 1 -Type DWord" 2>nul || echo.
powershell -Command "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1 -Type DWord" 2>nul || echo.
net user Guest /active:no 2>nul || echo.
wmic useraccount where "name='Guest'" set disabled=true 2>nul || echo.
icacls "%windir%\System32\drivers\etc\hosts" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F" 2>nul || echo.
icacls "%windir%\System32\drivers\etc\hosts" /remove "Users" 2>nul || echo.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" /v "MaxSize" /t REG_DWORD /d 1048576 /f 2>nul || echo.
wevtutil cl Security 2>nul || echo.
wevtutil sl Security /ms:1048576 2>nul || echo.
powershell -Command "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" 2>nul || echo.
powershell -Command "Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow" 2>nul || echo.
powershell -Command "Get-Service -Name RemoteRegistry,RemoteAccess,SNMP,SSDPDiscovery,upnphost | Stop-Service -Force -ErrorAction SilentlyContinue" 2>nul || echo.
powershell -Command "Get-Service -Name RemoteRegistry,RemoteAccess,SNMP,SSDPDiscovery,upnphost | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue" 2>nul || echo.
powershell -Command "Disable-PSRemoting -Force" 2>nul || echo.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 0 /f 2>nul || echo.
dism /online /Remove-Capability /CapabilityName:Telnet.Client~~~~0.0.1.0 2>nul || echo.
netsh advfirewall firewall add rule name="Block Tools Scans (common ports)" protocol=TCP localport=1-65535 dir=in action=block profile=Public,Private,Domain 2>nul || echo.
netsh advfirewall firewall add rule name="Allow HTTP HTTPS Out" protocol=TCP localport=80,443 dir=out action=allow 2>nul || echo.
