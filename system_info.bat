@echo off
echo ===================== SYSTEM & OS INFO =====================
systeminfo
echo.

echo ===================== HOSTNAME & USER =====================
hostname
whoami
echo.

echo ===================== CPU INFO =====================
wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
echo.

echo ===================== MEMORY INFO =====================
wmic memorychip get Capacity,Manufacturer,Speed,PartNumber
systeminfo | find "Total Physical Memory"
echo.

echo ===================== DISK INFO =====================
wmic diskdrive get Model,Name,InterfaceType,MediaType,Size
echo.
wmic logicaldisk get DeviceID,VolumeName,FileSystem,Size,FreeSpace
echo.

echo ===================== BIOS & MOTHERBOARD =====================
wmic bios get Manufacturer,Name,Version,SerialNumber
wmic baseboard get Manufacturer,Product,SerialNumber
echo.

echo ===================== NETWORK ADAPTERS =====================
ipconfig /all
echo.

echo ===================== ACTIVE NETWORK CONNECTIONS =====================
netstat -ano
echo.

echo ===================== ROUTING TABLE =====================
route print
echo.

echo ===================== ARP TABLE =====================
arp -a
echo.

echo ===================== DNS CONFIGURATION =====================
nslookup google.com
echo.

echo ===================== NETWORK INTERFACES (Advanced) =====================
powershell -Command "Get-NetAdapter | Format-Table -AutoSize"
echo.

echo ===================== IP CONFIGURATION =====================
powershell -Command "Get-NetIPConfiguration | Format-List"
echo.

echo ===================== WIRELESS INFO =====================
netsh wlan show interfaces
netsh wlan show networks
echo.

echo ===================== DRIVERS & DEVICES =====================
driverquery /FO table
echo.

echo ===================== GPU INFO =====================
wmic path win32_videocontroller get name,driverversion
echo.

echo ===================== RUNNING PROCESSES =====================
tasklist
echo.

echo ===================== TOP NETWORK PROCESSES =====================
powershell -Command "Get-NetTCPConnection | Group-Object -Property OwningProcess | Sort Count -Descending | Select -First 10 | ForEach-Object { $_.Group | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess }"
echo.

echo ===================== SYSTEM TEMPERATURE (if supported) =====================
powershell -Command "Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace root/wmi | ForEach-Object {($_.CurrentTemperature/10)-273.15}"
echo.

echo ===================== DONE =====================
pause
