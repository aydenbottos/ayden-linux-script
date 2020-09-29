echo "Made by Ellie"
@ECHO OFF

::Get current  directory
set path=%~dp0
echo %path%output> "%path%resources\path.txt"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v "PowerShellVersion" /z >nul
If %ERRORLEVEL% == 1 (
	echo Powershell not installed, please install and try again.
	pause>nul
	exit
)
:: Get names of users on computer
echo Users and Administrators output to %path%output\users.txt
start C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe "%path%resources\usrList.ps1"
color 01

::This batch file is designed to aid in solving Windows images.
::Section 1: UserAccounts
echo "Here is a list of usernames and passwords."
rundll32.exe keymgr.dll,KRShowKeyMgr

::AddingPasswords
echo "Now add passwords to users without one"
set /P name="What user would you like to add a password to? "
echo "The password will be set to CyberTaipan123!."
net user %name% CyberTaipan123!
echo "would you like to add another password? "
set /P answer=Please choose yes or no:
if "%answer%"=="Yes" goto  AddingPasswords
if "%answer%"=="No" goto UserRights


::UserRights
echo Installing ntrights.exe to C:\Windows\System32
copy %path%resources\ntrights.exe C:\Windows\System32
if exist C:\Windows\System32\ntrights.exe (
	echo Installation succeeded, managing user rights..
	set remove=("Backup Operators" "Everyone" "Power Users" "Users" "NETWORK SERVICE" "LOCAL SERVICE" "Remote Desktop User" "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
set bad=( "ANONOYMOUS LOGON" "Guest" "Performance Log Users")
	for %%a in (%remove%) do (
			ntrights -U %%a -R SeIncreaseQuotaPrivilege
			ntrights -U %%a -R SeRemoteInteractiveLogonRight
			ntrights -U %%a -R SeSystemtimePrivilege
			ntrights -U %%a +R SeDenyNetworkLogonRight
			ntrights -U %%a -R SeProfileSingleProcessPrivilege
			ntrights -U %%a -R SeBatchLogonRight
			ntrights -U %%a -R SeUndockPrivilege
			ntrights -U %%a -R SeRestorePrivilege
			ntrights -U %%a -R SeShutdownPrivilege
		)
for %%a in (%bad%) do (
			ntrights -U %%a -R SeNetworkLogonRight 
			ntrights -U %%a -R SeIncreaseQuotaPrivilege
			ntrights -U %%a -R SeInteractiveLogonRight
			ntrights -U %%a -R SeRemoteInteractiveLogonRight
			ntrights -U %%a -R SeSystemtimePrivilege
			ntrights -U %%a +R SeDenyNetworkLogonRight
			ntrights -U %%a +R SeDenyRemoteInteractiveLogonRight
			ntrights -U %%a -R SeProfileSingleProcessPrivilege
			ntrights -U %%a -R SeBatchLogonRight
			ntrights -U %%a -R SeUndockPrivilege
			ntrights -U %%a -R SeRestorePrivilege
			ntrights -U %%a -R SeShutdownPrivilege
		)
		ntrights -U "Administrators" -R SeImpersonatePrivilege
		ntrights -U "Administrator" -R SeImpersonatePrivilege
		ntrights -U "Administrator" -R SeSystemTimePrivilege
		ntrights -U "SERVICE" -R SeImpersonatePrivilege
		ntrights -U "LOCAL SERVICE" +R SeImpersonatePrivilege
		ntrights -U "NETWORK SERVICE" +R SeImpersonatePrivilege
		ntrights -U "Administrators" +R SeMachineAccountPrivilege
		ntrights -U "Administrator" +R SeMachineAccountPrivilege
		ntrights -U "Administrators" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrator" -R SeIncreaseQuotaPrivilege
		ntrights -U "Administrators" -R SeDebugPrivilege
		ntrights -U "Administrator" -R SeDebugPrivilege
		ntrights -U "Administrators" +R SeLockMemoryPrivilege
		ntrights -U "Administrator" +R SeLockMemoryPrivilege
		ntrights -U "Administrators" -R SeBatchLogonRight
		ntrights -U "Administrator" -R SeBatchLogonRight
		echo Managed User Rights
)


::DeletingUsers
echo "would you like to delete a user? "
set /p answer=Please choose yes or no:
if "%answer%"=="yes" goto ::DeleteaUser
if "%answer%"=="no" goto ::AddingUsers

::DeleteaUser
set /P user="What User would you like to delete?"
// How can I get it so that user enters in the users password?//
net user %user%/DELETE

::AddingUsers
echo "would you like to add a user?"
set /p answer1=Please choose yes or no:
if "%answer1%"=="yes" goto ::AddingNewUser
if "%answer1%"=="no" goto ::DisableAccounts

::AddingNewUser
set /p username="What is the name of the user you would like to add?”
set /p pw="What is the password of the user you would like to add?”
Net user %username% %pw% /ADD
echo "would you like to add another user?"
set /p skip=Please choose yes or no:
if "%skip%"=="yes" goto ::AddingNewUser
if "%skip%"=="no" goto ::DisableAccounts

::DisableAccounts
net user guest /active:no
net user administrator /active:no

::PasswordSettings
"The Password Policies and Expiration will be changed"
wmic UserAccount set PasswordExpires=True
wmic UserAccount set PasswordChangeable=True
wmic UserAccount set PasswordRequired=True
net accounts /minpwlen:10
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /uniquepw:10

::Firewall
netsh advfirewall set allprofiles state on
echo Setting basic firewall rules..
REM Remote Desktop
sc stop “TermService”
sc config “TermService” start=disabled
sc stop “SessionEnv” 
sc config “SessionEnv” start=disabled
sc stop “UmRdpService”  
sc config “UmRdpService” start=disabled
sc stop “RemoteRegistry”  
sc config “RemoteRegistry” start=disabled
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no
reg add “HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server” /v fDenyTSConnections /t REG_DWORD /d 1 /f

:audit
echo Setting all audits.
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
echo Set auditing success and failure


::FTPSettings
net stop msftpsvc


::Malicious Files
dir /s /b C:\Users\*.midi > badfiles
del /s C:\Users\*.mid 
del /s C:\Users\*.mod 
del /s C:\Users\*.mp3 
del /s C:\Users\*.mp2 
del /s C:\Users\*.mpa 
del /s C:\Users\*.abs 
del /s C:\Users\*.mpega 
del /s C:\Users\*.au 
del /s C:\Users\*.snd 
del /s C:\Users\*.wav 
del /s C:\Users\*.aiff 
del /s C:\Users\*.aif 
del /s C:\Users\*.sid 
del /s C:\Users\*.flac 
del /s C:\Users\*.ogg 
del /s C:\Users\*.mpeg 
del /s C:\Users\*.mpg 
del /s C:\Users\*.mpe 
del /s C:\Users\*.dl 
del /s C:\Users\*.movie 
del /s C:\Users\*.movi 
del /s C:\Users\*.mv 
del /s C:\Users\*.iff 
del /s C:\Users\*.anim5 
del /s C:\Users\*.anim3 
del /s C:\Users\*.anim7 
del /s C:\Users\*.avi 
del /s C:\Users\*.vfw 
del /s C:\Users\*.avx 
del /s C:\Users\*.fli 
del /s C:\Users\*.flc 
del /s C:\Users\*.mov 
del /s C:\Users\*.qt 
del /s C:\Users\*.spl 
del /s C:\Users\*.swf 
del /s C:\Users\*.dcr 
del /s C:\Users\*.dir 
del /s C:\Users\*.dxr 
del /s C:\Users\*.rpm 
del /s C:\Users\*.rm 
del /s C:\Users\*.smi 
del /s C:\Users\*.ra 
del /s C:\Users\*.ram 
del /s C:\Users\*.rv 
del /s C:\Users\*.wmv 
del /s C:\Users\*.asf 
del /s C:\Users\*.asx 
del /s C:\Users\*.wma 
del /s C:\Users\*.wax 
del /s C:\Users\*.wmv 
del /s C:\Users\*.wmx 
del /s C:\Users\*.3gp 
del /s C:\Users\*.mov 
del /s C:\Users\*.mp4 
del /s C:\Users\*.avi 
del /s C:\Users\*.swf 
del /s C:\Users\*.flv 
del /s C:\Users\*.m4v 
del /s C:\Users\*.tiff 
del /s C:\Users\*.tif 
del /s C:\Users\*.rs 
del /s C:\Users\*.im1 
del /s C:\Users\*.gif 
del /s C:\Users\*.jpeg 
del /s C:\Users\*.jpg 
del /s C:\Users\*.jpe 
del /s C:\Users\*.png 
del /s C:\Users\*.rgb 
del /s C:\Users\*.xwd 
del /s C:\Users\*.xpm 
del /s C:\Users\*.ppm 
del /s C:\Users\*.pbm 
del /s C:\Users\*.pgm 
del /s C:\Users\*.pcx 
del /s C:\Users\*.ico 
del /s C:\Users\*.svg 
del /s C:\Users\*.svgz

::Services
sc stop TapiSrv
sc config TapiSrv start= disabled
sc stop TlntSvr
sc config TlntSvr start= disabled
sc stop ftpsvc
sc config ftpsvc start= disabled
sc stop SNMP
sc config SNMP start= disabled
sc stop SessionEnv
sc config SessionEnv start= disabled
sc stop TermService
sc config TermService start= disabled
sc stop UmRdpService
sc config UmRdpService start= disabled
sc stop SharedAccess
sc config SharedAccess start= disabled
sc stop remoteRegistry 
sc config remoteRegistry start= disabled
sc stop SSDPSRV
sc config SSDPSRV start= disabled
sc stop W3SVC
sc config W3SVC start= disabled
sc stop SNMPTRAP
sc config SNMPTRAP start= disabled
sc stop remoteAccess
sc config remoteAccess start= disabled
sc stop RpcSs
sc config RpcSs start= disabled
sc stop HomeGroupProvider
sc config HomeGroupProvider start= disabled
sc stop HomeGroupListener
sc config HomeGroupListener start= disabled

::AutomaticUpdates
reg add "HKLM\SOFTWARE\Microsoft\WINDOWS\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

::LSP
rem Restrict CD ROM drive
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
REM Automatic Admin logon
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
REM Logon message text
set /p body=Please enter logon text: 
    reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticetext" /v LegalNoticeText /t REG_SZ /d "%body%"

:WindowsServices
set servicesD=RemoteAccess Telephony TapiSrv Tlntsvr tlntsvr p2pimsvc simptcp fax msftpsvc iprip ftpsvc RemoteRegistry RasMan RasAuto seclogon MSFTPSVC W3SVC SMTPSVC Dfs TrkWks MSDTC DNS ERSVC NtFrs MSFtpsvc helpsvc HTTPFilter IISADMIN IsmServ WmdmPmSN Spooler RDSessMgr RPCLocator RsoPProv	ShellHWDetection ScardSvr Sacsvr TermService Uploadmgr VDS VSS WINS WinHttpAutoProxySvc SZCSVC CscService hidserv IPBusEnum PolicyAgent SCPolicySvc SharedAccess SSDPSRV Themes upnphost nfssvc nfsclnt MSSQLServerADHelper
set servicesM=dmserver SrvcSurg
set servicesG=Dhcp Dnscache NtLmSsp
echo Disabling bad services...
for %%a in (%servicesD%) do (
	echo Service: %%a
	sc stop "%%a"
	sc config "%%a" start= disabled
)
echo Disabled bad services
echo Setting services to manual...
for %%b in (%servicesM%) do (
	echo Service: %%b
	sc config "%%b" start= demand
)
echo Set services to manual
echo Seting services to auto...
for %%c in (%servicesG%) do (
	echo Service: %%c
	sc config "%%c" start= auto
)
echo Started auto services


:rdp
set /p rdpChk="Enable remote desktop (yes/no)"
if %rdpChk%==yes (
	echo Enabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=yes
	echo Please select "Allow connections only from computers running Remote Desktop with Network Level Authentication (more secure)"
	start SystemPropertiesRemote.exe /wait
	echo Enabled remote desktop
	goto:WindowsFeatures
)
if %rdpChk%==no (
	echo Disabling remote desktop...
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
	netsh advfirewall firewall set rule group="remote desktop" new enable=no
	echo Disabled remote desktop
	goto:WindowsFeatures
)
echo Invalid input %rdpChk%
goto rdp


::WindowsFeatures
echo Installing Dism.exe
copy %path%resources\Dism.exe C:\Windows\System32
xcopy %path%resources\Dism* C:\Windows\System32
echo Disabling Windows features...
set features=IIS-WebServerRole IIS-WebServer IIS-CommonHttpFeatures IIS-HttpErrors IIS-HttpRedirect IIS-ApplicationDevelopment IIS-NetFxExtensibility IIS-NetFxExtensibility45 IIS-HealthAndDiagnostics IIS-HttpLogging IIS-LoggingLibraries IIS-RequestMonitor IIS-HttpTracing IIS-Security IIS-URLAuthorization IIS-RequestFiltering IIS-IPSecurity IIS-Performance IIS-HttpCompressionDynamic IIS-WebServerManagementTools IIS-ManagementScriptingTools IIS-IIS6ManagementCompatibility IIS-Metabase IIS-HostableWebCore IIS-StaticContent IIS-DefaultDocument IIS-DirectoryBrowsing IIS-WebDAV IIS-WebSockets IIS-ApplicationInit IIS-ASPNET IIS-ASPNET45 IIS-ASP IIS-CGI IIS-ISAPIExtensions IIS-ISAPIFilter IIS-ServerSideIncludes IIS-CustomLogging IIS-BasicAuthentication IIS-HttpCompressionStatic IIS-ManagementConsole IIS-ManagementService IIS-WMICompatibility IIS-LegacyScripts IIS-LegacySnapIn IIS-FTPServer IIS-FTPSvc IIS-FTPExtensibility TFTP TelnetClient TelnetServer
for %%a in (%features%) do dism /online /disable-feature /featurename:%%a
echo Disabled Windows features


REM Logon Message Title Bar
set /p subject=Please enter the title of the message: 
reg ADD "HKLM\SYSTEM\microsoft\Windwos\CurrentVersion\Policies\System\legalnoticecaption" /v LegalNoticeCaption /t REG_SZ /d "%subject%"
    
REM Wipe page file from shutdown
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
    
REM Disallow remote access to floppy disks
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
    
REM Prevent print driver installs 
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
    
REM Limit local account use of blank passwords to console
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
rem Auditing access of Global System Objects
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v auditbaseobjects /t REG_DWORD /d 1 /f
rem Auditing Backup and Restore
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v fullprivilegeauditing /t REG_DWORD /d 1 /f
    
rem Do not display last user on logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
rem UAC setting (Prompt on Secure Desktop)
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
rem Enable Installer Detection
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
rem Undock without logon
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
    
rem Maximum Machine Password Age
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
    
rem Disable machine account password changes
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
    
rem Require Strong Session Key
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
    
rem Require Sign/Seal
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
    
rem Sign Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
    
rem Seal Channel
reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
    
rem Don't disable CTRL+ALT+DEL even though it serves no purpose
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f 
    
rem Restrict Anonymous Enumeration #1
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f 
    
rem Restrict Anonymous Enumeration #2
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f 
rem Idle Time Limit - 45 mins
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f 
rem Require Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f 
rem Enable Security Signature - Disabled pursuant to checklist
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f 
rem Disable Domain Credential Storage
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f 
rem Don't Give Anons Everyone Permissions   
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f 
rem SMB Passwords unencrypted to third party
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
rem Null Session Pipes Cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
rem remotely accessible registry paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
rem remotely accessible registry paths and sub-paths cleared
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
    
rem Restict anonymous access to named pipes and shares
reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
    
rem Allow to use Machine ID for NTLM
reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
rem Enables DEP
bcdedit.exe /set {current} nx AlwaysOn

REM Check For Updates
UsoClient ScanInstallWait

::Install Software
Set /p firefoxq=”Has firefox been installed (yes/no)?”
If %firefoxq% == no (
	Set urlfirefox=”https://support.mozilla.org/en-US/products/firefox/install-and-update-firefox”
	Start iexplore.exe %urlfirefox%
)
Set /p notepadq=”Has the latest version of notepad++ been installed (yes/no)?”
If %notepadq% == no (
	Set urlnotepad=”https://notepad-plus-plus.org/downloads/”
    Start firefox.exe %urlnotepad%
)
wmic useraccount where name='administrator' rename cyber
wmic useraccount where name='guest' rename taipan

echo "Thankyou for using this script"
