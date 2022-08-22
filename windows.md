

<h1>Windows</h1>

```mermaid
%%{init: { 'theme':'white', 'htmlLabels': true} }%%
graph LR
    
windows{"<span style='white-space: normal;font-size:30px'>
	<b style='font-size:40px;'>Windows</b>
	</br></br></br></br></br></span>
	"}
windows --> w1[["<span style='white-space: normal;font-size:30px'>
								<b style='font-size:40px;'>Windows Information	</b>
								<br> 1-Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
								<br> 2-Systeminfo
								<br> 3-wmic os get version
								<br> 4-ver
								</br></br></br></br></br></span>
							"]]
windows --> w2[["<span style='white-space: normal;font-size:30px'>
						  <b style='font-size:40px;'>utilities		</b>													
						 <br>1-Remote Desktop RDP :mstsc.exe
						 </br></br></br></br></br></span>
									"]]
windows --> w3[["<span style='white-space: normal;font-size:30px'>
								<b style='font-size:40px;'>Permissions</b>
								</br></br></br></br></br></span>
								"]]
w3 --> wcommand31("
									<span style='white-space: normal;font-size:30px'>
									<b style='font-size:40px;'>ICACLS Tool For NTFS </b>
									</br></br></br></br></br></span>
									")
wcommand31 --> icacls1("<span style='white-space: normal;font-size:30px'>
											(CI): container inherit 
											</br>(OI): object inherit	
											</br>(IO): inherit only
											</br>(NP): do not propagate inherit
											</br>(I): permission inherited from parent container
											</br>----------------------
											</br>F : full access 
											</br>D :  delete access
											</br>N :  no access
											</br>M :  modify access
											</br>RX :  read and execute access
											</br>R :  read-only access
											</br>W :  write-only access
											</br>1-grant the joe user full control over the directory 
											</br>No Access over the user subdirectories : icacls c:\users /grant joe:f
											</br>2-revoked Permissions: icacls c:\users /remove joe
											</br>3-Remove inheritence : icacls folder /inheritance:d
											</br>4-enable inheritence : icacls folder /inheritance:e
											</br>5-Grant Permissions  : icacls folder /grant hr:(m,rx,RD,WDAC)
											</br>6-Options  : icacls RnD /grant everyone:R /t /c
											</br>/t parameter—Specifies a recursive operation
											</br>/c parameter—Specifies a continued operation despite any errors
											</br>7-ADVANCED Permissions : icacls RnD /grant:r Auditors:(WDAC) /t /c
											</br>example : icacls RnD /grant:r Auditors:(WDAC) /t /c 
											</br>advanced permissions need to be enclosed in parentheses
											</br>(REA) with (WDAC) write it as follows: Auditors:(WDAC,REA)
											</br>8-Interited Permissions
											</br>example : icacls RnD /grant:r Everyone:(OI)(CI)W /t
											</br>The /grant:r is pionting to old read ACE
											</br>we need to use both the OI and CI permissions together
											</br>9-Remove Permissions : icacls RnD\dir3 /remove:g Everyone /t /c
											</br>*the /remove:g parameter removes the grant permissions from the Everyone
											</br>*To remove the deny permissions : /remove:d
											</br>10-Deny Permissions : icacls D:\FileShare\HR /deny Developers:(OI)(CI)F /t /c
											</br>*denying permission overrides any permission explicitly granted to the same user or group
											</br>*To remove the deny permissions : /remove:d
											</br>11-Restting Permissions : icacls RnD /reset /t /c
											</br>12-View File Folder Ownership : dir /q
											</br>13-set ownership :icacls RnD /setowner Domain\Surender /t /c /
											</br>14-Exporting  ACL : icacls RnD /save rnd_acl_backup /t
											</br>15-importing an ACL  :icacls C:\ /restore rnd_acl_backup
											</br>*provide the path of the parent directory for the /restore parameter
											</br> Restore Acl With Substitute : icacls D:\ /restore file_share_acl /substitute John Mike /t /c /q
											</br>16-Determining user rights : icacls d:\ /findsid John /t
											</br>17-view the Mandatory Label:whoami /groups
											</br>18-set IL :icacls testDir /setintegritylevel h
											</br>*only accept l (for low), m (for medium), and h (for high) ILs
											</br>19-site :https://4sysops.com/archives/icacls-list-set-grant-remove-and-deny-permissions/
											</br></br></br></br></br></span>
											")



								

wcommand31 --> icacls2("<span style='white-space: normal;font-size:30px'>
										<b style='font-size:40px;'>icalcls on a folder that only gets created once a user signs</b>
										<br>@echo OFF
										<br>set folderpath=%LOCALAPPDATA%\YourFolder
										<br>:START
										<br>if not exist %folderpath% GOTO WAIT
										<br>GOTO PERM
										<br>:WAIT
										<br>timeout /t 2 /nobreak
										<br>GOTO START
										<br>:PERM
										<br>icacls %folderpath% /grant:r 'Authenticated Users':(OI)(CI)F /t /c 
										<br>Then use the task scheduler to start the batch script <br>based on a trigger when a match is found in audit logging. Checkout this article.
											</br></br></br></br></br></span>
											")


w3 --> wcommand32("<span style='white-space: normal;font-size:30px'>
										<b style='font-size:40px;'>Share Permissions</b>
										<br>1-Create Share :net share name='path' /grant:group,changeORreadORfull
										<br>2-use smbclient to Connect to the Share :smbclient -L IPaddressOfTarget -U htb-student
										<br>3-view all the shared folders : net share
										</br></br></br></br></br></span>
										")


windows --> w4[["<span style='white-space: normal;font-size:30px'>
									<b style='font-size:40px;'>Windows Defender</b>
									</br></br></br></br></br></span>
									"]]
w4--> wd1("<span style='white-space: normal;font-size:30px'>
					<b style='font-size:40px;'>stop windows defender :</b>
					 <br>1-sc stop WinDefend
					 <br>2-sc config WinDefend start= disabled 
					 <br>3-sc query WinDefend
					 	</br></br></br></br></br></span>
					 ")
w4--> wd2("<span style='white-space: normal;font-size:30px'>\
						<b style='font-size:40px;'>window Defender Tool CMD:</b>
					 <br>1-find the utility in %ProgramFiles%\Windows Defender\MpCmdRun.exe
					 <br>2-check for upadate :MpCmdRun -SignatureUpdate
					 <br>3-remove definitions ::MpCmdRun -RemoveDefinitions -DynamicSignaturesThe -DynamicSignatures
					 <br>4-scan:MpCmdRun -Scan -ScanType 1 (1 Quick scan2 Full scan 3 File and directory custom scan)
					 <br>5-boot sector malware scan :MpCmdRun -Scan -ScanType -BootSectorScan
					 <br>6-view quarantined items :MpCmdRun -Restore -ListAll
					 <br>7-restore quarantined items :MpCmdRun -Restore -All 
					 <br>8-restore quarantined items :MpCmdRun -Restore -Name ITEM-NAME -FilePath
				 	 <br>9-Exclution path : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
					 </br></br></br></br></br></span>
						")
w4--> wd3("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>Window Defender Tool powershell:</b>
					 <br>1-status of Microsoft Defender::Get-MpComputerStatus -Confirm the AntivirusEnabled is reads True
					 <br>2-check for upadate :Update-MpSignature
					 <br>3-offline virus scan :Start-MpWDOScan
					 <br>4-delete active threat:Remove-MpThreat
					 <br>5-list prefences :Get-MpPreference
					 <br>6-change preferences :Set-MpPreference -ExclusionPath
					 <br>7-exclude extenstion : Set-MpPreference -ExclusionExtension docx 
					 <br>8-remove prefence : Remove-MpPreference -ExclusionExtension EXTENSION
					 <br>9-set Quarantine time before deletion:Set-MpPreference -QuarantinePurgeItemsAfterDelay 30
					 <br>10-Schedule quick scan:Set-MpPreference -ScanScheduleQuickScanTime 06:00:00
					 <br>Schedule Full Scan 
					 <br>1-Set-MpPreference -ScanParameters 2
					 <br>2-Set-MpPreference -RemediationScheduleDay SCAN-DAY (0–Everyday 1–Sunday 2-Monday 3–Tuesday 4–Wednesday 5–Thursday 6–Friday 7–Saturday 8–Never)
					 <br>3-Set-MpPreference -RemediationScheduleTime SCAN-TIME
					 <br>11- Disable Window Defender :Set-MpPreference -DisableRealtimeMonitoring $true
					 <br>12-Enable external drive scanning :Set-MpPreference -DisableRemovableDriveScanning $false
					 <br>13-Enable network drive scanning : set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
					 <br>12-disable archive scanning :Set-MpPreference -DisableArchiveScanning $true
					 <br>13-add exclution :powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath 'C:\Windows\SysWOW64\Mpk'
					 <br>14-Unistall Window Defender :Uninstall-WindowsFeature -Name Windows-Defender
					</br></br></br></br></br></span>
						")
windows--> wd4("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>Windows Logs PowerShell:</b>
					 <br>1-<b>listing Logs</b> : Get-WinEvent -ListLog *
					 <br>2-command :Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize
					 <br>3-information : All logs post-Windows Vista save as *.evtx 	
					 <br>4-List Sources : Get-WinEvent -ListProvider * | Format-Table -Autosize
					 <br>5-term 'powershell' in the path: Get-WinEvent -ListLog *powershell*
					 <br>6-list all events from the PowerShell:Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational'
					 <br>7-displaying it one page at a time:Get-WinEvent -LogName 'System' | Out-Host -Paging
					 <br>8-most recent events :Get-WinEvent -LogName 'System' -MaxEvents 20
					 <br>9-Events with a specific ID: Get-WinEvent -FilterHashTable @{LogName='System';ID='1020'}
					 <br>Events :LogAlways 0 -Critical 1 -Error 2 -Warning 3 -Informational 4 -Verbose 5
					 <br>10-Maching 2 Levels :Get-WinEvent -FilterHashtable @{LogName='system'} | Where-Object -FilterScript {($_.Level -eq 2) -or ($_.Level -eq 3)}
					 <br>11-displays all audit failure events from the Security:Get-WinEvent -FilterHashtable @{LogName='Security';Keywords='4503599627370496'} 
					 <br>*Failure Audit 4503599627370496 *Success audit 9007199254740992
					 <br>12-messages containing specific words:Get-WinEvent -FilterHashtable @{LogName='System'} | Where-Object -Property Message -Match 'the system has resumed'
					 <br>13-Filter by date:Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$StartTime;EndTime=$EndTime}
					 <br>14-list without detials :Get-WinEvent -FilterHashtable @{LogName='Security''} | Format-Table -Property RecordId,TimeCreated,ID,LevelDisplayName,Message
					 <br>15-one event : Get-WinEvent -FilterHashtable @{LogName='Security'} |Where-Object ‑Property RecordId -eq 810
					 </br></br></br></br></br></span>
						")
windows--> wd5("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>Services And Processes</b>
					 <br>1-list services :get-service -property *
					 <br>2-extract properties : get-service | get-member
					 <br>3-example: get-service -DisplayName 'windows a*'
					 <br>4-remote :  get-service spooler -ComputerName novo8
					 <br>5-stopped :get-service | where {$_.status -eq 'stopped'}
					 <br>6-group based on status: get-service | Group-Object -Property Status 
					 <br>7-stop service: stop-service lanmanserver -force –PassThru
					 <br>8-start service:start-service wuauserv -PassThru
					 <br>8-restart service:restart-service spooler -PassThru
					 <br>9-suspend : suspend-service o2flash -PassThru
					 <br>10-resume:resume-service o2flash -PassThru
					 <br>11-Remote Services :Invoke-Command {restart-service dns –passthru} –comp chi-dc03,chi-dc02,chi-dc01
					 <br>12-Setting Startup Type: set-service remoteregistry -StartupType Manual -WhatIf
					 <br>-----------------wmi-----------------
					 <br>1-list services : get-wmiobject win32_service | format-table
					 <br>2-search service: get-wmiobject win32_service -filter 'name='bits'' | Select *
					 <br>3-example:get-wmiobject win32_service -filter 'startmode='auto' AND state<>'Running''
					 <br>4-Get Account:get-wmiobject win32_service -comp chi-ex01 | group startname 
	`				 <br>5-Methods That i can  use  :get-wmiobject win32_service -filter 'name='lanmanserver'' | get-member -MemberType Method | Select name
					 <br>6-Changing Mode:get-wmiobject win32_service -filter 'name='spooler'' | Invoke-WmiMethod -Name ChangeStartMode -ArgumentList 'Manual' 
					 <br>7-set an initial password for system accounts :Get-CimInstance win32_service -filter 'name='yammmsvc'' | Invoke-CimMethod -Name Change -Arguments 									@{StartName='.\Jeff';StartPassword='P@ssw0rd'}
					 <br>8-site:https://4sysops.com/archives/managing-services-the-powershell-way-part-1/
					 <br>9-get non standard service : Get-WmiObject win32_service | where { $_.Caption -notmatch 'Windows' -and $_.PathName -notmatch 'Windows'  } 
					  <br>-----------------sc-----------------
						<br>1-show service : sc qc wuauserv
						<br>2-stop service : sc stop wuauserv
						<br>3-change service executable : sc config wuauserv binPath=C:\Winbows\Perfectlylegitprogram.exe
						<br>4-show permissions : sc sdshow wuauserv
						<br>5-show permissions :Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List
						<br>example :D: (A;;CCLCSWRPLORC;;;AU)
						<br>D: - the proceeding characters are DACL permissions
						<br>AU: - defines the security principal Authenticated Users
						<br>A;; - access is allowed
						<br>CC - SERVICE_QUERY_CONFIG is the full name, and it is a query to the service control manager (SCM) for the service configuration
						<br>LC - SERVICE_QUERY_STATUS is the full name, and it is a query to the service control manager (SCM) for the current status of the service
						<br>SW - SERVICE_ENUMERATE_DEPENDENTS is the full name, and it will enumerate a list of dependent services
						<br>RP - SERVICE_START is the full name, and it will start the service
						<br>LO - SERVICE_INTERROGATE is the full name, and it will query the service for its current status
						<br>RC - READ_CONTROL is the full name, and it will query the security descriptor of the service
						
					 </br></br></br></br></br></span>
						")
windows--> wd6("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'Wmi:</b>
						<br>WMI is a management technology that can be used for much more than reading system information<br> WMI enables you to run processes remotely, schedule 							tasks that have to start at particular times, <br>reboot computers remotely, read event logs, and find out which applications are installed on local and 							remote computers.
					 <br>1- Check if wmi Is Running: sc query winmgmt
					 <br>2-Start wmi Service :sc start winmgmt
					 <br>3-check if wmi enabled by firewall:netsh advfirewall firewall show rule name='windows management instrumentation (WMI-in)'
					 <br>4-enable by firewall :netsh advfirewall firewall set rule group='windows management instrumentation (wmi)' new enable=yes
					 <br>5-Getting detailed information with wmic :type wmic then : OS get /?.
					 <br>6-connect to several computers :/node:[computername] /user:[username] /password:[password]
					 <br>7-last booted :OS get LastBootUpTime.
					 <br>8-output as html : /format:htable
					 <br>9- read NIC properties remotly :wmic /node:192.168.23.214 NIC get description,macaddress
					 <br>10-Get the List of all Installed Applications in Windows : wmic product get name
					 <br>11-Count the number of Installed Updates in Windows :wmic qfe list | find /c /v ''
					 <br>12-Get the Total Number of CPU Cores in Windows:wmic cpu get numberofcores
					 <br>13-Process Id of a running program in Windows
					 <br>14-wmic process where ExecutablePath='C:\\windows\\system32\\notepad.exe' get ProcessId
					 <br>15-Get All the Users logged in to a Remote System
					 <br>16-wmic /node:192.168.27.103 /user:admin /password:pass123 computersystem get username
					 <br>17-Check all the logs related to Explorer:wmic ntevent where (message like '%explorer%') list brief
					 <br>18-get path for process :wmic process where 'name='chrome.exe'' get ProcessID, ExecutablePath
						 <br>19-Get the System Slot Status using wmic command :wmic systemslot get slotdesignation,currentusage,description,status
					 <br>20-System Sensor Status :wmic temperature get deviceid,name,status
					 <br>21- get sid of users :wmic useraccount get name,sid

					</br></br></br></br></br></span>
						")												
windows--> wd7("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>General Information:</b>
					 <br>1-<b>Powershell History File :</b> : %appdata%\Microsoft\Windows\PowerShell\PSReadLine
					 <br>2- Check if Powershell Is Admin: [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')
					 <br>3-execute command remotly :Invoke-Command -ComputerName Server01 {Restart-Service Spooler}
					 <br>4-get cmdlet properties get-service | get-member
					 <br>5-Count result Lines : .count
					 <br>6-search commands : get-command -noun keyword 
					 <br>7-important dirs 
					 <br>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
						<br>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
						<br>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
						<br>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
			  		</br></br></br></br></br></span>
						")
						
windows--> wd8("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>powershell:</b>
					 <br>1-Create msgbox :$wshell = new-object -COM 'Wscript.Shell' 
					 <br> $wshell.Popup($msg,15,'Service Aler',64) | Out-Null
					 <br>2-execution policy :Get-ExecutionPolicy -List
					 <br>3-change policy:Set-ExecutionPolicy Bypass -Scope Process
					 <br>4-run instance : Invoke-WmiMethod -Path win32_process -Name create -ArgumentList 'cmd /c cd ../../users/dell/desktop&&dir&&pause'
					 <br>5-search for word :findstr /si password *.xml *.ini *.txt 
					 <br>6-
					 <br>
					</br></br></br></br></br></span>
						")						
						
windows--> wd9("<span style='white-space: normal;font-size:30px'>
						<b style='font-size:40px;'>UAC:</b>
					 <br>1- disable : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System 
					 <br>*To completely disable User Account Control, simply change the value of the EnableLUA parameter to 0 (zero), 
					 <br>2- reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
					 <br>3-New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
					 <br>4-
					 <br>5-
					 <br>6-
					 <br>
					</br></br></br></br></br></span>
						")						
					
						
classDef default text-align:left,font-size:30px;
linkStyle default fill:none,stroke-width:3px,stroke:red;


```



