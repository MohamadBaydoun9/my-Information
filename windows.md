# Windows
```mermaid
{{<mermaid align="left">}}
 graph LR
    
windows{Windows}
windows --> w1[[Windows Information]]
w1 --> wcommand11("1-Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber")
w1 --> wcommand12("2-Systeminfo")
w1 --> wcommand13("3-wmic os get version")
w1 --> wcommand14("4-ver")
windows --> w2[[utilities]]
w2 --> wcommand21("Remote Desktop RDP :mstsc.exe")
windows --> w3[[Permissions]]
w3 --> wcommand31("ICACLS Tool For NTFS ")
wcommand31 --> icacls1("(CI): container inherit </br>(OI): object inherit</br>(IO): inherit only</br>(NP): do not propagate inherit</br>(I): permission inherited from parent container")
wcommand31 --> icacls2("F : full access </br>D :  delete access</br>N :  no access</br>M :  modify access</br>RX :  read and execute access</br>R :  read-only access</br>W :  write-only access")
wcommand31 --> icacls3("icacls c:\users /grant joe:f <br> grant the joe user full control over the directory<br> but (oi) and (ci) were not included in the command,Then No Access over the user subdirectories <br>*These permissions can be revoked using the command: icacls c:\users /remove joe.")
wcommand31 --> icacls4("Remove inheritence :icacls folder /inheritance:d<br>enable inheritence :icacls folder /inheritance:e")
wcommand31 --> icacls5("Grant Permissions :icacls folder /grant hr:(m,rx,RD,WDAC)")
wcommand31 --> icacls6("icacls RnD /grant everyone:R /t /c
										granting read access to the special identity Everyone
										\n/t parameter—Specifies a recursive operation
										\n/c parameter—Specifies a continued operation despite any errors")
wcommand31 --> icacls7("# ADVANCED Permissions
										<br>icacls RnD /grant:r Auditors:(WDAC) /t /c
										<br>advanced permissions need to be enclosed in parentheses
										<br>(REA) with (WDAC) write it as follows: Auditors:(WDAC,REA)")
wcommand31 --> icacls8("Interited Permissions
										<br>icacls RnD /grant:r Everyone:(OI)(CI)W /t
										<br>The /grant:r is pionting to old read ACE
										<br>we need to use both the OI and CI permissions together.")
wcommand31 --> icacls9("Remove Permissions
										<br>icacls RnD\dir3 /inheritance:d /t /c
										<br>icacls RnD\dir3 /remove:g Everyone /t /c
										<br>In the first command, the /inheritance:d parameter disables the inheritance
										<br>the /remove:g parameter removes the grant permissions from the Everyone
										<br>To remove the deny permissions : /remove:d ")
wcommand31 --> icacls10("Deny Permissions
										<br>icacls D:\FileShare\HR /deny Developers:(OI)(CI)F /t /c
										<br>deny Full Control to the Developers group on the HR directory
										<br>denying permission overrides any permission explicitly granted to the same user or group		
										<br>To remove the deny permissions : /remove:d")
wcommand31 --> icacls11("Restting Permissions
										<br>icacls RnD /reset /t /c ")
wcommand31 --> icacls12("Ownership 
										<br>set ownership :icacls RnD /setowner Domain\Surender /t /c /q
										<br>View Ownership :dir /q ")
wcommand31 --> icacls13("Exporting and importing an ACL 
										<br>icacls RnD /save rnd_acl_backup /t
										<br>icacls C:\ /restore rnd_acl_backup
										<br>provide the path of the parent directory for the /restore parameter		
										<br>icacls D:\ /restore file_share_acl /substitute John Mike /t /c /q")								
wcommand31 --> icacls14("Determining user rights In Drive 
										<br>icacls d:\ /findsid John /t")
wcommand31 --> icacls15("ILS
										<br>view the Mandatory Label:whoami /groups
										<br>set IL :icacls testDir /setintegritylevel h
										<br>only accept l (for low), m (for medium), and h (for high) ILs")
wcommand31 --> icacls16("icalcls on a folder that only gets created once a user signs
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
										<br>Then use the task scheduler to start the batch script <br>based on a trigger when a match is found in audit logging. Checkout this article.")
wcommand31 --> icacls13("site :https://4sysops.com/archives/icacls-list-set-grant-remove-and-deny-permissions/")

w3 --> wcommand32("Share Permissions")
wcommand32 --> share1("net share name='path' /grant:group,changeORreadORfull")
wcommand32 --> share2("using smbclient to Connect to the Share :smbclient -L IPaddressOfTarget -U htb-student")
wcommand32 --> share3("The command allows us to view all the shared folders : net share")

windows --> w4[[Windows Defender]]
w4--> wd1("stop windows defender :
					 <br>1-sc stop WinDefend
					 <br>2-sc config WinDefend start= disabled 
					 <br>3-sc query WinDefend
					 <br>turn off the real-time protection of Windows
					 <br>1-Set-MpPreference -DisableRealtimeMonitoring $true
					 <br>2-Uninstall-WindowsFeature -Name Windows-Defender")
w4--> wd2("mpcmdrun.exe Tool CMD:
					 <br>1-find the utility in %ProgramFiles%\Windows Defender\MpCmdRun.exe
					 <br>2-check for upadate :MpCmdRun -SignatureUpdate
					 <br>3-remove definitions ::MpCmdRun -RemoveDefinitions -DynamicSignaturesThe -DynamicSignatures
					 <br>4-scan:MpCmdRun -Scan -ScanType 1 (1 Quick scan2 Full scan 3 File and directory custom scan)
					 <br>5-boot sector malware scan :MpCmdRun -Scan -ScanType -BootSectorScan
					 <br>6-view quarantined items :MpCmdRun -Restore -ListAll
					 <br>7-restore quarantined items :MpCmdRun -Restore -All 
					 <br>8-restore quarantined items :MpCmdRun -Restore -Name ITEM-NAME -FilePath
					 <br> add exclution :powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath 'C:\Windows\SysWOW64\Mpk'
					<br>Exclution path : HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths")
w4--> wd3("mpcmdrun.exe Tool powershell:
					 <br>1-status of Microsoft Defender::Get-MpComputerStatus -Confirm the AntivirusEnabled is reads True
					 <br>2-check for upadate :Update-MpSignature
					 <br>3-offline virus scan :Start-MpWDOScan
					 <br>4-delete active threat:Remove-MpThreat
					 <br>5-list prefences :Get-MpPreference
					 <br>6-change prefences :Set-MpPreference -ExclusionPath
					 <br>7-exclude extenstion : Set-MpPreference -ExclusionExtension docx 
					 <br>8-remove prefence : Remove-MpPreference -ExclusionExtension EXTENSION
					 <br>9-set Quarantine time before deletion:Set-MpPreference -QuarantinePurgeItemsAfterDelay 30
					 <br>10-Schedule quick scan:Set-MpPreference -ScanScheduleQuickScanTime 06:00:00
					 <br>Schedule Full Scan 
					 <br>1-Set-MpPreference -ScanParameters 2
					 <br>2-Set-MpPreference -RemediationScheduleDay SCAN-DAY (0 – Everyday1 – Sunday2 – Monday3 – Tuesday4 – Wednesday5 – Thursday6 – Friday7 – Saturday8 – Never)
					 <br>3-Set-MpPreference -RemediationScheduleTime SCAN-TIME
					 <br>11-Disable anti virus:Enter:Set-MpPreference -DisableRealtimeMonitoring $true
					 <br>12-Enable external drive scanning :Set-MpPreference -DisableRemovableDriveScanning $false
					 <br>13-Enable network drive scanning : set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $false
					 <br>12-disable archive scanning :Set-MpPreference -DisableArchiveScanning $true
")


```
