# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.iscsiReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}

$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $username = "$domain\setupadmin"
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

    $Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:COMPUTERNAME -EA Stop | ? {$_.IPEnabled}
    $netmask  = $Network.IPSubnet[1]
    $static_ip = Get-NetIPAddress | Where-Object -FilterScript { $_.ValidLifetime -Lt ([TimeSpan]::FromDays(1)) } | Select-Object -ExpandProperty IPAddress
    $gateway = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop
    start-sleep -s 10
    #####Add static IPs
    $dns_ips = Resolve-DnsName $domain | select -Property IPAddress
    $dns1 = $dns_ips.IPAddress.Split()[-1]
    $dns2 = $dns_ips.IPAddress.Split()[-2]

    netsh interface ip set address name=Ethernet static $static_ip $netmask $gateway 1
    $interface = (Get-NetAdapter).ifIndex
    Set-DnsClientServerAddress -InterfaceIndex $interface -ServerAddresses ("$dns1","$dns2")

    Get-Disk | Where partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false

    New-Item -Path 'D:\temp\' -ItemType Directory
    Set-Location -Path D:\temp\
    gsutil -m cp -r gs://$storage/piserver/* D:\temp\
    $location = Get-Location
    
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5457
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5463
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5468
    
    Add-Computer -DomainName $domain -Credential $cred
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools
    Install-WindowsFeature Failover-Clustering -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation
    
    # Install Chrome Browser
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    function Set-ChromeAsDefaultBrowser {
        Add-Type -AssemblyName 'System.Windows.Forms'
        Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
        Sleep 2
        [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
    } 
    Set-ChromeAsDefaultBrowser


    #Add setupadmin to local admin group
    $addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
    start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"
    
$gMSA = @'
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}
    
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
#$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"
    
Add-ADGroupMember -Identity an_group -Members $env:COMPUTERNAME$
Set-ADServiceAccount -Identity ds-pian-svc -PrincipalsAllowedToRetrieveManagedPassword an_group
Set-ADServiceAccount -Identity ds-pino-svc -PrincipalsAllowedToRetrieveManagedPassword an_group
Set-ADServiceAccount -Identity ds-pint-svc -PrincipalsAllowedToRetrieveManagedPassword an_group

#Windows firewall rule for PI Integrator
netsh advfirewall firewall add rule name="PI Integrator 444" dir=in action=allow protocol=TCP localport=444

Write-Host("Scheduling piserver Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\aninstall.ps1" 
Register-ScheduledTask -TaskName "an-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force
Disable-ScheduledTask -TaskName "gMSA-install"

Start-Sleep -Seconds 10
Restart-Computer -Force
'@
$gMSA | Out-File D:\temp\gMSA.ps1
    
$aninstall = @'
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone
$analysis_svc = "$domain\ds-pian-svc$"
$notification_svc = "$domain\ds-pino-svc$"

Set-Location D:\temp
$cmd = .\PI-Server_2018-SP3-Patch-1_.exe /passive ADDLOCAL=PINotificationsService,PIAnalysisService,FD_AFExplorer,FD_AFAnalysisMgmt,FD_AFDocs,PiPowerShell   AFSERVER="$afserver" SENDTELEMETRY="1" AFACKNOWLEDGEBACKUP="1" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername" PIANALYSIS_SERVICEACCOUNT="$analysis_svc" PINOTIFICATIONS_SMTPSERVER="dummy" PINOTIFICATIONS_FROMEMAIL="dummy@osi.com" PINOTIFICATIONS_SERVICEACCOUNT="$notification_svc"

Write-Host "Starting Piserver installation"
Start-Process powershell -Credential $cred -ArgumentList "-noexit -command (Invoke-Command -ScriptBlock {$cmd})"
Write-Host "Sleep-wait"
start-sleep -s 300
Write-Host "Out of sleep. Creating af_success.txt file"
#Create sucess file flag for AF server
New-Item D:\temp\an_success.txt
gsutil cp D:\temp\an_success.txt gs://$storage/an_success.txt

try{
    if($zone -eq $zone1){
        $zone -eq $zone1
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=an1Ready="True"
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=an1Name="$env:computername"
    }elseif($zone -eq $zone2){
        $zone -eq $zone2
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=an2Ready="True"
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=an2Name="$env:computername"
    }
}catch{
    $Error[0] | Out-Null
}

# Write-Host("Scheduling integrator Task")
# $Trigger= New-ScheduledTaskTrigger -AtStartup
# $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\integrator-install.ps1" 
# Register-ScheduledTask -TaskName "integrator-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

Disable-ScheduledTask -TaskName "an-install"
get-service "PIAnalysisManager" | Where {$_.Status -ne 'Running'} | start-service
get-service "PINotificationsService" | Where {$_.Status -ne 'Running'} | start-service
get-service "PIINTEGRATOR" | Where {$_.Status -ne 'Running'} | start-service

##################Integrator installation steps##########################

$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get storage bucket name to where piserver executables are present
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1

# Check if Integrator license/executable exists
$flag = gsutil stat gs://$storage/integrator/OSIsoft*

if ($flag){

$sqlserver = "sql-server"#gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone $zone
$integrator_svc = "$domain\ds-pint-svc$"
$domain_admin = "$domain\setupadmin"
                
Set-Location D:\temp

gsutil -m cp -r gs://$storage/integrator/* D:\temp\

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    
Expand-7Zip -ArchiveFileName .\OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe -TargetPath 'D:\temp\pi-integrator\'
Set-Location D:\temp\pi-integrator
    
$location = Get-Location
    
(Get-Content .\silent.ini) `
    | %{ $_ -replace "9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus.+","9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus SENDTELEMETRY=0 SERVICEACCOUNT=$integrator_svc AFSERVER=$afserver SQLSERVER=$sqlserver USERPORT=444 SQLHOSTNAME=$sqlserver"} `
    | Set-Content .\silent.ini
    
$cmd = .\Setup.exe -f .\silent.ini
Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
Start-sleep -s 300


$piservices = @('PISYNCSERVICE','PIWORKERNODE1', 'PIINTEGRATOR', 'PINotificationsService')
foreach ($piservice in $piservices){
    get-service "$piservice" | Restart-Service
}


#Create sucess file flag for integrator server
New-Item D:\temp\integrator_success.txt
gsutil cp D:\temp\integrator_success.txt gs://$storage/integrator_success.txt

}

Start-sleep -S 300
Invoke-Command -FilePath D:\temp\db.ps1 -ComputerName 'sql-server' 

#Disable-ScheduledTask -TaskName "integrator-install"

#Run cluster scrip ton node2
$node2 = gcloud compute instances describe pibastion1 --format='value[](metadata.items.an2Name)' --zone $zone1
Invoke-Command -FilePath D:\temp\win-clus2-installer.ps1 -ComputerName $node2
Start-sleep -S 60

$cmd = D:\temp\win-clus1-installer.ps1
$cmd
Start-sleep -s 180

Restart-Computer
'@
$aninstall | out-file D:\temp\aninstall.ps1

# $integrator = @'
# $project = gcloud config list --format=value'(core.project)'
# $zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
# $zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

# $data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
# $zone = $data.split()[1]

# if($zone -eq $zone1){
#     $zone -eq $zone1
# }elseif($zone -eq $zone2){
#     $zone -eq $zone2
# }

# $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
# $afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone
# $sqlserver = "sql-server"#gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone $zone
# $integrator_svc = "$domain\ds-pint-svc$"
# $domain_admin = "$domain\setupadmin"
                
# Set-Location D:\temp
# $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
# gsutil -m cp -r gs://$storage/pivision_integrator/* D:\temp\


# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Install-PackageProvider -Name NuGet -Force
# Set-PSRepository PSGallery -InstallationPolicy Trusted
# Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    
# Expand-7Zip -ArchiveFileName .\OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe -TargetPath 'D:\temp\pi-integrator\'
# Set-Location D:\temp\pi-integrator
    
# $location = Get-Location
    
# (Get-Content .\silent.ini) `
#     | %{ $_ -replace "9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus.+","9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus SENDTELEMETRY=0 SERVICEACCOUNT=$integrator_svc AFSERVER=$afserver SQLSERVER=$sqlserver USERPORT=444 SQLHOSTNAME=$sqlserver"} `
#     | Set-Content .\silent.ini
    
# $cmd = .\Setup.exe -f .\silent.ini
# Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
    
# #Create sucess file flag for integrator server
# New-Item D:\temp\integrator_success.txt
# gsutil cp D:\temp\integrator_success.txt gs://$storage/pivision_integrator/
    
# Disable-ScheduledTask -TaskName "integrator-install"
# '@
#     $integrator | Out-File D:\temp\integrator-install.ps1

 
$db = @'
# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Get bucket name where executables are stored.
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
    

$domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)
$name = -join("$domain_trim","\",'ds-pint-svc$')

Import-Module SqlServer
cd SQLSERVER:\SQL\localhost\default\

$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , "BUILTIN\Administrators"
$sqlServer.AddToRole("sysadmin")

Start-Sleep -S 20

$service_accounts = @('ds-pint-svc$')
foreach ($sa in $service_accounts){
    $name = -join("$domain_trim","\",$sa)
    $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , $name
    $sqlServer.AddToRole("sysadmin")
    $sqlServer.AddToRole("dbcreator")
    $sqlServer.AddToRole("securityadmin")
}



$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'sql-server'
$databases = @('PIIntegratorDB','PIIntegratorLogs','PIIntegratorStats')
foreach ($db in $databases){

    $database = $sqlServer.Databases[$db]
    
    $login = $sqlServer.Logins[$name]
    $dbUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.User -ArgumentList $database, $name
    $dbUser.Login = $name
    $dbUser.Create()
    $dbrole = $database.Roles['db_owner']
    $dbrole.AddMember($name)
    }


Start-Sleep -S 300

Remove-SqlLogin -LoginName "BUILTIN\Users" -Force 

New-Item -Path C:\db_success.txt -ItemType file
gsutil -m cp c:\db_success.txt gs://$storage/

'@
$db | Out-File D:\temp\db.ps1
 




$iscsi_node2 = @'
#######################################################
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}

$TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
$InitiatorPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone

Install-WindowsFeature -Name FS-Fileserver

Start-Service -Name MSiSCSI
Set-Service -Name MSiSCSI -StartupType Automatic

New-IscsiTargetPortal -TargetPortalAddress "$TargetPortalAddress" -InitiatorPortalAddress "$InitiatorPortalAddress"  #ip address of Iscsi vm

Start-sleep -seconds 4

$targets = Get-IscsiTarget
foreach ($target in $targets)
    {
    Connect-IscsiTarget -IsMultipathEnabled $true -NodeAddress $target.NodeAddress -IsPersistent $true
    }

$newdisk = @(Get-Disk | Where-Object partitionstyle -eq 'raw')
$Labels = @('DISK1','Disk2','Disk3')

for($i = 0; $i -lt $newdisk.Count ; $i++)
{

    $disknum = $newdisk[$i].Number
    $dl = get-Disk $disknum | 
       Initialize-Disk -PartitionStyle GPT -PassThru | 
          New-Partition -AssignDriveLetter -UseMaximumSize
    Format-Volume -driveletter $dl.Driveletter -FileSystem NTFS -NewFileSystemLabel $Labels[$i] -Confirm:$false

}
'@
    $iscsi_node2 | Out-File D:\temp\win-clus2-installer.ps1
    
$iscsi_node1 = @'
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$node1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an1)' --zone $zone
$node2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone
$nameWSFC = "win-clus" 
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
$ipWSFC2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC2)' --zone $zone
$TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
$InitiatorPortalAddress = $node1
$IPClusRole1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole1)' --zone $zone
$IPClusRole2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole2)' --zone $zone

New-Cluster -Name $nameWSFC -Node $node1, $node2 -NoStorage -StaticAddress $ipWSFC1, $ipWSFC2

Install-WindowsFeature -Name FS-Fileserver

Start-Service -Name MSiSCSI
Set-Service -Name MSiSCSI -StartupType Automatic

New-IscsiTargetPortal -TargetPortalAddress "$TargetPortalAddress" -InitiatorPortalAddress "$InitiatorPortalAddress"  

Start-sleep -seconds 4

$targets = Get-IscsiTarget
foreach ($target in $targets)
    {
    Connect-IscsiTarget -IsMultipathEnabled $true -NodeAddress $target.NodeAddress -IsPersistent $true
    }
Get-ClusterAvailableDisk | Add-ClusterDisk

Set-ClusterQuorum -DiskWitness "Cluster Disk 1"

Add-ClusterSharedVolume -Name "Cluster Disk 2"

New-Item -ItemType directory -Path C:\ClusterStorage\Volume1\OSIsoft\PIAnalysis

$domain_arr = $domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

#Adding permissions to win-clus to create computer object for AnalysisCluster role
$user=[System.Security.Principal.NTAccount]'$domain\win-clus$'
$compPath="AD:\OU=Computers,OU=Cloud,$domainPath"
$compPath
$acl= Get-Acl $compPath
$acl
$ace=New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
$User,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl $compPath $acl

Add-ClusterGenericServiceRole  -ServiceName "PIAnalysisManager" -Storage "Cluster Disk 3" -CheckpointKey "SOFTWARE\PISystem\Analysis Service" -Name "AnalysisCluster" -StaticAddress $IPClusRole1, $IPClusRole2
'@
    $iscsi_node1 | Out-File D:\temp\win-clus1-installer.ps1
    

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force
    Restart-Computer
}
