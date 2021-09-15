# Getting the projet details and finding zone.
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
# gcloud compute instances add-metadata  $env:COMPUTERNAME  --metadata=enable-wsfc="true" --zone=$zone

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.iscsiReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}

# Check if machine is domain joined. If yes then exit and do nothing.
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
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    $Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:COMPUTERNAME -EA Stop | ? {$_.IPEnabled}
    $netmask  = $Network.IPSubnet[1]
    $static_ip = Get-NetIPAddress | Where-Object -FilterScript { $_.ValidLifetime -Lt ([TimeSpan]::FromDays(1)) } | Select-Object -ExpandProperty IPAddress
    $gateway = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop
    start-sleep -s 10
    
    # Adding static IPs
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
    
    # Join machine to domain
    Add-Computer -DomainName $domain -Credential $cred

    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Failover Cluster Tool
    Install-WindowsFeature Failover-Clustering -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation
    
    # Install Chrome Browser
    # function Set-ChromeAsDefaultBrowser {
    #     Add-Type -AssemblyName 'System.Windows.Forms'
    #     Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
    #     Sleep 2
    #     [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
    # } 
    # Set-ChromeAsDefaultBrowser


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

Import-Module ActiveDirectory
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword an_group
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword an_group

#Windows firewall rule for PI Integrator
netsh advfirewall firewall add rule name="PI Integrator 444" dir=in action=allow protocol=TCP localport=444

###### Loadbalancer frontend deletion

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

# $region = $zone.Substring(0,$zone.Length-2)
# $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
# $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
# $password1 = [string]::join("",($password1.Split("`n")))
# $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
# $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
# $username = "$domain\setupadmin"
# $cred = New-Object System.Management.Automation.PSCredential($username,$password)
# $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

# $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
# $node1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an1)' --zone $zone
# $node2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone
# $nameWSFC = "win-clus" 
# $ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
# $TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
# $InitiatorPortalAddress = $node1
# $IPClusRole1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole1)' --zone $zone
# $IPClusRole2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole2)' --zone $zone
# $afserver = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af2)' --zone $zone

# $ipWSFC1 = [string]$ipWSFC1
# $IPClusRole1 = [string]$IPClusRole1
# $IPClusRole2 = [string]$IPClusRole2

# $target1 = @( $ipWSFC1, $IPClusRole1 ,$IPClusRole2)
# $i=1

# foreach ($x in $target1)
#     {
#     $name="fwd-ani-$i"  
#     gcloud compute forwarding-rules delete $name --region=$region --quiet
#     Start-Sleep -s 20
#     $i++
#     }


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


if($zone -eq $zone1){
    while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.an2Ready)' --zone $zone1)){
        Start-Sleep -s 10
    }
}

Set-Location D:\temp
$cmd = .\PI-Server_2018-SP3-Patch-3_.exe /passive ADDLOCAL=PINotificationsService,PIAnalysisService,FD_AFExplorer,FD_AFAnalysisMgmt,FD_AFDocs,PiPowerShell   AFSERVER="$afserver" SENDTELEMETRY="1" AFACKNOWLEDGEBACKUP="1" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername" PIANALYSIS_SERVICEACCOUNT="$analysis_svc" PINOTIFICATIONS_SMTPSERVER="dummy" PINOTIFICATIONS_FROMEMAIL="dummy@osi.com" PINOTIFICATIONS_SERVICEACCOUNT="$notification_svc"
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


##################Integrator installation steps##########################

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

# Get storage bucket name to where piserver executables are present
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

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

#Run cluster scripton node2
$node2 = gcloud compute instances describe pibastion1 --format='value[](metadata.items.an2Name)' --zone $zone
Invoke-Command -FilePath D:\temp\win-clus2-installer.ps1 -ComputerName $node2
Start-sleep -S 60


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

while(!($flag =gsutil stat gs://$storage/collective_success.txt))
    {
        Start-Sleep -s 10
    }

if($zone -eq $zone1){
    $cmd = D:\temp\win-clus1-installer.ps1
    $cmd
    Start-sleep -s 180
}

$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
Rundll32 iesetup.dll, IEHardenLMSettings
Rundll32 iesetup.dll, IEHardenUser
Rundll32 iesetup.dll, IEHardenAdmin
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled."

get-service "PIAnalysisManager" | Where {$_.Status -ne 'Running'} | start-service
get-service "PINotificationsService" | Where {$_.Status -ne 'Running'} | start-service
get-service "PIINTEGRATOR" | Where {$_.Status -ne 'Running'} | start-service

while(!($flag =gsutil stat gs://$storage/intdb_success.txt))
    {
        Start-Sleep -s 5
    }
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

Import-Module ActiveDirectory
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword an_group
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword an_group
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$region = $zone.Substring(0,$zone.Length-2)

$names = gcloud compute instances list --filter pisvr* --format="value(name)"
$piclient_32 = @"
[APIBUFFER]
BUFFERING=1
BUF1SIZE=2000000
BUF2SIZE=2000000
FILEBUFPATH=C:\Program Files (x86)\PIPC\dat
[PIBUFSS]
Buffering=1
[BUFFEREDSERVERLIST]
BUFSERV1=$($names[0])
BUFSERV2=$($names[1])
"@
$piclient_32 | Out-File 'C:\Program Files (x86)\PIPC\dat\piclient.ini' 
$piclient_64 = @"
[PISERVER]
LONGPROCNAME=0
[APIBUFFER]
BUFFERING=1
BUF1SIZE=2000000
BUF2SIZE=2000000
FILEBUFPATH=C:\Program Files (x86)\PIPC\dat
[PIBUFSS]
Buffering=1
[BUFFEREDSERVERLIST]
BUFSERV1=$($names[0])
BUFSERV2=$($names[1])
"@
$piclient_64 | Out-File 'C:\Program Files\PIPC\dat\piclient.ini' 
New-Item 'C:\ProgramData\OSIsoft\Buffering\pibufcfg.xml' -ItemType File
Set-Content 'C:\ProgramData\OSIsoft\Buffering\pibufcfg.xml' '<?xml version="1.0" encoding="utf-8"?>
<BufferingConfiguration xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <Version>1</Version>
  <globalConfig>
    <defaultPhysicalSrvConfig>
      <queuePath>C:\ProgramData\OSIsoft\Buffering</queuePath>
    </defaultPhysicalSrvConfig>
  </globalConfig>
</BufferingConfiguration>'
cmd /c SC CONFIG PIAnalysisManager depend=pibufss


$svcs = @('pibufss')
$gMSA = "$domain\ds-pibufss-svc$"
foreach($svc in $svcs){
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$svc'"
    $service.Change($null, $null, $null, $null, $null, $null, $gMSA, $null, $null, $null, $null)
}

$piservices = @('pibufss','PIAnalysisManager')
foreach ($piservice in $piservices){
    get-service "$piservice" | Restart-Service -Force
}

Start-sleep -s 180

Write-Host "Out of sleep. Creating Collective_Success.txt file"
#Create sucess file flag for AF server
New-Item D:\temp\buff_success.txt
gsutil cp D:\temp\buff_success.txt gs://$storage/buff_success.txt

$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument  "D:\temp\collective_trigger.ps1"
Register-ScheduledTask -TaskName "collect_trigger" -Trigger $Trigger -User $username -Password $password1 -Action $Action -RunLevel Highest -Force
Restart-Computer
'@
$aninstall | out-file D:\temp\aninstall.ps1

$collective_trigger = @'
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

Set-Location D:\temp
$names = gcloud compute instances list --filter pisvr* --format="value(name)"
$af_path =  -join($names[0],'.',$domain)
Add-PIDataArchiveConnectionConfiguration -Name 'PIDA_Collective' -Path $af_path
$PIDataArchive = Get-PIDataArchiveConnectionConfiguration -Name 'PIDA_Collective' -ErrorAction Stop
Connect-PIDataArchive -PIDataArchiveConnectionConfiguration $PIDataArchive -ErrorAction Stop

Disable-ScheduledTask -TaskName "collect_trigger"
'@
$collective_trigger | Out-File D:\temp\collective_trigger.ps1  
 
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

# $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , "BUILTIN\Administrators"
# $sqlServer.AddToRole("sysadmin")

Start-Sleep -S 20

# $service_accounts = @('ds-pint-svc$', 'ds-pivs-svc$')
# foreach ($sa in $service_accounts){
#     $name = -join("$domain_trim","\",$sa)
#     $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , $name
#     $sqlServer.AddToRole("sysadmin")
#     $sqlServer.AddToRole("dbcreator")
#     $sqlServer.AddToRole("securityadmin")
# }



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
$Labels = @('DISK1','Disk2')

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
Set-NetTeredoConfiguration -Type Disabled
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

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$node1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an1)' --zone $zone
$node2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone
$nameWSFC = "win-clus" 
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
$TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
$InitiatorPortalAddress = $node1
$IPClusRole1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole1)' --zone $zone
$IPClusRole2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole2)' --zone $zone
$afserver = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af2)' --zone $zone

$ipWSFC1 = [string]$ipWSFC1
$IPClusRole1 = [string]$IPClusRole1
$IPClusRole2 = [string]$IPClusRole2

# $target1 = @( $ipWSFC1, $IPClusRole1 ,$IPClusRole2)
# $i=1

# foreach ($x in $target1)
#     {
#     $name="fwd-ani-$i"  
#     gcloud compute forwarding-rules delete $name --region=$region --quiet
#     Start-Sleep -s 20
#     $i++
#     }

New-Cluster -Name $nameWSFC -Node $node1, $node2 -NoStorage -StaticAddress $ipWSFC1 

Install-WindowsFeature -Name FS-Fileserver

Import-Module activedirectory

Start-Service -Name MSiSCSI
Set-Service -Name MSiSCSI -StartupType Automatic

New-IscsiTargetPortal -TargetPortalAddress "$TargetPortalAddress" -InitiatorPortalAddress "$InitiatorPortalAddress"  

Start-sleep -seconds 4

$targets = Get-IscsiTarget
foreach ($target in $targets)
    {
    Connect-IscsiTarget -IsMultipathEnabled $true -NodeAddress $target.NodeAddress -IsPersistent $true
    }

Start-Sleep -S 60

Get-ClusterAvailableDisk | Add-ClusterDisk

Set-ClusterQuorum -NodeAndDiskMajority "Cluster Disk 1"
Add-ClusterSharedVolume -Name "Cluster Disk 2"

New-Item -ItemType directory -Path C:\ClusterStorage\Volume1\OSIsoft\PIAnalysis
New-Item -ItemType directory -Path C:\ClusterStorage\Volume1\OSIsoft\PINotifications

$domain_arr = $domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)


$domain_trim = $domain.Substring(0,$domain.Length-4)
$clus_name = -join($domain_trim,"\",'win-clus$')
#Adding permissions to win-clus to create computer object for AnalysisCluster role
#should change
$user=[System.Security.Principal.NTAccount]$clus_name
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

Add-ClusterGenericServiceRole  -ServiceName "PIAnalysisManager" -CheckpointKey "SOFTWARE\PISystem\Analysis Service" -Name "AnalysisCluster" -StaticAddress $IPClusRole1 

Add-ClusterGenericServiceRole  -ServiceName "PINotificationsService"  -Name "NotifCluster" -StaticAddress $IPClusRole2 


$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\ss.ps1" 
Register-ScheduledTask -TaskName "ss-ins" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


'@
$iscsi_node1 | Out-File D:\temp\win-clus1-installer.ps1

$af_attr = @'

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

$TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
$InitiatorPortalAddress = $node1
$IPClusRole1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole1)' --zone $zone
$IPClusRole2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole2)' --zone $zone

$region = $zone.Substring(0,$zone.Length-2)
$smn = gcloud compute forwarding-rules describe fwd-pisvr-1 --region=$region --flatten=IPAddress
$ip = $smn[1].trim()
$afserver = $ip
$host1 = -join("AnalysisCluster",".",$domain)
$host2 = -join("NotifCluster",".",$domain)
Stop-ClusterGroup -Name AnalysisCluster
Stop-ClusterGroup -Name NotifCluster

$afserv = Get-AFServer -Name $afserver
$afdb = Get-AFDatabase -Name "configuration" -AFServer $afserv
$afElement = Get-AFElement -Name "OSISOFT" -AFDatabase $afdb

$afElement = Get-AFElement -Name "PIANO" -AFElement $afElement
$afElement = Get-AFElement -Name "AnalysisService" -AFElement $afElement
$afElement = Get-AFElement -Name "ServiceConfiguration" -AFElement $afElement
$afAttribute = Get-AFAttribute -Name "ServiceConfiguration" -AFElement $afElement 
$afAttribute.GetValue().value
$xml = @"
<?xml version="1.0" encoding="utf-16"?>
<ANServiceConfigurationDataContract xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/OSIsoft.AN.WCF">
  <CalculationEngineParameters>
    <AutoBackfillingEnabled>true</AutoBackfillingEnabled>
    <AutoRecalculationEnabled>true</AutoRecalculationEnabled>
    <AutoRecalculationIgnoreTimeInSeconds>30</AutoRecalculationIgnoreTimeInSeconds>
    <AutoRecalculationMinWaitTimeInSeconds>60</AutoRecalculationMinWaitTimeInSeconds>
    <CalculationWaitTimeInSeconds>5</CalculationWaitTimeInSeconds>
    <CreateFuturePIPointsForAmbiguousOutputTimes>true</CreateFuturePIPointsForAmbiguousOutputTimes>
    <DataCacheConfiguration>
      <CacheTimeSpanInMinutes>5</CacheTimeSpanInMinutes>
      <MaxCacheEventsPerAttribute>1024</MaxCacheEventsPerAttribute>
      <MinCacheEventsPerAttribute>1</MinCacheEventsPerAttribute>
      <NumberParallelDataPipes>1</NumberParallelDataPipes>
    </DataCacheConfiguration>
    <DataWriterConfiguration>
      <NumberDataWriterThreads>1</NumberDataWriterThreads>
    </DataWriterConfiguration>
    <EvaluationPartitionSize>10000</EvaluationPartitionSize>
    <LoadSheddingParameters>
      <EvaluationsToQueueBeforeSkipping>50</EvaluationsToQueueBeforeSkipping>
      <LoadSheddingEnabled>true</LoadSheddingEnabled>
    </LoadSheddingParameters>
    <MaxAllowedAutoRecalculationSpanInDays>180</MaxAllowedAutoRecalculationSpanInDays>
    <NumberEvaluationThreads>2</NumberEvaluationThreads>
  </CalculationEngineParameters>
  <CommonParameters>
    <RuntimeStorageFolderPath>C:\ClusterStorage\Volume1\OSIsoft\PIAnalysis</RuntimeStorageFolderPath>
  </CommonParameters>
  <IsTelemetryAllowed>true</IsTelemetryAllowed>
  <RecalculationEngineParameters>
    <MaxConcurrentRecalculationRequests>1</MaxConcurrentRecalculationRequests>
    <MaximumAllowedAutoBackfillingSpanInHours>72</MaximumAllowedAutoBackfillingSpanInHours>
  </RecalculationEngineParameters>
  <RegisteredHosts>
    <ANRegisteredHostDataContract>
      <HostName>$host1</HostName>
    </ANRegisteredHostDataContract>
  </RegisteredHosts>
  <Version>1</Version>
</ANServiceConfigurationDataContract>
"@
Set-AFAttribute -AFAttribute $afAttribute -CheckIn -Value $xml
$afAttribute.GetValue().value



$afdb = Get-AFDatabase -Name "configuration" -AFServer $afserv
$afElement = Get-AFElement -Name "OSISOFT" -AFDatabase $afdb

$afElement = Get-AFElement -Name "PIANO" -AFElement $afElement
$afElement = Get-AFElement -Name "Notifications" -AFElement $afElement
$afElement = Get-AFElement -Name "Service" -AFElement $afElement
$afAttribute = Get-AFAttribute -Name "DataDirectory" -AFElement $afElement 

$ddr = @"
C:\ClusterStorage\Volume1\OSIsoft\PINotifications\Data
"@
Set-AFAttribute -AFAttribute $afAttribute -CheckIn -Value $ddr

$hsn = @"
{"HostName":"$host2"}
"@
$afAttribute = Get-AFAttribute -Name "Configuration" -AFElement $afElement
Set-AFAttribute -AFAttribute $afAttribute -CheckIn -Value $hsn

Start-ClusterGroup -Name AnalysisCluster 

Start-ClusterGroup -Name NotifCluster

Start-Sleep -s 60

############### Load balancer frontend

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

$region = $zone.Substring(0,$zone.Length-2)
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$node1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an1)' --zone $zone
$node2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone
$nameWSFC = "win-clus"
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone

$TargetPortalAddress = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.iscsi)' --zone $zone
$InitiatorPortalAddress = $node1
$IPClusRole1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole1)' --zone $zone
$IPClusRole2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.IPClusRole2)' --zone $zone

$afserver = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af2)' --zone $zone

$target1 = @( $ipWSFC1, $IPClusRole1 ,$IPClusRole2)

$i=1

foreach ($x in $target1)
    {
    $name="fwd-ani-$i"  
    gcloud compute forwarding-rules create $name --backend-service="bk-ani" --region=$region --load-balancing-scheme="INTERNAL" --ports="5463,5468" --service-label="ani" --subnet="osi-subnet-5" --address=$x --network="osi-vpc"
    Start-Sleep -s 20
    $i++
    }

New-Item -Path C:\complete.txt -ItemType file
gsutil -m cp c:\complete.txt gs://$storage/

Disable-ScheduledTask -TaskName "ss-ins"

'@
$af_attr| out-file D:\temp\ss.ps1

# Services to start if not already running after every boot
$services = @'
#Check if PI services are running. If not then start the services.
$piservices = @('pibufss','PIAnalysisManager','PINotificationsService','PIINTEGRATOR','PISYNCSERVICE','PIWORKERNODE1')
foreach ($piservice in $piservices){
    get-service "$piservice" | Where {$_.Status -ne 'Running'} | start-service
}

# $piservices = @('pibufss','PIAnalysisManager','PINotificationsService','PIINTEGRATOR','PISYNCSERVICE','PIWORKERNODE1')
# foreach ($piservice in $piservices){
#     get-service "$piservice" | Set-Service -StartupType Automatic
# } 
'@
$services | out-file D:\temp\services.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    #Schedule a task to check if pi services are running after every boot.
    Write-Host("Scheduling Services to restart")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\services.ps1" 
    Register-ScheduledTask -TaskName "services-restart-at-every-boot" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}