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

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.sql1Ready)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 10 sec"
    Start-Sleep -s 10
}

try{
    if (Get-ScheduledTask -taskname gMSA-install | ? state -eq Ready){
        write-host "Task is enable..will run now"
        Start-ScheduledTask -TaskName gMSA-install
    }else{
        throw "1"
    }
}catch{
   if ($_.Exception.Message -eq 1){
        "Schedule task not found/disabled"
    }
}

Write-Host "Checking doamin join"
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
   Write-Host ("Machine is domain joined...exiting")
}else{
    Write-Host "Machine is not domain joined, executing installation steps"

    # Read password from secret manager, remove whitespaces and extra characters 
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $username = "$domain\setupadmin"

    # Create credentials object 
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)

    # Get bucket name where executables are stored.
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

    # Preapre the extra disk for piserver installation
    Get-Disk | Where-object partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false


    # Create staging location for executables 
    New-Item -Path 'D:\temp\' -ItemType Directory
    Set-Location D:\temp\
    gsutil -m cp -r gs://$storage/piserver/* D:\temp\
    $location = Get-Location
    
    #Open firewall ports needed for communication between pi components
    netsh advfirewall firewall add rule name="Open port for af server inbound" dir=in action=allow protocol=TCP localport=5457
    netsh advfirewall firewall add rule name="Open port for af server inbound" dir=in action=allow protocol=TCP localport=5450
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5463
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5468
    
    netsh advfirewall firewall add rule name="Open port for outbound on the PISVR1" dir=out action=allow protocol=TCP localport=135
    netsh advfirewall firewall add rule name="Open port for inbound for PISVR2" dir=in action=allow protocol=TCP localport=445

   # Join machine to domain
   Add-Computer -DomainName $domain -Credential $cred
    
   # Install RSAT tools for AD management
   Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

   # Install Windows Identity Foundation 3.5 feature
   Install-WindowsFeature Windows-Identity-Foundation 
   
   # Install Chrome Browser
   $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
#    function Set-ChromeAsDefaultBrowser {
#        Add-Type -AssemblyName 'System.Windows.Forms'
#        Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
#        Sleep 2
#        [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
#    } 
#    Set-ChromeAsDefaultBrowser

   # Add setupadmin to local admin group
   $addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
   start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"

# Create gMSA.ps1 file to be executed by scheduler on the next boot.   
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

#AF piserver to piserver group
Add-ADGroupMember -Identity af_group -Members $env:COMPUTERNAME$

# Grant piserver_group to use service account
Set-ADServiceAccount -Identity ds-piaf-svc -PrincipalsAllowedToRetrieveManagedPassword af_group
Set-ADServiceAccount -Identity ds-pian-svc -PrincipalsAllowedToRetrieveManagedPassword af_group
Set-ADServiceAccount -Identity ds-pino-svc -PrincipalsAllowedToRetrieveManagedPassword af_group
Set-ADServiceAccount -Identity ds-pidas-svc -PrincipalsAllowedToRetrieveManagedPassword af_group
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword af_group

Invoke-Command -ComputerName sql-server -ScriptBlock{Add-LocalGroupMember -Group "AFServers" -Member "$domain\$env:computername$"}

# To create AFServer SPN in the “New-ADServiceAccount” command with the option “-ServicePrincipalNames 
$machine_domain = -join($env:computername,".",$domain)
setspn -s AFServer/$env:computername $domain\ds-piaf-svc$
setspn -s AFServer/$machine_domain $domain\ds-piaf-svc$ 


# Add piserver name to AFservers group present on the sql server. This is required as prerequisite
Invoke-Command -ComputerName sql-server -ScriptBlock{Add-LocalGroupMember -Group "AFServers" -Member "$domain\$env:computername$"}

# Scheudle piserver installation task which will run on the next boot 
Write-Host("Scheduling piserver Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\piserver.ps1" 
Register-ScheduledTask -TaskName "piserver-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


# Disable gMSA-install task.
Disable-ScheduledTask -TaskName "gMSA-install"
#To be changed
# Unregister-ScheduledTask -TaskName "gMSA-install" -Confirm:$false
Restart-Computer

Start-Sleep -Seconds 10
Restart-Computer -Force
'@
$gMSA | Out-File D:\temp\gMSA.ps1

$piserver = @'
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
    
Set-Location D:\temp\
$location = Get-Location

#to be changed
$sqlserver = "sql-server"#gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone us-central1-a


$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"

# Create credentials object 
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

# Variables for gMSA services
$afsvc = "$domain\ds-piaf-svc$"
$pidassvc = "$domain\ds-pidas-svc$"

$cmd = .\PI-Server_2018-SP3-Patch-1_.exe /passive ADDLOCAL=PIDataArchive,PITotal,FD_AppsServer,PiSqlDas.Rtqp,FD_AFExplorer,FD_AFAnalysisMgmt,FD_AFDocs,PiPowerShell,pismt3  `
PIHOME="D:\Program Files (x86)\PIPC" PIHOME64="D:\Program Files\PIPC" AFSERVER="$env:computername" SENDTELEMETRY="1" AFSERVICEACCOUNT="$afsvc" FDSQLDBNAME="PIFD" FDSQLDBSERVER="$sqlserver" `
AFACKNOWLEDGEBACKUP="1" PISQLDAS_SERVICEACCOUNT="$pidassvc" PI_LICDIR="$location\License" `
PI_INSTALLDIR="D:\Program Files\PI" PI_EVENTQUEUEDIR="D:\Program Files\PI\Queue" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername"

# Execuate piserver installation command with elavated privileges  
Write-Host "Starting Piserver installation"
Start-Process powershell -Credential $cred -ArgumentList "-noexit -command (Invoke-Command -ScriptBlock {$cmd})"
Write-Host "Sleep-wait"
start-sleep -s 540

# Restart pibuf service with pibuff gMSA account
$pibuff_svc = "pibufss"
$pibuff_gMSA = "$domain\ds-pibufss-svc$"
$service = Get-WmiObject -Class Win32_Service -Filter "Name='$pibuff_svc'"
$service.Change($null, $null, $null, $null, $null, $null, $pibuff_gMSA, $null, $null, $null, $null)
Write-Output "Restared "+$pibuff_svc+" with account "+$pibuff_gMSA
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

Write-Host "Out of sleep. Creating af_success.txt file"
#Create sucess file flag for AF server
New-Item D:\temp\af_success.txt
gsutil cp D:\temp\af_success.txt gs://$storage/af_success.txt

# Disable piserver-install as installation is done 
Disable-ScheduledTask -TaskName "piserver-install"
# Unregister-ScheduledTask -TaskName "piserver-install" -Confirm:$false

# Schedule task for configuration of pi identities
Write-Host("Scheduling PI identities Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\identities.ps1" 
Register-ScheduledTask -TaskName "identities-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

Restart-Computer

'@
$piserver | Out-File D:\temp\piserver.ps1    

$identities = @'
# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

#$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'
$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}

# Split domain to create correct OU path
$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

# Connect to pi data archive server
$PIDataArchive = Get-PIDataArchiveConnectionConfiguration -Default -ErrorAction Stop
$PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveConnectionConfiguration $PIDataArchive -ErrorAction Stop

# Adding remaining WIS Identities and setting PI Identities security options
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Points&Analysis Creator" -Description "Identity for PIACEService, PIAFService and users that can create and edit PI Points" -DisallowDelete
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Web Apps" -Description "Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler" -DisallowDelete
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Connector Relays" -Description "Identity for PI Connector Relays" -DisallowDelete

# Disabling PIWorld, pidemo and piusers
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PIWorld" -Enabled 0 -CanDelete 0 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0.
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "pidemo" -Enabled 0 -CanDelete 1 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "piusers" -Enabled 0 -CanDelete 0 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0

$RenameIdentity = @(
    @{ExistingName = "PIEngineers"; NewName = 'PI Buffers';},
    @{ExistingName = "PIOperators"; NewName = 'PI Interfaces' ;},
    @{ExistingName = "PISupervisors"; NewName = 'PI Users' ;}
)

for($i=0 ; $i -lt $RenameIdentity.length; $i++){
    $ExistingName = $RenameIdentity[$i]['ExistingName']
    $NewName = $RenameIdentity[$i]['NewName']
    Rename-PIIdentity -Connection $PIDataArchiveConnection -ExistingName "$ExistingName" -NewName "$NewName" -ErrorAction SilentlyContinue
}

# Adding remaining WIS Identities and setting PI Identities security options
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" -Description "Identity for PI Buffer Subsystem and PI Buffer Server" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0 
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" -Description "Identity for PI Interfaces" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" -Description "Identity for the users to get Read access on the PI Data Archive" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
 
$PISecurityGroups = @(
    @{Name = 'PIBuff'; Description = 'Identity for PI Buffer Subsystem and PI Buffer Server'; }#,
    @{Name = 'PIInterfacesADGroup'; Description = 'Identity for PI Interfaces'; },
    @{Name = 'PIUsersADGroup'; Description = 'Identity for the Read-only users'; },
    @{Name = 'PIPointsAnalysisCreatorADGroup'; Description = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'; }
    @{Name = 'PIWebAppsADGroup'; Description = 'Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler'; },
    @{Name = 'PIConnectorRelaysADGroup'; Description = 'Identity for PI Connector Relays'; },
    @{Name = 'PIDataCollectionManagersADGroup'; Description = 'Identity for PI Data Collection Managers'; }
)

for($i=0 ; $i -lt $PISecurityGroups.length; $i++){
    $name = $PISecurityGroups[$i]['Name']
    $description = $PISecurityGroups[$i]['Description']
    New-ADGroup -Name "$name" -SamAccountName "$name" -GroupCategory Security -GroupScope Global -Description "$description" -Path "OU=Computers,OU=Cloud,$domainPath"  
}

$PISecurityGroupsMap = @(
    @{Name = "BUILTIN\Administrators"; Identity = 'piadmins';},
    @{Name = "\Everyone"; Identity = 'piusers';},
    @{Name = "$domain\PIBuff"; Identity = 'PI Buffers';},
    @{Name = "$domain\PIInterfacesADGroup"; Identity = 'PI Interfaces' ;},
    @{Name = "$domain\PIUsersADGroup"; Identity = 'PI Users' ;},
    @{Name = "$domain\PIPointsAnalysisCreatorADGroup"; Identity = 'PI Points&Analysis Creator' ;}
    @{Name = "$domain\PIWebAppsADGroup"; Identity = 'PI Web Apps' ;},
    @{Name = "$domain\PIConnectorRelaysADGroup"; Identity = 'PI Connector Relays' ;},
    @{Name = "$domain\PIDataCollectionManagersADGroup"; Identity = 'PI Data Collection Managers' ;}
)

for($i=0 ; $i -lt $PISecurityGroupsMap.length; $i++){
    $name = $PISecurityGroupsMap[$i]['Name']
    $identity = $PISecurityGroupsMap[$i]['Identity']
    Add-PIMapping -Connection $PIDataArchiveConnection -Name "$name" -PrincipalName "$name" -Identity "$identity" -ErrorAction SilentlyContinue
}

# Editing the Security Databases according to KB00833
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIAFLINK" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIARCADMIN" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIARCDATA" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIAUDIT" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBACKUP" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBatch" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBATCHLEGACY" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PICampaign" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIDBSEC" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIDS" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Points&Analysis Creator: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIHeadingSets" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIMAPPING" -Security "piadmins: A(r,w) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIModules" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIMSGSS" -Security "piadmins: A(r,w) | PIWorld: A(r,w)| PI Users: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIPOINT" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Buffers: A(r,w) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIReplication" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITransferRecords" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITRUST" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITUNING" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIUSER" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue

#Add-ADGroupMember -Identity PIWebAppsADGroup -Members ds-pivs-svc$
#Create OMF_DB database
$hostname = "$env:computername"
$afServer = Get-AFServer -Name $hostname -ErrorAction Stop
$afConnection = Connect-AFServer -AFServer $afServer -ErrorAction Stop
Add-AFDatabase -Name OMF_DB -AFServer $afConnection    

# The PowerShell script to gMSA account ds-pibufss-svc$ to be member of local group “PI Buffer Writers” and “PI Buffering Administrators” on PISRV-1
Add-LocalGroupMember -Group "PI Buffer Writers" -Member "$domain\ds-pibufss-svc$" 
Add-LocalGroupMember -Group "PI Buffering Administrators" -Member "$domain\ds-pibufss-svc$" 


try{
    if($zone -eq $zone1){
        $zone -eq $zone1
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=af1Ready="True"
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=af1="$env:computername"
    }elseif($zone -eq $zone2){
        $zone -eq $zone2
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=af2Ready="True"
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=af2="$env:computername"
    }
}catch{
    $Error[0] | Out-Null
}

#Check if AF service is running. If not start the service
get-service "AFService" | Where {$_.Status -ne 'Running'} | start-service


##################### PI COLLECTIVE ##################### 

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
if($zone -eq $zone1){
 
    while(!($flag =gsutil stat gs://$storage/db_success.txt))
    {
        Start-Sleep -s 5
    }

    Start-Sleep -s 300

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

            
    $StartTime = $(get-date)
    $PICollectiveName = 'PIDA_Collective'
    $PIPrimaryName = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af1)' --zone $zone1
    $PISecondaryNames = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af2)' --zone $zone1
    $NumberOfArchivesToBackup = 1
    $BackupLocationOnPrimary = 'D:\Backup'
    $activity = "Creating Collective " + $PICollectiveName


    $status = "Connecting to server " + $PIPrimaryName
    Write-Progress -Activity $activity -Status $status

    $connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIPrimaryName -ErrorAction Stop

    [Version] $v395 = "3.4.395"
    [Version] $v410 = "3.4.410"
    [String] $firstPathArchiveSet1;
    $includeSet1 = $false

    Write-Progress -Activity $activity -Status "Getting primary archive"
    $archives = Get-PIArchiveInfo -Connection $connection
    $primaryArchive = $archives.ArchiveFileInfo[0].Path

    Start-Sleep -s 150
    Set-Location D:\temp\

    if ($connection.ServerVersion -ge $v410) {
        ###########################################################
        # Exchange public certificates between collective members #
        ###########################################################
        $storePath = 'OSIsoft LLC Certificates'
        .\SendPrimaryPublicCertToSecondaries.ps1 $PIPrimaryName $storePath $PISecondaryNames
        .\SendSecondaryPublicCertToPrimary.ps1 $PIPrimaryName $PISecondaryNames $storePath
    }

    #####################################################################
    # Verify primary name specified is not already part of a collective #
    #####################################################################
    if ($connection.CurrentRole.Type -ne "Unspecified") {
        Write-Host "Error:" $PIPrimaryName "is already part of a collective."
            
    }
        
    ###########################################
    # Write collective information to primary #
    ###########################################

    Write-Progress -Activity $activity -Status "Writing collective information to primary"
    $collective = New-PICollective -Name $PICollectiveName -Secondaries $PISecondaryNames -Connection $connection

    Start-Sleep -s 10

    $collective | Set-PICollectiveMember -Name $PISecondaryNames -Path $PISecondaryNames

    ####################################################
    # Get the PI directory for each of the secondaries #
    ####################################################

    $destinationPIPaths = @{}
    foreach ($secondary in $PISecondaryNames) {
        $session = New-PSSession -ComputerName $secondary -ErrorAction Stop -WarningAction Stop
        $destinationPIPaths.Add($secondary, (Invoke-Command -Session $session -ScriptBlock { (Get-ItemProperty (Get-Item HKLM:\Software\PISystem\PI).PSPath).InstallationPath } ))
        Remove-PSSession -Id $session.ID
    }

    ############################
    # Stop all the secondaries #
    ############################

    Write-Host "Stopping secondary Services"
    foreach ($secondary in $PISecondaryNames) {
        $status = "Stopping secondary node " + $secondary
        Write-Progress -Activity $activity -Status $status -CurrentOperation "Retrieving dependent services..."
        $pinetmgrService = Get-Service -Name "pinetmgr" -ComputerName $secondary
        $dependentServices = Get-Service -InputObject $pinetmgrService -DependentServices
        $index = 1
        foreach ($dependentService in $dependentServices) {
            if ($dependentService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                Write-Progress -Activity $activity -Status $status -CurrentOperation ("Stopping " + $dependentService.DisplayName) -PercentComplete (($index / ($dependentServices.Count + 1)) * 100)
                Stop-Service -InputObject $dependentService -Force -ErrorAction Stop -WarningAction SilentlyContinue
            }
            $index++
        }
        Write-Progress -Activity $activity -Status $status -CurrentOperation ("Stopping " + $pinetmgrService.Name) -PercentComplete 100
        Stop-Service -InputObject $pinetmgrService -Force -WarningAction SilentlyContinue -ErrorAction Stop
    }

    Start-Sleep -s 30

    ###########################
    # Flush the archive cache #
    ###########################

    Write-Host "Flushing the archive cache"
    Write-Progress -Activity $activity -Status ("Flushing archive cache on server " + $connection.Name)
    Clear-PIArchiveQueue -Connection $connection

    #########################
    # Backup Primary Server #
    #########################

    Write-Host "Backing up"
    $status = "Backing up PI Server " + $connection.Name
    Write-Progress -Activity $activity -Status $status -CurrentOperation "Initializing..."
    Start-PIBackup -Connection $connection -BackupLocation $BackupLocationOnPrimary -Exclude pimsgss, SettingsAndTimeoutParameters -ErrorAction Stop
    $state = Get-PIBackupState -Connection $connection
    while ($state.IsInProgress -eq $true) {
        [int32]$pc = [int32]$state.BackupProgress.OverallPercentComplete
        Write-Progress -Activity $activity -Status $status -CurrentOperation $state.CurrentBackupProgress.CurrentFile -PercentComplete $pc
        Start-Sleep -Milliseconds 500
        $state = Get-PIBackupState -Connection $connection
    }

    Start-Sleep -s 60

    $backupInfo = Get-PIBackupReport -Connection $connection -LastReport

    ###################################################
    # Create restore file for each of the secondaries #
    ###################################################

    $sec_back = $BackupLocationOnPrimary + "\" + $secondary
    New-Item $sec_back -ItemType "directory"
    foreach ($secondary in $PISecondaryNames) {
        Write-Progress -Activity $activity -Status "Creating secondary restore files" -CurrentOperation $secondary
        $secondaryArchiveDirectory = Split-Path $primaryArchive
        if ($includeSet1 -eq $false) {
            Write-Host "Hi"
            New-PIBackupRestoreFile -Connection $connection -OutputDirectory ($BackupLocationOnPrimary + "\" + $secondary ) -NumberOfArchives 1 -HistoricalArchiveDirectory $secondaryArchiveDirectory
        }
        else {
            $secondaryArchiveSet1Directory = Split-Path $firstPathArchiveSet1
            $newArchiveDirectories = $secondaryArchiveDirectory, $secondaryArchiveSet1Directory
            New-PIBackupRestoreFile -Connection $connection -OutputDirectory ($BackupLocationOnPrimary + "\" + $secondary) -NumberOfArchives $NumberOfArchivesToBackup -ArchiveSetDirectories $newArchiveDirectories
        }
    }

    #################################
    # Copy Backup to each secondary #
    #################################

    Write-Host "Copying backup to secondary server"
    $backupLocationUNC = $BackupLocationOnPrimary

    foreach ($item in $backupInfo.Files) {
        $totalSize += $item.Size
    }

    foreach ($secondary in $PISecondaryNames) {
        $destinationUNCPIRoot = "\\" + $secondary + "\" + $destinationPIPaths.$secondary.Substring(0, 1) + "$" + $destinationPIPaths.$secondary.Substring(2)

        $status = "Copying backup to secondary node"
        $currentSize = 0
        foreach ($file in $backupInfo.Files) {
            $currentSize += $file.Size
            Write-Progress -Activity $activity -Status $status -CurrentOperation $file.Name -PercentComplete (($currentSize / $totalSize) * 100)
            $sourceUNCFile = "\\" + $connection.Address.Host + "\" + $file.Destination.SubString(0, 1) + "$" + $file.Destination.Substring(2)
            if ($file.ComponentDescription.StartsWith("Archive") -eq $true) {
                $destinationFilePath = Split-Path $file.Destination
                if ($destinationFilePath.EndsWith("arcFuture") -eq $true) {
                    $destinationUNCPath = "\\" + $secondary + "\" + $secondaryArchiveSet1Directory.Substring(0, 1) + "$" + $secondaryArchiveSet1Directory.Substring(2)
                }
                else {
                    $destinationUNCPath = "\\" + $secondary + "\" + $secondaryArchiveDirectory.Substring(0, 1) + "$" + $secondaryArchiveDirectory.Substring(2)
                }
            }
            else {
                $destinationUNCPath = $destinationUNCPIRoot + (Split-Path $file.Destination).Replace($BackupLocationOnPrimary, "")
            }

            if ((Test-Path -Path $destinationUNCPath) -eq $false) {
                New-Item -Path $destinationUNCPath -ItemType Directory | Out-Null
            }

            Copy-Item -Path $sourceUNCFile -Destination $destinationUNCPath

            $index++
        }

        
    }

    ########################
    # Cleanup backup files #
    ########################

    Start-Sleep -S 60

    Write-Host "Cleaning backup files"
    foreach ($file in $backupInfo.Files) {
        $sourceUNCFile = "\\" + $PIPrimaryName + "\" + $file.Destination.SubString(0, 1) + "$" + $file.Destination.Substring(2)
        Remove-Item -Path $sourceUNCFile
    }

    [Int32]$count = (Get-ChildItem $backupLocationUNC -Recurse | where {$_.psIsContainer -eq $false}).Count

    if ($count -eq 0) {
        Write-Progress -Activity $activity -Status "Removing empty backup directories."
        Remove-Item -Path $backupLocationUNC -Recurse
    }

    #########################
    # Start all secondaries #
    #########################

    Write-Host "Starting secondary Services"

    [string[]] $piServices = "pinetmgr", "pimsgss", "pilicmgr", "piupdmgr", "pibasess", "pisnapss", "piarchss", "pibackup"

    foreach ($secondary in $PISecondaryNames) {
        foreach ($service in $piServices) {
            $service = Get-Service -ComputerName $secondary -Name $service
            Write-Progress -Activity $activity -Status ("Starting secondary node " + $secondary) -CurrentOperation ("Starting " + $service.DisplayName)
            Start-Service -InputObject $service -WarningAction SilentlyContinue
        }
    }



    Start-Sleep -s 150

    ############################# PI Collective Refresh #############################

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
    $StartTime = $(get-date)
    $PICollectiveName = 'PIDA_Collective'
    $PIPrimaryName = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af1)' --zone $zone1
    $PISecondaryNames = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af2)' --zone $zone1
    $NumberOfArchivesToBackup = 1
    $BackupLocationOnPrimary = 'D:\Backup'
    $activity = "Creating Collective " + $PICollectiveName
    $status = "Connecting to server " + $PIPrimaryName
    Write-Progress -Activity $activity -Status $status
    $connection = Connect-PIDataArchive -PIDataArchiveMachineName $PIPrimaryName -ErrorAction Stop
    [Version] $v395 = "3.4.395"
    [Version] $v410 = "3.4.410"
    [String] $firstPathArchiveSet1;
    $includeSet1 = $false
    Write-Progress -Activity $activity -Status "Getting primary archive"
    $archives = Get-PIArchiveInfo -Connection $connection
    $primaryArchive = $archives.ArchiveFileInfo[0].Path
    Write-Progress -Activity $activity -Status "Writing collective information to primary"
    $collective = New-PICollective -Name $PICollectiveName -Secondaries $PISecondaryNames -Connection $connection

    Set-Location D:\temp\
    $storePath = 'OSIsoft LLC Certificates'
    .\SendPrimaryPublicCertToSecondaries.ps1 $PIPrimaryName $storePath $PISecondaryNames 
    .\SendSecondaryPublicCertToPrimary.ps1 $PIPrimaryName $PISecondaryNames $storePath


    ############################# PI Collective Refresh Done #############################


    ######################################### PI Collective Code Finished #########################################


    Write-Host "Out of sleep. Creating Collective_Success.txt file"
    #Create sucess file flag for AF server
    New-Item D:\temp\Collective_Success.txt
    gsutil cp D:\temp\Collective_Success.txt gs://$storage/Collective_Success.txt
}
  

# Disable identities-install
Disable-ScheduledTask -TaskName "identities-install"


'@
$identities | out-file D:\temp\identities.ps1


$getcert = @'

# ***********************************************************************
# * All sample code is provided by OSIsoft for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * OSIsoft provides no guarantee nor implies any reliability, 
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS" 
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING 
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************

# ************************************************************************
# This script is used for getting a certificate from a certificate store of
# a machine.
# Remote Administration needs to be enabled on all collective members
# ************************************************************************
param ([String]$machineName, [String]$storePath)
$path = $storePath.Split("\")
if ($path.Count -eq 2)
{
	if ($path[0] -ieq 'CurrentUser')
	{
		$storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
	}
	if ($path[0] -ieq 'LocalMachine')
	{
		$storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
	}
	else
	{
		throw [System.ArgumentException] 'invalid certificate store'
	}
	$storeName = $path[1]
}
if ($path.Count -eq 1)
{
	$storeName = $storePath
	$storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
}
else
{
	throw [System.ArgumentException] 'invalid certificate store'
}
$store = New-Object -Type System.Security.Cryptography.X509Certificates.X509Store("\\$machineName\$storeName", $storeLocation)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
try
{
	$cert = $store.Certificates[0]
}
finally
{
	$store.Close()
}
$cert

'@
$getcert | out-file D:\temp\Get-RemoteCert.ps1


$primtosec = @'

# ***********************************************************************
# * All sample code is provided by OSIsoft for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * OSIsoft provides no guarantee nor implies any reliability, 
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS" 
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING 
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************

# ************************************************************************
# This script sends the primary public certificate to all secondary members.
# It can be used for changing the certificate of the primary data archive.
# Remote Administration needs to be enabled on all collective members.
# ************************************************************************

param ([String] $primary, [String]$storePath, [String[]]$secondaries)
if ((Test-Path '.\Get-RemoteCert.ps1') -eq $false)
{
	Write-Error 'missing file: Get-RemoteCert.ps1'
	return
}
$cert = .\Get-RemoteCert.ps1 $primary $storePath
if ($cert)
{
	$store = New-Object -Type System.Security.Cryptography.X509Certificates.X509Certificate2Collection($cert)
	$publicCert = $store.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
	$store.Clear()
	$store.Import($publicCert)
	$publicCert = $store.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)
	foreach($secondary in $secondaries)
	{
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $secondary).OpenSubkey('SOFTWARE\PISystem\PI', 'true')
		try
		{	
			$reg.SetValue('PrimaryCertSignature', $publicCert, [Microsoft.Win32.RegistryValueKind]::Binary)
		}
		catch 
		{
			Write-Error 'Unable to write the public certificate to the registry on $secondary: $_.Exception.Message'
		}
		finally
		{
			$reg.Close()
		}
	}
}
else
{
	Write-Error 'Cannot get the certificate from $storePath of $primary'
}

'@
$primtosec | out-file D:\temp\SendPrimaryPublicCertToSecondaries.ps1 

$sectoprim = @'

# ***********************************************************************
# * All sample code is provided by OSIsoft for illustrative purposes only.
# * These examples have not been thoroughly tested under all conditions.
# * OSIsoft provides no guarantee nor implies any reliability, 
# * serviceability, or function of these programs.
# * ALL PROGRAMS CONTAINED HEREIN ARE PROVIDED TO YOU "AS IS" 
# * WITHOUT ANY WARRANTIES OF ANY KIND. ALL WARRANTIES INCLUDING 
# * THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY
# * AND FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY DISCLAIMED.
# ************************************************************************

# ************************************************************************
# This script sends the secondary public certificates to primary member.
# It can be used for changing the certificate on any secondary data archive
# Limitation: The certificate store names of all secondary data archives 
# have to be identical.
# This script can run on any machine with PI PowerShell Tools installed.
# Remote Administration needs to be enabled on all collective members
# ************************************************************************
param ([String]$primary, [String[]]$secondaries, [String]$storePath)
if ((Test-Path '.\Get-RemoteCert.ps1') -eq $false)
{
	Write-Error 'missing file: Get-RemoteCert.ps1'
	return
}
$collective = Connect-PIDataArchive $primary | Get-PICollective
foreach($secondary in $secondaries)
{
	$cert = .\Get-RemoteCert.ps1 $secondary $storePath
	$collective | Set-PICollectiveMember $secondary -PublicCert $cert
}

'@
$sectoprim | out-file D:\temp\SendSecondaryPublicCertToPrimary.ps1

# # Services to start if not already running after every boot
# $services = @'
# #Check if PI services are running. If not then start the services.
# $piservices = @('AFService','PIAnalysisManager','piarchss','pibackup','pibasess','pibufss','PINotificationsService','PISqlDas.RTQP','pisqlss')
# foreach ($piservice in $piservices){
#     get-service "$piservice" | Where {$_.Status -ne 'Running'} | start-service
# }
# '@
# $services | out-file D:\temp\services.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


    # #Schedule a task to check if pi services are running after every boot.
    # Write-Host("Scheduling Services to restart")
    # $Trigger= New-ScheduledTaskTrigger -AtStartup
    # $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\services.ps1" 
    # Register-ScheduledTask -TaskName "services-restart-at-every-boot" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


    Restart-Computer
}