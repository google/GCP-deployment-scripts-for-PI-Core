# Getting the projet details and finding zone.
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Read domain name from metadata.
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Check if sqlReady flag is present in bastion metadata. If not wait for 60 seconds and try again
while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.sqlReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}

# Force gMSA task to run if exist on the boot. This will execute on the second boot. 
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

# Check if machine is domain joined. If yes then exit and do nothing.
Write-Host "Checking doamin join"
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
   Write-Host ("Machine is domain joined...exiting")
}else{
    Write-Host "Machine is not domain joined, executing installation stpes"

    # Read password from secret manager, remove whitespaces and extra characters 
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $username = "$domain\setupadmin"

    # Create credentials object 
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    
    # Get bucket name where executables are stored.
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
    
    # Preapre the extra disk for piserver installation
    Get-Disk | Where-object partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false

    # Create staging location for executables 
    New-Item -Path 'D:\temp\' -ItemType Directory
    Set-Location D:\temp\
    gsutil -m cp -r gs://$storage/piserver/* D:\temp\
    
    #Open firewall ports needed for communication between pi components
    netsh advfirewall firewall add rule name="Open port for af server inbound" dir=in action=allow protocol=TCP localport=5457
    netsh advfirewall firewall add rule name="Open port for af server inbound" dir=in action=allow protocol=TCP localport=5450
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5463
    netsh advfirewall firewall add rule name="Open port for analysis service inbound" dir=in action=allow protocol=TCP localport=5468
    
    # Join machine to domain
    Add-Computer -DomainName $domain -Credential $cred
    
    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 
    
    # Add setupadmin to local admin group
    $addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
    start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"

# Create gMSA.ps1 file to be executed by scheduler on the next boot.
$gMSA = @'
# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Read password from secret manager, remove whitespaces and extra characters 
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
#$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"

#AF piserver to piserver group
Add-ADGroupMember -Identity piserver_group -Members $env:COMPUTERNAME$

# Grant piserver_group to use service account
Set-ADServiceAccount -Identity ds-piaf-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group
Set-ADServiceAccount -Identity ds-pian-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group
Set-ADServiceAccount -Identity ds-pino-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group
Set-ADServiceAccount -Identity ds-pidas-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group
Set-ADServiceAccount -Identity ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group

# To create AFServer SPN in the “New-ADServiceAccount” command with the option “-ServicePrincipalNames 
$machine_domain = -join($env:computername,".",$domain)
setspn -s AFServer/$env:computername $domain\ds-piaf-svc$
setspn -s AFServer/$machine_domain $domain\ds-piaf-svc$ 

#Adding to give security privilege for PI Integrator account to access PI Data Archive
Add-ADGroupMember -Identity PIUsersADGroup -Members ds-pint-svc$

# Add piserver name to AFservers group present on the sql server. This is required as prerequisite
Invoke-Command -ComputerName pisql-1 -ScriptBlock{Add-LocalGroupMember -Group "AFServers" -Member "$domain\$env:computername$"}

# Scheudle piserver installation task which will run on the next boot 
Write-Host("Scheduling piserver Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\piserver.ps1" 
Register-ScheduledTask -TaskName "piserver-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

# Disable gMSA-install task.
Disable-ScheduledTask -TaskName "gMSA-install"
Unregister-ScheduledTask -TaskName "gMSA-install" -Confirm:$false
Restart-Computer

Start-Sleep -Seconds 10
Restart-Computer -Force
'@
$gMSA | Out-File D:\temp\gMSA.ps1

#Create piserver.ps1 file to install piserver
$piserver = @'
# Getting the projet details and finding zone. 
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get storage bucket name to where piserver executables are present
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1
    
Set-Location D:\temp\
$location = Get-Location

# Get SQL server name from metadata
$sqlserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone $zone1

# Read password from secret manager, remove whitespaces and extra characters 
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"

# Create credentials object 
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

# Variables for gMSA services
$afsvc = "$domain\ds-piaf-svc$"
$ansvc = "$domain\ds-pian-svc$"
$nosvc = "$domain\ds-pino-svc$"
$pidassvc = "$domain\ds-pidas-svc$"

$cmd = .\PI-Server_2018-SP3-Patch-3_.exe /passive ADDLOCAL=PIDataArchive,PITotal,FD_AppsServer,PiSqlDas.Rtqp,PINotificationsService,PIAnalysisService,FD_AFExplorer,FD_AFAnalysisMgmt,FD_AFDocs,PiPowerShell,pismt3 `
PIHOME="D:\Program Files (x86)\PIPC" PIHOME64="D:\Program Files\PIPC" AFSERVER="$env:computername" SENDTELEMETRY="1" `
AFSERVICEACCOUNT="$afsvc" FDSQLDBNAME="PIFD" FDSQLDBSERVER="$sqlserver" AFACKNOWLEDGEBACKUP="1" `
PISQLDAS_SERVICEACCOUNT="$pidassvc" PI_LICDIR="$location\License" `
PI_INSTALLDIR="D:\Program Files\PI" PI_EVENTQUEUEDIR="D:\Program Files\PI\Queue"  PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername" `
PIANALYSIS_SERVICEACCOUNT="$ansvc" PINOTIFICATIONS_SMTPSERVER="abc" PINOTIFICATIONS_FROMEMAIL="abc@test.com" `
PINOTIFICATIONS_SERVICEACCOUNT="$nosvc"

# Execuate piserver installation command with elavated privileges  
Write-Host "Starting Piserver installation"
Start-Process powershell -Credential $cred -ArgumentList "-noexit -command (Invoke-Command -ScriptBlock {$cmd})"
Write-Host "Sleep-wait"
start-sleep -s 660

# Restart pibuf service with pibuff gMSA account
$pibuff_svc = "pibufss"
$pibuff_gMSA = "$domain\ds-pibufss-svc$"
$service = Get-WmiObject -Class Win32_Service -Filter "Name='$pibuff_svc'"
$service.Change($null, $null, $null, $null, $null, $null, $pibuff_gMSA, $null, $null, $null, $null)
Write-Output "Restared "+$pibuff_svc+" with account "+$pibuff_gMSA

Write-Host "Out of sleep. Creating af_success.txt file"
#Create sucess file flag for AF server and upload to storage bucket
New-Item D:\temp\piserver_success.txt -ItemType file
gsutil -m cp D:\temp\piserver_success.txt gs://$storage/

# Disable piserver-install as installation is done 
Disable-ScheduledTask -TaskName "piserver-install"
Unregister-ScheduledTask -TaskName "piserver-install" -Confirm:$false

# Schedule task for configuration of pi identities
Write-Host("Scheduling PI identities Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\identities.ps1" 
Register-ScheduledTask -TaskName "identities-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

Restart-Computer

'@
$piserver | Out-File D:\temp\piserver.ps1    

# Create identities.ps1 to configure identities of the piserver
$identities = @'
# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

#$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'
#$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
#$zone = $data.split()[1]

#Check if PI services are running. If not then start the services.
$piservices = @('AFService','PIAnalysisManager','piarchss','pibackup','pibasess','pibufss','PINotificationsService','PISqlDas.RTQP','pisqlss')
foreach ($piservice in $piservices){
    get-service "$piservice" | Where {$_.Status -ne 'Running'} | start-service
}

# Split domain to create correct OU path
$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1
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

# Remove-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" 
# Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" -Description "Identity for PI Buffer Subsystem and PI Buffer Server"
# Remove-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" 
# Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" -Description "Identity for PI Interfaces" 
# Remove-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" 
# Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" -Description "Identity for the users to get Read access on the PI Data Archive" 

# Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" -Description "Identity for PI Buffer Subsystem and PI Buffer Server" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0 
# Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" -Description "Identity for PI Interfaces" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
# Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" -Description "Identity for the users to get Read access on the PI Data Archive" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0

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

Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" -Description "Identity for PI Buffer Subsystem and PI Buffer Server" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0 
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" -Description "Identity for PI Interfaces" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" -Description "Identity for the users to get Read access on the PI Data Archive" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0

 
#PI Security groups objects 
$PISecurityGroups = @(
    @{Name = 'PIBuff'; Description = 'Identity for PI Buffer Subsystem and PI Buffer Server'; }
    @{Name = 'PIInterfacesADGroup'; Description = 'Identity for PI Interfaces'; },
    @{Name = 'PIUsersADGroup'; Description = 'Identity for the Read-only users'; },
    @{Name = 'PIPointsAnalysisCreatorADGroup'; Description = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'; }
    @{Name = 'PIWebAppsADGroup'; Description = 'Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler'; },
    @{Name = 'PIConnectorRelaysADGroup'; Description = 'Identity for PI Connector Relays'; },
    @{Name = 'PIDataCollectionManagersADGroup'; Description = 'Identity for PI Data Collection Managers'; }
)

# Create AD group of all PI Security groups
for($i=0 ; $i -lt $PISecurityGroups.length; $i++){
    $name = $PISecurityGroups[$i]['Name']
    $description = $PISecurityGroups[$i]['Description']
    New-ADGroup -Name "$name" -SamAccountName "$name" -GroupCategory Security -GroupScope Global -Description "$description" -Path "OU=Computers,OU=Cloud,$domainPath"  
}

# PI Security groups and identity mappings
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

# Add PI mappings 
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

# #Setting flag for af server ready. 
gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=af1Ready="True"

# The PowerShell script to gMSA account ds-pibufss-svc$ to be member of local group “PI Buffer Writers” and “PI Buffering Administrators” on PISRV-1
Add-LocalGroupMember -Group "PI Buffer Writers" -Member "$domain\ds-pibufss-svc$" 
Add-LocalGroupMember -Group "PI Buffering Administrators" -Member "$domain\ds-pibufss-svc$" 

# Disable identities-install
Disable-ScheduledTask -TaskName "identities-install"
Unregister-ScheduledTask -TaskName "identities-install" -Confirm:$false
Remove-Item D:\temp\gMSA.ps1
Remove-Item D:\temp\piserver.ps1
Remove-Item D:\temp\identities.ps1
# Remove-Item D:\temp\*.ps1*
'@
$identities | out-file D:\temp\identities.ps1

# Services to start if not already running after every boot
$services = @'
#Check if PI services are running. If not then start the services.
$piservices = @('AFService','PIAnalysisManager','piarchss','pibackup','pibasess','pibufss','PINotificationsService','PISqlDas.RTQP','pisqlss')
foreach ($piservice in $piservices){
    get-service "$piservice" | Where {$_.Status -ne 'Running'} | start-service
}
'@
$services | out-file D:\temp\services.ps1

    # Schedule gMSA script on the next boot.
    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    # Schedule a task to check if pi services are running after every boot.
    Write-Host("Scheduling Services to restart")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\services.ps1" 
    Register-ScheduledTask -TaskName "services-restart-at-every-boot" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


    Restart-Computer
}