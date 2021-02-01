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

# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Check if af server flag is present in bastion metadata. If not wait for 60 seconds and try again
while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af1Ready)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Get bucket name from metadata where executables are stored
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
    
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

Write-Host("Checking domain join")
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    Write-Host "Machine is not domain joined"
   
    $username = "$domain\setupadmin"

    # Read password from secret manager, remove whitespaces and extra characters 
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)

    # Prepare disk for pivision installation 
    Get-Disk | Where-Object partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false
    
    #Install IIS
    Install-WindowsFeature -name Web-Server -IncludeManagementTools

    #Join machine to domain
    Add-Computer -DomainName $domain -Credential $cred
    
    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 
    
    # Create staging location for executables 
    New-Item -Path 'C:\temp\' -ItemType Directory
    Set-Location -Path C:\temp\
    gsutil -m cp -r gs://$storage/pivision/* C:\temp\
    
    # Install 7zip to extract installer
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -Force
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    
    #Extract the installar to the staging location
    Expand-7Zip -ArchiveFileName .\PI-Vision_2019-Patch-1_.exe -TargetPath '.\'
    
# Create gMSA.ps1 file to be executed by scheduler on the next boot.
$gMSA = @'
# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Read password from secret manager, remove whitespaces and extra characters
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
#$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"

# Add pivision computer to AD group vision_group
Add-ADGroupMember -Identity vision_group -Members $env:COMPUTERNAME$

#Grant permission to vision_group to use gMSA service account
Set-ADServiceAccount -Identity ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group
Set-ADServiceAccount -Identity ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group

# Scheudle vision installation task on the next boot
Write-Host("Scheduling piserver Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "c:\temp\vision.ps1" 
Register-ScheduledTask -TaskName "piserver-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

# Disable gMSA-install task
Disable-ScheduledTask -TaskName "gMSA-install"
Unregister-ScheduledTask -TaskName "gMSA-install" -Confirm:$false
Restart-Computer
'@
$gMSA | Out-File c:\temp\gMSA.ps1

# Prepare vision.ps1 file for installaling pivision server
$vision_install = @'
# Getting the projet details and finding zone.
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get storage bucket name to where piserver executables are present
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1

Set-Location -Path C:\temp\PIVision_*
	
# Get AF server name from the metadata. Needed for pivision installation 
$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.af-server)' --zone $zone1 

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Read password from secret manager, remove whitespaces and extra characters 
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\setupadmin"

# Prepare credentials object
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

$location = Get-Location

#Parameters for config.json
$ConfigAssetServer =  "$afserver" 
$CrawlerSubmitUrl = "https://$env:computername/piwebapi/"
$ConfigInstance = $env:computername

#Parameters for silent.ini
$MyPIServer = "$afserver"
$MyAFServer = "$afserver"
$ServiceAccountUsername = "$domain\ds-pivs-svc$"
$machine_name = -join($env:computername,".",$ServiceAccountUsername)

# Added these lines for Enabling Kerberos delegation 
# Sets the value of useAppPoolCredentials for pivision site
Import-Module WebAdministration
cd 'IIS:\Sites\Default Web Site\PIVision\'  
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/PIVision' -filter /system.webServer/security/authentication/windowsAuthentication -name useAppPoolCredentials  -value True
setspn -S $env:computername $ServiceAccountUsername
setspn -S $machine_name $ServiceAccountUsername

Set-Location -Path C:\Windows\system32

# Added these lines for Configure resource-based constrained delegation also for adding members to PIWebAppsADGroup
$frontendidentity = Get-ADServiceAccount -Identity ds-pivs-svc
$backendidentity = Get-ADServiceAccount -Identity ds-piaf-svc
Set-ADServiceAccount $backendidentity -PrincipalsAllowedToDelegateToAccount $frontendidentity
Get-ADServiceAccount $backendidentity -Properties PrincipalsAllowedToDelegateToAccount
Add-ADGroupMember -Identity "PIWebAppsADGroup" -Members ds-pivs-svc$ 
Add-ADGroupMember -Identity "PIWebAppsADGroup" -Members setupadmin

Set-Location -Path C:\temp\PIVision_*

#To change in config.json
$JSON = Get-Content -Path ".\SilentConfig.json" | ConvertFrom-JSON

$JSON | Add-Member -Name "ConfigAssetServer" -MemberType NoteProperty -Value "$ConfigAssetServer" -Force
$JSON | Add-Member -Name "CrawlerSubmitUrl" -MemberType NoteProperty -Value $CrawlerSubmitUrl -Force
$JSON | Add-Member -Name "ConfigInstance" -MemberType NoteProperty -Value "$ConfigInstance" -Force
$JSON | Add-Member -Name "ApiServiceAccountType" -MemberType NoteProperty -Value "Custom" -Force    
$JSON | Add-Member -Name "CrawlerServiceAccountType" -MemberType NoteProperty -Value "Custom" -Force  
$JSON | Add-Member -Name "ApiServiceAccountUsername" -MemberType NoteProperty -Value "$ServiceAccountUsername" -Force  
$JSON | Add-Member -Name "CrawlerServiceAccountUsername" -MemberType NoteProperty -Value "$ServiceAccountUsername" -Force  
$JSON | ConvertTo-JSON | Out-File ".\SilentConfig.json"

(Get-Content -path .\silent.ini) |
ForEach-Object {$_ -replace 'MyAFServer',$MyAFServer}  |
Out-File .\silent.ini

(Get-Content -path .\silent.ini) |
ForEach-Object {$_ -replace 'MyPIServer',$MyPIServer}  |
Out-File .\silent.ini

write-host("Preparing silent.ini")
$location = Get-Location
(Get-Content -path .\silent.ini) |
ForEach-Object {$_ -replace [regex]::Escape(".\SilentConfig.json"),"$location\SilentConfig.json"}  |
Out-File .\silent.ini

write-host("Starting vision installation")
$cmd = .\Setup.exe -f .\silent.ini
$proc = Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
$proc
Start-Sleep -s 540

Import-Module WebAdministration
Get-ChildItem -Path IIS:\AppPools
$gMSA = "$domain\ds-pivs-svc$"
$pass = "null"
$pools = @('PIVisionServiceAppPool','PIVisionUtilityAppPool','PIVisionAdminAppPool')

# user name & pass is being set to $pools whose values are in list 
foreach($pool in $pools){
    Set-ItemProperty IIS:\AppPools\$pool -name processModel -value @{userName="$gMSA";password="$pass";identitytype=3}
}

# adding local group member in Group "PI Web API Admins
$cmd = Add-LocalGroupMember -Group "PI Web API Admins" -Member "$domain\ds-pivs-svc$"
start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$cmd})"

#Create sucess file flag for vision server
New-Item C:\temp\vision_success.txt -ItemType file
gsutil -m cp C:\temp\vision_success.txt gs://$storage/

# Disable vision-install task
Disable-ScheduledTask -TaskName "vision-install"
Unregister-ScheduledTask -TaskName "vision-install" -Confirm:$false

#INTEGRATOR INSTALL
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Get storage bucket name to where piserver executables are present
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1

# Check if Integrator license/executable exists
$flag = gsutil stat gs://$storage/integrator/OSIsoft*
if ($flag){

$sqlserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone $zone1
$integrator_svc = "$domain\ds-pint-svc$"
$domain_admin = "$domain\setupadmin"
                
Set-Location C:\temp
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
gsutil -m cp -r gs://$storage/integrator/* C:\temp\

# Extract integrator installer 
Expand-7Zip -ArchiveFileName .\OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe -TargetPath 'C:\temp\pi-integrator\'
Set-Location C:\temp\pi-integrator
    
$location = Get-Location

# update silent.ini with required values needed for installation 
(Get-Content .\silent.ini) `
    | %{ $_ -replace "9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus.+","9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus SENDTELEMETRY=0 SERVICEACCOUNT=$integrator_svc AFSERVER=$afserver SQLSERVER=$sqlserver USERPORT=444 SQLHOSTNAME=$sqlserver"} `
    | Set-Content .\silent.ini
    
# Prepare the installation command     
$cmd = .\Setup.exe -f .\silent.ini

# Run installation command with elavated previleges
Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
    
#Create sucess file flag for integrator server
New-Item C:\temp\integrator_success.txt
gsutil cp C:\temp\integrator_success.txt gs://$storage/

Start-sleep -s 180

#start integrator service if not running
get-service -displayname "PI Integrator for Business Analytics" | Where {$_.Status -ne 'Running'} | start-service

}

# Download Web-omf installer to staging location 
New-Item -ItemType directory -Path C:\temp
gsutil -m cp -r gs://$storage/piweb/* C:\temp
Start-Sleep -s 15
Set-Location -Path C:\temp\

# Extract web api executable
Expand-7Zip -ArchiveFileName .\PI-Web-API-2019-SP1_1.13.0.6518_.exe -TargetPath '.\'

# Add vision server to AD group omf_group 
Add-ADGroupMember -Identity omf_group -Members $env:COMPUTERNAME$

# Grant access to omf_group to use gMSA service account 
Set-ADServiceAccount -Identity ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group

Set-Location -Path C:\temp\PIWebAPI*

# Split domain to create correct OU path
$domain_arr = $domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

#Some of the lines have been edited in order to change InstallationConfig.json file
$ConfigAssetServer =  "$afserver" 
$CrawlerSubmitUrl = "https://$env:computername/piwebapi/"
$ConfigInstance = $env:computername
$OmfAssetServerName = "$afserver"
$OmfAssetDatabaseName = "OMF_DB"
$OmfDataArchiveName = "$afserver"
$ApiServiceAccountType = "Custom" 
$ApiServiceAccountUsername = "$ServiceAccountUsername"
$CrawlerServiceAccountType = "Custom"
$CrawlerServiceAccountUsername = "$ServiceAccountUsername"

# Update InstallationConfig.json with required values
$JSON = Get-Content -Path "C:\temp\InstallationConfig.json" | ConvertFrom-JSON
$JSON | Add-Member -Name "ConfigAssetServer" -MemberType NoteProperty -Value "$ConfigAssetServer" -Force
$JSON | Add-Member -Name "CrawlerSubmitUrl" -MemberType NoteProperty -Value $CrawlerSubmitUrl -Force
$JSON | Add-Member -Name "ConfigInstance" -MemberType NoteProperty -Value "$ConfigInstance" -Force
$JSON | Add-Member -Name "OmfAssetServerName" -MemberType NoteProperty -Value "$OmfAssetServerName" -Force  
$JSON | Add-Member -Name "OmfAssetDatabaseName" -MemberType NoteProperty -Value "$OmfAssetDatabaseName" -Force  
$JSON | Add-Member -Name "OmfDataArchiveName" -MemberType NoteProperty -Value "$OmfDataArchiveName" -Force  
$JSON | Add-Member -Name "ApiServiceAccountType" -MemberType NoteProperty -Value "$ApiServiceAccountType" -Force  
$JSON | Add-Member -Name "ApiServiceAccountUsername" -MemberType NoteProperty -Value "$ApiServiceAccountUsername" -Force 
$JSON | Add-Member -Name "CrawlerServiceAccountType" -MemberType NoteProperty -Value "$CrawlerServiceAccountType" -Force  
$JSON | Add-Member -Name "CrawlerServiceAccountUsername" -MemberType NoteProperty -Value "$CrawlerServiceAccountUsername" -Force  

$JSON | ConvertTo-JSON | Out-File "C:\temp\InstallationConfig.json"

#These lines are added to restart the picrawler and piwebapi services as you insisted
$piservices = @('picrawler','piwebapi')
foreach ($piservice in $piservices){
    get-service "$piservice" | Restart-Service
}

# Update silent.ini with required values 
$fileContent = Get-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini
$textToAdd = ' ADDLOCAL=ALL DATA_DIR=D:\Data_DIR INSTALLATION_DIR=D:\piweb_install CONFIG_FILE=C:\temp\InstallationConfig.json'
$fileContent[93] += $textToAdd
$fileContent | Set-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini

write-host("Starting web omf installation")
$cmd = .\Setup.exe -f .\silent.ini
$proc = Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)" 
$proc
Start-Sleep -s 180

#The below line has been modified for maintaining the uniformity in the service account
$svcs = @('picrawler','piwebapi')
$gMSA = "$domain\ds-pivs-svc$"
foreach($svc in $svcs){
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$svc'"
    $service.Change($null, $null, $null, $null, $null, $null, $gMSA, $null, $null, $null, $null)
}

#Create success file flag for omf server
New-Item C:\temp\omf_success.txt
gsutil cp C:\temp\omf_success.txt gs://$storage/

#Windows firewall rule for PI Integrator
netsh advfirewall firewall add rule name="PI Integrator 444" dir=in action=allow protocol=TCP localport=444

#Give database roles and user mapping for gMSA of Integrator
Invoke-Command -FilePath c:\temp\db.ps1 -ComputerName 'pisql-1'

Remove-Item C:\temp\*.ps1*
'@
$vision_install | Out-File c:\temp\vision.ps1    

# Staging InstallationConfig.json file to be used to omf server installation
$installconfig = @'
{
    "ConfigAssetServer": "OSI-PISERVER",
    "ConfigInstance": "web-omf",
    "IsFirewallExceptionEnabled": true,
    "IsTelemetryEnabled": true,
    "ListenPort": 443,
    "ApiServiceAccountType": "Default",
    "ApiServiceAccountUsername": "NT Service\\piwebapi",
    "CrawlerServiceAccountType": "Default",
    "CrawlerServiceAccountUsername": "NT Service\\picrawler",
    "CrawlBuiltInGroups": true,
    "CrawlerSubmitTimeout": 1200.0,
    "CrawlerSubmitUrl": "https://web-omf.ad.osi.com/piwebapi/",
    "MaxConcurrentCrawlers": 4,
    "AutoCrawlRebuild": true,
    "CrawlerMaxPathCount": 1000000,
    "OmfAssetServerName": "OSI-PISERVER",
    "OmfAssetDatabaseName": "OMF_DB",
    "OmfDataArchiveName": "piidentity"
}
'@
$installconfig | Out-File c:\temp\InstallationConfig.json

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

$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'pisql-1'
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
New-Item -Path C:\db_success.txt -ItemType file
gsutil -m cp c:\db_success.txt gs://$storage/

'@
$db | Out-File c:\temp\db.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password1 -Action $Action -RunLevel Highest -Force
    
    Restart-Computer
}