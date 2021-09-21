
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

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af1Ready)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 10 sec"
    Start-Sleep -s 10
}

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

#check if AF Server Installation is complete
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
Write-Host("Checking domain join")
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    Write-Host "Machine is not domain joined"
    #$taskPass = gcloud secrets versions access 1 --secret=osi-pi-secret
    $username = "$domain\setupadmin"
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)

    Get-Disk | Where-Object partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false
    
    #Install IIS
    Install-WindowsFeature -name Web-Server -IncludeManagementTools

    #Join machine to domain
    Add-Computer -DomainName $domain -Credential $cred
    
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 

    # Install Chrome Browser
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    # function Set-ChromeAsDefaultBrowser {
    #     Add-Type -AssemblyName 'System.Windows.Forms'
    #     Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
    #     Sleep 2
    #     [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
    # } 
    # Set-ChromeAsDefaultBrowser


    New-Item -Path 'C:\temp\' -ItemType Directory
    Set-Location -Path C:\temp\
    gsutil -m cp -r gs://$storage/pivision/* C:\temp\
    ## 
    gsutil -m cp -r gs://$storage/piserver/* C:\temp\
   

    # Install 7zip to extract installer
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -Force
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    
    #Extract the installar to the staging location
    Expand-7Zip -ArchiveFileName .\PI-Vision_2020_.exe -TargetPath '.\'

    Write-Host "Creating temp directory for web api installation files"
    New-Item -ItemType directory -Path C:\temp
    gsutil -m cp -r gs://$storage/piweb/* C:\temp
    Start-Sleep -s 15

    Set-Location -Path C:\temp\
    Expand-7Zip -ArchiveFileName .\PI-Web-API-2019-SP1_1.13.0.6518_.exe -TargetPath '.\'
    

$gMSA = @'

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
    
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
#$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"
    
Add-ADGroupMember -Identity vision_group -Members $env:COMPUTERNAME$
Set-ADServiceAccount -Identity ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group

Write-Host("Scheduling piserver Task")
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "c:\temp\vision.ps1" 
Register-ScheduledTask -TaskName "piserver-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force
Disable-ScheduledTask -TaskName "gMSA-install"
Restart-Computer
'@
$gMSA | Out-File c:\temp\gMSA.ps1

#Prepare InstallationConfig.json 
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
    "CrawlerMaxPathCount": 1000000
}
'@
$installconfig | Out-File c:\temp\InstallationConfig.json


$vision_install = @'
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
Set-Location -Path C:\temp\PIVision_*
$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone 
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

$location = Get-Location

#Parameters for config.json
$ConfigAssetServer =  "$afserver" 
$CrawlerSubmitUrl = "https://$env:computername/piwebapi/"
$ConfigInstance = $env:computername

#Parameters for silent.ini
$MyPIServer = "$afserver"
$MyAFServer = "$afserver"
$name = $env:COMPUTERNAME.ToLower()
$ServiceAccountUsername = "$domain\ds-pivs-svc$"
$machine_name = -join($name,".",$domain)

# Added these lines for Enabling Kerberos delegation 

#Step1: which sets the value of useAppPoolCredentials for pivision site
Import-Module WebAdministration
cd 'IIS:\Sites\Default Web Site\PIVision\'  
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -Location 'Default Web Site/PIVision' -filter /system.webServer/security/authentication/windowsAuthentication -name useAppPoolCredentials  -value True
#Step2
setspn -S HTTP/$name $ServiceAccountUsername
setspn -S HTTP/$machine_name $ServiceAccountUsername 

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
#$proc = Start-Process powershell -Credential $cred -NoNewWindow -ArgumentList "-command(Invoke-Command -ScriptBlock {$cmd})" -PassThru
$proc = Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
$proc
Start-Sleep -s 540

Import-Module WebAdministration
Get-ChildItem -Path IIS:\AppPools
$gMSA = "$domain\ds-pivs-svc$"
$pass = "null"
$pools = @('PIVisionServiceAppPool','PIVisionUtilityAppPool','PIVisionAdminAppPool')

foreach($pool in $pools){
    Set-ItemProperty IIS:\AppPools\$pool -name processModel -value @{userName="$gMSA";password="$pass";identitytype=3}
}

# adding local group member in Group "PI Web API Admins
$cmd = Add-LocalGroupMember -Group "PI Web API Admins" -Member "$domain\ds-pivs-svc$"
start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$cmd})"
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone



################################Added to check if pi web api works############################3
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]
$region1 = $zone1.Split("-")[0]
$region = $region1+"-"+$zone1.Split("-")[1]
if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}
Set-Location -Path C:\temp\PIVision_*
$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone 
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)


Set-ADServiceAccount -Identity ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group
$afserver = gcloud compute forwarding-rules describe fwd-pisvr-1 --region $region --format="value(serviceName)"

Set-Location -Path C:\temp\PIWebAPI*

$domain_arr = $domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

$ServiceAccountUsername = "$domain\ds-pivs-svc$"
$ConfigAssetServer =  "$afserver" 
$CrawlerSubmitUrl = "https://$env:computername/piwebapi/"
$ConfigInstance = $env:computername
$ApiServiceAccountType = "Custom" 
$ApiServiceAccountUsername = "$ServiceAccountUsername"
$CrawlerServiceAccountType = "Custom"
$CrawlerServiceAccountUsername = "$ServiceAccountUsername"

#To change in config.json
$JSON = Get-Content -Path "C:\temp\InstallationConfig.json" | ConvertFrom-JSON

$JSON | Add-Member -Name "ConfigAssetServer" -MemberType NoteProperty -Value "$ConfigAssetServer" -Force
$JSON | Add-Member -Name "CrawlerSubmitUrl" -MemberType NoteProperty -Value $CrawlerSubmitUrl -Force
$JSON | Add-Member -Name "ConfigInstance" -MemberType NoteProperty -Value "$ConfigInstance" -Force
$JSON | Add-Member -Name "ApiServiceAccountType" -MemberType NoteProperty -Value "$ApiServiceAccountType" -Force  
$JSON | Add-Member -Name "ApiServiceAccountUsername" -MemberType NoteProperty -Value "$ApiServiceAccountUsername" -Force 
$JSON | Add-Member -Name "CrawlerServiceAccountType" -MemberType NoteProperty -Value "$CrawlerServiceAccountType" -Force  
$JSON | Add-Member -Name "CrawlerServiceAccountUsername" -MemberType NoteProperty -Value "$CrawlerServiceAccountUsername" -Force  

$JSON | ConvertTo-JSON | Out-File "C:\temp\InstallationConfig.json"

# Update silent.ini with required values 
$fileContent = Get-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini
$textToAdd = 'ADDLOCAL=ALL CONFIG_FILE=C:\temp\InstallationConfig.json'
$fileContent[93] += $textToAdd
$fileContent | Set-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini



write-host("Starting Web API installation")
$cmd = .\Setup.exe -f .\silent.ini
$proc = Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)" 
$proc
Start-Sleep -s 180
$svcs = @('picrawler','piwebapi')
$gMSA = "$domain\ds-pivs-svc$"
foreach($svc in $svcs){
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$svc'"
    $service.Change($null, $null, $null, $null, $null, $null, $gMSA, $null, $null, $null, $null)
}

$piservices = @('picrawler','piwebapi')
foreach ($piservice in $piservices){
    get-service "$piservice" | Restart-Service
}

Start-Sleep -s 120


########################## PI web api installation Finished #####################################


Invoke-Command -FilePath c:\temp\chrome.ps1 -ComputerName 'pibastion1' 

#Create sucess file flag for integrator server
New-Item -ItemType File -path C:\temp\pivision_success.txt
gsutil -m cp c:\temp\pivision_success.txt gs://$storage/pivision_success.txt


$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
Rundll32 iesetup.dll, IEHardenLMSettings
Rundll32 iesetup.dll, IEHardenUser
Rundll32 iesetup.dll, IEHardenAdmin
Write-Host "IE Enhanced Security Configuration (ESC) has been disabled."
iisreset

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
Set-Location -Path C:\temp\PIVision_*
$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone 
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$location = Get-Location
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

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
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
$username = "$domain\setupadmin"
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

Set-Location C:\temp
$cmd = .\PI-Server_2018-SP3-Patch-3_.exe /passive ADDLOCAL=PiPowerShell   SENDTELEMETRY="1" AFACKNOWLEDGEBACKUP="1" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername"
Start-Sleep -s 300

# Powershell.exe -executionpolicy remotesigned -File  "c:\temp\collective_trigger.ps1" 
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument  "c:\temp\collective_trigger.ps1"
Register-ScheduledTask -TaskName "collect_trigger" -Trigger $Trigger -User $username -Password $password1 -Action $Action -RunLevel Highest -Force
Disable-ScheduledTask -TaskName "vision-install"
Restart-Computer
'@
$vision_install | Out-File c:\temp\vision.ps1       

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

Set-Location C:\temp
$names = gcloud compute instances list --filter pisvr* --format="value(name)"
$af_path =  -join($names[0],'.',$domain)
Add-PIDataArchiveConnectionConfiguration -Name 'PIDA_Collective' -Path $af_path
$PIDataArchive = Get-PIDataArchiveConnectionConfiguration -Name 'PIDA_Collective' -ErrorAction Stop 
Connect-PIDataArchive -PIDataArchiveConnectionConfiguration $PIDataArchive -ErrorAction Stop 
Set-PIDataArchiveConnectionConfiguration -PIDataArchiveConnectionConfiguration $PIDataArchive -Default
$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ilb)' --zone $zone 
Remove-PIDataArchiveConnectionConfiguration -Name $afserver 
Disable-ScheduledTask -TaskName "collect_trigger"
'@
$collective_trigger | Out-File c:\temp\collective_trigger.ps1  

    Write-Host("Scheduling integrator Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password1 -Action $Action -RunLevel Highest -Force
    
    Restart-Computer
}
