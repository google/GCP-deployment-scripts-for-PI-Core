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
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
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
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    $username = "$domain\setupadmin"
    $username = "setupadmin@$domain"
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
    Add-Computer -DomainName $domain -Credential $cred

    # Install Chrome Browser and make it default
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    Write-Host "Chrome installation complete"

    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools
    
    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 

        
    
    Write-Host "Creating temp directory for installation files"
    New-Item -ItemType directory -Path C:\temp
    gsutil -m cp -r gs://$storage/piweb/* C:\temp
    Start-Sleep -s 15

    Set-Location -Path C:\temp\
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -Force
    Set-PSRepository PSGallery -InstallationPolicy Trusted
    Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    Expand-7Zip -ArchiveFileName .\PI-Web-API-2019-SP1_1.13.0.6518_.exe -TargetPath '.\'

$setgMSA = @'
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
# $username = "setupadmin@$domain"
$username = "setupadmin@$domain"
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}

Add-ADGroupMember -Identity omf_group -Members $env:COMPUTERNAME$
Set-ADServiceAccount -Identity ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group

Write-Host "Scheduling OMF installation Task"
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\installOMF.ps1" 
Register-ScheduledTask -TaskName "omf-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

Disable-ScheduledTask -TaskName "gMSA-install"
Unregister-ScheduledTask -TaskName "gMSA-install" -Confirm:$false

Restart-Computer
'@
$setgMSA | Out-File C:\temp\gMSA.ps1

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
    "CrawlerMaxPathCount": 1000000,
    "OmfAssetServerName": "OSI-PISERVER",
    "OmfAssetDatabaseName": "OMF_DB",
    "OmfDataArchiveName": "piidentity"
}
'@
$installconfig | Out-File c:\temp\InstallationConfig.json

$installOMF = @'
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

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
#$username = "$domain\setupadmin"    
$username = "setupadmin@$domain"
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$afserver = gcloud compute forwarding-rules describe fwd-pisvr-1 --region $region --format="value(serviceName)"
Set-Location -Path C:\temp\PIWebAPI*

$domain_arr = $domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

$ConfigAssetServer =  "$afserver" 
$CrawlerSubmitUrl = "https://$env:computername/piwebapi/"
$ConfigInstance = $env:computername
$OmfAssetServerName = "$afserver"
$OmfAssetDatabaseName = "OMF_DB"
$OmfDataArchiveName = "$afserver"

#To change in config.json
$JSON = Get-Content -Path "C:\temp\InstallationConfig.json" | ConvertFrom-JSON

$JSON | Add-Member -Name "ConfigAssetServer" -MemberType NoteProperty -Value "$ConfigAssetServer" -Force
$JSON | Add-Member -Name "CrawlerSubmitUrl" -MemberType NoteProperty -Value $CrawlerSubmitUrl -Force
$JSON | Add-Member -Name "ConfigInstance" -MemberType NoteProperty -Value "$ConfigInstance" -Force
$JSON | Add-Member -Name "OmfAssetServerName" -MemberType NoteProperty -Value "$OmfAssetServerName" -Force  
$JSON | Add-Member -Name "OmfAssetDatabaseName" -MemberType NoteProperty -Value "$OmfAssetDatabaseName" -Force  
$JSON | Add-Member -Name "OmfDataArchiveName" -MemberType NoteProperty -Value "$OmfDataArchiveName" -Force  

$JSON | ConvertTo-JSON | Out-File "C:\temp\InstallationConfig.json"

$fileContent = Get-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini
$textToAdd = ' ADDLOCAL=ALL CONFIG_FILE=C:\temp\InstallationConfig.json'
$fileContent[93] += $textToAdd
$fileContent | Set-Content C:\temp\PIWebAPI_1.13.0.6518\silent.ini

write-host("Starting web omf installation")
$cmd = .\Setup.exe -f .\silent.ini
$proc = Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)" 
$proc
Start-Sleep -s 180
$svcs = @('picrawler','piwebapi')
$gMSA = "$domain\ds-piwe-svc$"
foreach($svc in $svcs){
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$svc'"
    $service.Change($null, $null, $null, $null, $null, $null, $gMSA, $null, $null, $null, $null)
}
Disable-ScheduledTask -TaskName "omf-install"
Unregister-ScheduledTask -TaskName "omf-install" -Confirm:$false
Remove-Item C:\temp\installOMF.ps1
'@
$installOMF | Out-File C:\temp\installOMF.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}

