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
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
    Add-Computer -DomainName $domain -Credential $cred

    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

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
$username = "$domain\setupadmin"
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}

Add-ADGroupMember -Identity omf_group -Members $env:COMPUTERNAME$
Set-ADServiceAccount -Identity ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group
Set-ADServiceAccount -Identity ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group

Write-Host "Scheduling OMF installation Task"
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\installOMF.ps1" 
Register-ScheduledTask -TaskName "omf-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

Disable-ScheduledTask -TaskName "gMSA-install"

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
$username = "$domain\setupadmin"    
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username,$password)

Set-ADServiceAccount -Identity ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group

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
$OmfAssetServerName = "$afserver"
$OmfAssetDatabaseName = "OMF_DB"
$OmfDataArchiveName = "$afserver"
$ApiServiceAccountType = "Custom" 
$ApiServiceAccountUsername = "$ServiceAccountUsername"
$CrawlerServiceAccountType = "Custom"
$CrawlerServiceAccountUsername = "$ServiceAccountUsername"

#To change in config.json
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

# Update silent.ini with required values 
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

$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone

#Create sucess file flag for omf server
New-Item C:\temp\omf_success.txt
gsutil -m cp c:\temp\omf_success.txt gs://$storage/omf_success.txt

# Disable-ScheduledTask -TaskName "omf-install"
'@
$installOMF | Out-File C:\temp\installOMF.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}