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

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.bastionReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}


$data = gcloud compute instances list --project $project --format=value'(NAME,ZONE)' | findstr $env:COMPUTERNAME.ToLower()
$zone = $data.split()[1]

if($zone -eq $zone1){
    $zone -eq $zone1
}elseif($zone -eq $zone2){
    $zone -eq $zone2
}
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.bastionReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 10 sec"
    Start-Sleep -s 10
}

try{
    if (Get-ScheduledTask -taskname mssql2 | ? state -eq Ready){
        write-host "Task is enable..will run now"
        Start-ScheduledTask -TaskName mssql2
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
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')}
    $username = "$domain\setupadmin"

    # Create credentials object 
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    
    Write-Host "Adding firewall rule"
    netsh advfirewall firewall add rule name="Open Port 5022 for Availability Groups" dir=in action=allow protocol=TCP localport=5022
    netsh advfirewall firewall add rule name="Open Port 1433 for SQL Server" dir=in action=allow protocol=TCP localport=1433    
    netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow


    # Get bucket name where executables are stored.
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
    
    # Join machine to domain
    Write-Host "Adding machine to domain"
    Add-Computer -DomainName $domain -Credential $cred

    # Install RSAT tools for AD management
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


    Write-Host "Creating new direcroty for isntall files"
    New-Item -ItemType directory -Path C:\install
    Set-Location -Path C:\install

    $addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
    start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"

    Install-WindowsFeature Failover-Clustering -IncludeManagementTools
    # $local_group = @('AFServers','AFQueryEngines')
    # forEach($group in $local_group){
    #     Add-LocalGroupMember -Group "$group" -Member 'ad.osi.com\osi-piserver$', 'ad.osi.com\osi-web-omf$'
        
    # }

    # The PowerShell script to gMSA account ds-piaf-svc$ to be member of local group “AFServers” and “AFQueryEngines” on PISQL-1 
    Add-LocalGroupMember -Group "AFServers" -Member "$domain\ds-piaf-svc$" 
    Add-LocalGroupMember -Group "AFQueryEngines" -Member "$domain\ds-piaf-svc$"

$MultilineComment = @'

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
$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone



$ADControllerFQDN = "$Domain"
$ServiceAccountName = "sql_service"
$ServiceAccountPrincipalName = "$ServiceAccountName@$Domain"
$username = "$Domain\setupadmin"
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$password = $password1 | Foreach {$_.TrimStart('password: ')} |  Foreach {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)



# [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SqlWmiManagement") | out-null
# $SMOWmiserver = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer') "$computer" #Suck in the server you want
# $SMOWmiserver.Services | select name, type, ServiceAccount, DisplayName, Properties, StartMode, StartupParameters | Format-Table
# $SMOWmiserver.Services | select name, type, ServiceAccount, DisplayName, Properties, StartMode, StartupParameters | Format-List
# $ChangeService=$SMOWmiserver.Services | where {$_.name -eq "MSSQLSERVER"} #Make sure this is what you want changed!
# $ChangeService
# $UName="$Domain\$ServiceAccountName$"
# $PWord="null"
# $ChangeService.SetServiceAccount($UName, $PWord)
# $ChangeService



New-Item -ItemType directory -Path C:\SQLData
New-Item -ItemType directory -Path C:\SQLLog
New-Item -ItemType directory -Path C:\SQLBackup
New-SMBShare -Name SQLBackup -Path C:\SQLBackup -FullAccess "Authenticated Users"
New-Item -ItemType File C:\success_SQL2.txt
gsutil -m cp c:\success_SQL2.txt gs://$storage/success_sql2.txt
#Setting flag for SQL1
try{
    gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=sql2Ready="True"
}catch{
    $Error[0] | Out-Null
}

#to be changed
Disable-ScheduledTask -TaskName "mssql2"
'@
$MultilineComment | Out-File $PWD\mssql2.ps1

    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "$PWD\mssql2.ps1" 
    Register-ScheduledTask -TaskName "mssql2" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}
