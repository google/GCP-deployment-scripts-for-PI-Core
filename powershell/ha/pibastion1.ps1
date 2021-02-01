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

$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    #gcloud config list --format=value\(core.project\)
    $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
    $username = "$domain\setupadmin"
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    Add-Computer -DomainName $domain -Credential $cred

    # Install Windows RSAT Tools
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 

    # Install Chrome Browser
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    function Set-ChromeAsDefaultBrowser {
        Add-Type -AssemblyName 'System.Windows.Forms'
        Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
        Start-Sleep -s 10
        [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
    } 
    Set-ChromeAsDefaultBrowser  
     
    Write-Host "Creating temp directory for installation files"
    New-Item -ItemType directory -Path C:\temp
    Set-Location -Path C:\temp

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

$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)


$ad_comp_account = @('pimssql1','pimssql2')
$sql01 = $ad_comp_account[0]+'$'
$sql02 = $ad_comp_account[1]+'$'

ForEach($account in $ad_comp_account){
    New-ADComputer -Enabled:$true -Name:$account -Path:"OU=Computers,OU=Cloud,$domainPath" -SamAccountName:$account
    Write-Host "created "+ $account
}

#SQL server group and gMSA
New-ADGroup -Name sql_group -Description "Security group for sql_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
Add-ADGroupMember -Identity sql_group -Members $sql01,$sql02
New-ADServiceAccount -Name sql_service -PrincipalsAllowedToRetrieveManagedPassword sql_group -Enabled:$true -DNSHostName $Domain -SamAccountName sql_service

#AF server group and gMSA
New-ADGroup -Name af_group -Description "Security group for af_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
#Add-ADGroupMember -Identity af_group -Members $af01,$af02
New-ADServiceAccount -Name ds-piaf-svc -PrincipalsAllowedToRetrieveManagedPassword af_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piaf-svc
New-ADServiceAccount -Name ds-pidas-svc -PrincipalsAllowedToRetrieveManagedPassword af_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pidas-svc


#Analysis notification server group and gMSA
New-ADGroup -Name an_group -Description "Security group for af_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
#Add-ADGroupMember -Identity af_group -Members $af01,$af02
New-ADServiceAccount -Name ds-pian-svc -PrincipalsAllowedToRetrieveManagedPassword an_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pian-svc
New-ADServiceAccount -Name ds-pino-svc -PrincipalsAllowedToRetrieveManagedPassword an_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pino-svc
New-ADServiceAccount -Name ds-pint-svc -PrincipalsAllowedToRetrieveManagedPassword an_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pint-svc

#Buffer system gMSA
New-ADServiceAccount -Name ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword af_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pibufss-svc

#Vision and web gMSA
New-ADGroup -Name vision_group -Description "Security group for vision_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
#Add-ADGroupMember -Identity vision_group -Members $vi01,$vi02
New-ADServiceAccount -Name ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pivs-svc

#web omf gMSA
New-ADGroup -Name omf_group -Description "Security group for vision_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
#Add-ADGroupMember -Identity vision_group -Members $vi01,$vi02
New-ADServiceAccount -Name ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piwe-svc
New-ADServiceAccount -Name ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piwe-svc 

try{
    gcloud compute instances add-metadata $env:computername.ToLower() --zone=$zone --metadata=bastionReady="True"
}catch{
    $Error[0] | Out-Null
}

Disable-ScheduledTask -TaskName "gMSA-install"

'@
$MultilineComment | Out-File C:\temp\gMSA.ps1

    if ($zone -eq $zone1){
        Write-Host("Scheduling gMSA Task")
        $Trigger= New-ScheduledTaskTrigger -AtStartup
        $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
        Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force
    }else{
        Write-host "Not scheduling task on $env:computername"
    }    
    Restart-Computer
}
