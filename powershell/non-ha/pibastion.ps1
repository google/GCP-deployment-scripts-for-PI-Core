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
Write-Host "Checking domain join"
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1
    #$username = "$domain\setupadmin"
    $username = "setupadmin@$domain" ## any reason for this change and not use above
    
    # Read password from secret manager, remove whitespaces and extra characters 
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    
    # Create credentials object 
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    
    # Join machine to domain
    Write-Host "Adding machine to domain"
    Add-Computer -DomainName $domain -Credential $cred

    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 

    # Create staging location for executables 
    Write-Host "Creating temp directory for installation files"
    New-Item -ItemType directory -Path C:\temp
    Set-Location -Path C:\temp

# Create gMSA.ps1 file to be executed by scheduler on the next boot.
$MultilineComment = @'
# Getting the projet details and finding zone. Needed for updating metadata in bastion
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Read domain name from metadata
$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Create dynamic domain path basted on domain name. Needed to creating objects in AD.
$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

#SQL server group and gMSA
New-ADGroup -Name sql_group -Description "Security group for sql_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
New-ADServiceAccount -Name sql_service -PrincipalsAllowedToRetrieveManagedPassword sql_group -Enabled:$true -DNSHostName $Domain -SamAccountName sql_service

#piserver  group and gMSA
New-ADGroup -Name piserver_group -Description "Security group for af_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
New-ADServiceAccount -Name ds-piaf-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piaf-svc
New-ADServiceAccount -Name ds-pian-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pian-svc
New-ADServiceAccount -Name ds-pino-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pino-svc
New-ADServiceAccount -Name ds-pidas-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pidas-svc

#Buffer system gMSA
New-ADServiceAccount -Name ds-pibufss-svc -PrincipalsAllowedToRetrieveManagedPassword piserver_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pibufss-svc

#Vision and web gMSA
New-ADGroup -Name vision_group -Description "Security group for vision_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
New-ADServiceAccount -Name ds-pivs-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pivs-svc
New-ADServiceAccount -Name ds-pint-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-pint-svc
New-ADServiceAccount -Name ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword vision_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piwe-svc

# web omf gMSA
New-ADGroup -Name omf_group -Description "Security group for vision_group computers" -GroupCategory Security -GroupScope Global -Path "OU=Computers,OU=Cloud,$domainPath"
New-ADServiceAccount -Name ds-piwe-svc -PrincipalsAllowedToRetrieveManagedPassword omf_group -Enabled:$true -DNSHostName $Domain -SamAccountName ds-piwe-svc

# Update bastion metadata to trigger script executaion of SQL server
gcloud compute instances add-metadata $env:computername.ToLower() --zone=$zone1 --metadata=bastionReady="True"

# Disable gMSA-install task so that it wont execute on the next boot.
Disable-ScheduledTask -TaskName "gMSA-install"
Unregister-ScheduledTask -TaskName "gMSA-install" -Confirm:$false
Remove-Item C:\temp\*.ps1*
'@
$MultilineComment | Out-File C:\temp\gMSA.ps1

    Write-Host("Scheduling gMSA Task")
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\temp\gMSA.ps1" 
    Register-ScheduledTask -TaskName "gMSA-install" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}
