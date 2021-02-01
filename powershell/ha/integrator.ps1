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

$integrator = @"
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone us-central1-a

$afserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.af-server)' --zone us-central1-a
$sqlserver = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.sql-server)' --zone us-central1-a
$integrator_user = "$domain\integratorsvc"
$domain_admin = "$domain\setupadmin"
    
$password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
$password1 = [string]::join("",($password1.Split("`n")))
$domain_pass = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($domain_admin,$domain_pass)
$pass1 = gcloud secrets versions access 1 --secret=integrator-secret 
        
$integrator_password1 = gcloud secrets versions access 1 --secret=integrator-secret
$integrator_password1 = [string]::join("",($integrator_password1.Split("`n")))
    
$integrator_Password = $integrator_password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    
Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools    
    
New-ADUser -DisplayName:"Integrator" -GivenName:"Integrator" -Name:"Integrator" -Path:"OU=Cloud,DC=osi-pi-test,DC=com" -ProfilePath:$null -SamAccountName:"integratorsvc" `
-Type:"user" -UserPrincipalName:"integratorsvc@osi-pi-test.com" -PasswordNeverExpires $true -CannotChangePassword $true -AccountPassword $integrator_Password -Enabled $True
    
Add-ADPrincipalGroupMembership -Identity:"CN=Integrator,OU=Cloud,DC=osi-pi-test,DC=com" `
-MemberOf:"CN=Cloud Service Administrators,OU=Cloud Service Objects,DC=osi-pi-test,DC=com"
Set-Location C:\temp
    
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
    
Expand-7Zip -ArchiveFileName .\OSIsoft.PIIntegratorBA_2020_ADV_1000_2.3.0.425_.exe -TargetPath 'C:\temp\pi-integrator\'
Set-Location C:\temp\pi-integrator
    
$location = Get-Location
    
(Get-Content .\silent.ini) `
    | %{ $_ -replace "9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus.+","9 = /q ALLUSERS=1 REBOOT=Suppress REINSTALLMODE=emus SENDTELEMETRY=0 SERVICEACCOUNT=$integrator_user SERVICEPASSWORD=$pass1 AFSERVER=$afserver SQLSERVER=$sqlserver USERPORT=444 SQLHOSTNAME=$sqlserver"} `
    | Set-Content .\silent.ini
    
$cmd = .\Setup.exe -f .\silent.ini
Start-Process powershell -Credential $cred -ArgumentList "-command($cmd)"
    
#Create sucess file flag for integrator server
New-Item C:\temp\integrator_success.txt
gsutil -m cp c:\temp\integrator_success.txt gs://$storage/integrator_succ.txt
    
Disable-ScheduledTask -TaskName "integrator-install"
"@
$integrator | Out-File $PWD\integrator-install.ps1
