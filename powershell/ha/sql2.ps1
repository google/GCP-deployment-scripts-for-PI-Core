
# Getting the projet details and finding zone.
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
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    # function Set-ChromeAsDefaultBrowser {
    #     Add-Type -AssemblyName 'System.Windows.Forms'
    #     Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome'
    #     Sleep 2
    #     [System.Windows.Forms.SendKeys]::SendWait("{TAB} {ENTER} {TAB}")
    # } 
    # Set-ChromeAsDefaultBrowser


    Write-Host "Creating new direcroty for install files"
    New-Item -ItemType directory -Path C:\install
    Set-Location -Path C:\install

    $addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
    start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"

    Install-WindowsFeature Failover-Clustering -IncludeManagementTools
    # $local_group = @('AFServers','AFQueryEngines')
    # forEach($group in $local_group){
    #     Add-LocalGroupMember -Group "$group" -Member 'ad.osi.com\osi-piserver$', 'ad.osi.com\osi-web-omf$'
        
    # }

    # The PowerShell script to gMSA account ds-piaf-svc$ to be member of local group “AFServers” and “AFQueryEngines” on PISQL-2
    Add-LocalGroupMember -Group "AFServers" -Member "$domain\ds-piaf-svc$" 
    Add-LocalGroupMember -Group "AFQueryEngines" -Member "$domain\ds-piaf-svc$"


    # Adding BUILTIN\Administrators
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    Install-PackageProvider -Name "NuGet" -RequiredVersion "2.8.5.208" -Force   
    Install-Module -Name SqlServer -AllowClobber -Force 
    Install-Module -Name SqlServer -Force
    Import-Module SqlServer
        
    cd SQLSERVER:\SQL\localhost\default\

    # write-host "admin add"
    # Add-SqlLogin -LoginName BUILTIN\Administrators -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
    # $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql2' , "BUILTIN\Administrators"
    # $sqlServer.AddToRole("sysadmin")
    # Remove-SqlLogin -LoginName "BUILTIN\Users" -Force  

    $domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)

    write-host "pint add"
    $service_accounts = @('ds-pint-svc$','ds-pivs-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        
        
    }
    Set-Location -Path C:\install
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
$password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')}
$cred = New-Object System.Management.Automation.PSCredential($username,$password)
$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)




New-Item -ItemType directory -Path C:\SQLData
New-Item -ItemType directory -Path C:\SQLLog
New-Item -ItemType directory -Path C:\SQLBackup
New-SMBShare -Name SQLBackup -Path C:\SQLBackup -FullAccess "Authenticated Users"

$databases = @('PIIntegratorDB','PIIntegratorStats','PIIntegratorLogs','PIVision','ReportServer','ReportServerTempDB')

foreach($db in $databases){
    $path = -join("$db","_","data")
    New-Item -ItemType directory -Path C:\$path
    $path = -join("$db","_","log")
    New-Item -ItemType directory -Path C:\$path
    New-Item -ItemType directory -Path C:\$db
    New-SMBShare -Name $db -Path C:\$db -FullAccess "Authenticated Users"
}

New-Item -ItemType File C:\success_SQL2.txt
gsutil -m cp c:\success_SQL2.txt gs://$storage/success_sql2.txt
#Setting flag for SQL1
try{
    gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=sql2Ready="True"
}catch{
    $Error[0] | Out-Null
}
$Trigger= New-ScheduledTaskTrigger -AtStartup
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\install\sync.ps1" 
Register-ScheduledTask -TaskName "sync" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force
#to be changed
Disable-ScheduledTask -TaskName "mssql2"
'@
$MultilineComment | Out-File $PWD\mssql2.ps1

$sync = @'
Start-ScheduledTask -TaskName "sync" -CimSession "pimssql1"
'@
$sync | Out-File $PWD\sync.ps1



$af_sql = @'
$owner = ((Get-ClusterGroup -Name MainAG).OwnerNode).Name 
if ($owner -eq 'pimssql2'){
$project = gcloud config list --format=value'(core.project)'
$zone1 =  gcloud projects describe $project --format='value[](labels.zone2)'

# Get domain name from metadata
$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1

# Get bucket name where executables are stored.
$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
Import-Module SqlServer
cd SQLSERVER:\SQL\localhost\default\ 


$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'sql-server'
$db = "PIFD"

$database = $sqlServer.Databases[$db]
$domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)
$name = -join("PIMSSQL2","\",'AFServers') 
Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , $name

$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'sql-server'
Invoke-Sqlcmd -Query "USE [PIFD]
GO
CREATE USER [PIMSSQL2\AFServers] FOR LOGIN [PIMSSQL2\AFServers]
GO
USE [PIFD]
GO
ALTER ROLE [db_AFServer] ADD MEMBER [PIMSSQL2\AFServers]
GO"  



$name = -join("PIMSSQL2","\",'AFQueryEngines')
Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
 $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'sql-server' , $name
$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'sql-server'   
 

Invoke-Sqlcmd -Query "USE [PIFD]
GO
CREATE USER [PIMSSQL2\AFQueryEngines] FOR LOGIN [PIMSSQL2\AFQueryEngines]
GO
USE [PIFD]
GO
ALTER ROLE [db_AFQueryEngine] ADD MEMBER [PIMSSQL2\AFQueryEngines]
GO" 
}



'@

$af_sql | Out-File C:\install\af_sql.ps1



$dbrestarts = @'
Write-Host "restarting for database sync"
Restart-Computer
'@
$dbrestarts | Out-File C:\install\dbrestarts.ps1

Write-Host("Scheduling dbrestarts Task")
$time = [DateTime]::Now.AddMinutes(90)
$Trigger= New-ScheduledTaskTrigger -Once -At $time
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\install\dbrestarts.ps1"
$Stset = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable
$Stset.CimInstanceProperties.Item('MultipleInstances').Value = 3
Register-ScheduledTask -TaskName "Restart-server" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force -Settings $Stset


Write-Host("Scheduling Services every 1 minute")
$repeat = (New-TimeSpan -Minutes 1)
$Trigger= New-JobTrigger -Once -At (Get-Date).Date -RepeatIndefinitely -RepetitionInterval $repeat
$Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "C:\install\af_sql.ps1" 
Register-ScheduledTask -TaskName "services-restart-at-every-boot" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force


   
    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "$PWD\mssql2.ps1" 
    Register-ScheduledTask -TaskName "mssql2" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer
}
