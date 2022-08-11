
# Getting the projet details and finding zone.
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone2 = gcloud projects describe $project --format='value[](labels.zone2)'

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.sqlwitness)' --zone $zone1)){
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

try{
    if (Get-ScheduledTask -taskname mssql1 | ? state -eq Ready){
        write-host "Task is enable..will run now"
        Start-ScheduledTask -TaskName mssql1
    }else{
        throw "1"
    }
}catch{
   if ($_.Exception.Message -eq 1){
        "Schedule task not found/disabled"
    }
}

$domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone

# Check if machine is domain joined. If yes then exit and do nothing.
Write-Host "Checking domain join"
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
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
    
    Write-Host "Adding machine to domain"

    # Join machine to domain
    Add-Computer -DomainName $domain -Credential $cred

    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools 

    Install-WindowsFeature -Name FS-Fileserver
    Install-WindowsFeature Failover-Clustering -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation     

    # Install Chrome Browser
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    # adding firewall rules
    netsh advfirewall firewall add rule name="Open Port 5022 for Availability Groups" dir=in action=allow protocol=TCP localport=5022
    netsh advfirewall firewall add rule name="Open Port 1433 for SQL Server" dir=in action=allow protocol=TCP localport=1433
    netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol="icmpv4:8,any" dir=in action=allow
    
    #$addlocaladmin = Add-LocalGroupMember -Group "Administrators" -Member "$domain\setupadmin"
    #start-process powershell -Credential $cred -ArgumentList "-command (Invoke-Command -ScriptBlock {$addlocaladmin})"

    New-Item -Path 'C:\temp\piserver\' -ItemType Directory
    Set-Location C:\temp\piserver
    write-host "inside directory "+$PWD

    gsutil -m cp -r gs://$storage/piserver/* .
    
    # Starting PI Server installation
    write-host "starting with installation"
    $cmd = .\PI-Server_2018-SP3-Patch-3_.exe /passive ADDLOCAL=FD_SQLServer,FD_SQLScriptExecution SENDTELEMETRY="1" FDSQLDBNAME="PIFD" FDSQLDBSERVER="$env:computername" AFACKNOWLEDGEBACKUP="1" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername"
    $cmd

    Start-sleep -Seconds 300

    Set-Location C:\temp\piserver\pivision-db-files
    $domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)
    $vision_sa = -join("$domain_trim","\","ds-pivs-svc$")
    $fileToCheck = "C:\temp\piserver\pivision-db-files\Go.bat"
    if (Test-Path $fileToCheck -PathType leaf){
        cd C:\temp\piserver\pivision-db-files\
        $vision_db = .\Go.bat $env:COMPUTERNAME PIVision $vision_sa
        $vision_db
    }
    else
    {
        continue
    }

    # This helps to remove any unnecessary issue
    Start-Sleep -S 10

    Set-Location C:\temp\piserver\pivision-db-files
    
    # The PowerShell script to gMSA account ds-piaf-svc$ to be member of local group “AFServers” and “AFQueryEngines” on PISQL-1 
    Add-LocalGroupMember -Group "AFServers" -Member "$domain\ds-piaf-svc$" 
    Add-LocalGroupMember -Group "AFQueryEngines" -Member "$domain\ds-piaf-svc$"
    

    # Adding BUILTIN\Administrators
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    Install-PackageProvider -Name "NuGet" -RequiredVersion "2.8.5.208" -Force   
    Install-Module -Name SqlServer -AllowClobber -Force 
    Install-Module -Name SqlServer -Force
    Import-Module SqlServer
        
    cd SQLSERVER:\SQL\localhost\default\


    $domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)

    $service_accounts = @('ds-pivs-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql1' , $name
        $sqlServer.AddToRole("sysadmin")
        $sqlServer.AddToRole("dbcreator")
        $sqlServer.AddToRole("securityadmin")
    }
    
    $service_accounts = @('ds-pint-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql1' , $name
        $sqlServer.AddToRole("dbcreator")
        $sqlServer.AddToRole("securityadmin")
    }
    


    New-Item -ItemType directory -Path C:\install
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

$node1 = "pimssql1"
$node2 = "pimssql2"
$nameWSFC = "cluster-dbclus" #Name of cluster
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
$ipWSFC2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC2)' --zone $zone
$ipWSListener1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener1)' --zone $zone
$ipWSListener2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener2)' --zone $zone


$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

Set-Location -Path C:\install

#Check if sql server is running on node1
$SQLServer1IsReady=$False
For ($i=0; $i -le 30; $i++) {
    $SqlCatalog = "master"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server = $node1;" + `
        "Database = $SqlCatalog; Integrated Security = True"
    try {
        $SqlConnection.Open()
        Write-Host "Connection to the server $node1 was successful"
        $SQLServer1IsReady=$True
        $SqlConnection.Close()
        break
    }
    catch {
        Write-Host "SQL server $node1 is not ready, waiting for 60s"
        Start-Sleep -s 60 #Wait for 60 seconds
    }
}
#check if sql server is running on node2
$SQLServer2IsReady=$False
For ($i=0; $i -le 30; $i++) {
    $SqlCatalog = "master"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server = $node2;" + `
        "Database = $SqlCatalog; Integrated Security = True"
    try {
        $SqlConnection.Open()
        Write-Host "Connection to the server $node2 was successful"
        $SQLServer2IsReady=$True
        $SqlConnection.Close()
        break
    }
    catch {
        Write-Host "SQL server $node2 is not ready, waiting for 60s"
        Start-Sleep -s 60 #Wait for 60 seconds
    }
}
if($SQLServer2IsReady -eq $False) {
    Write-Error "$node2 is not responding. Was it deployed correctly?"
}
if($SQLServer1IsReady -eq $False) {
    Write-Error "$node1 is not responding. Was it deployed correctly?"
}


#create a cluster
New-Cluster -Name $nameWSFC -Node $node1, $node2 -NoStorage -StaticAddress $ipWSFC1, $ipWSFC2

#Add listener as computer object
New-ADComputer -Name "sql-server" -SamAccountName "sql-server" -Path "OU=Computers,OU=Cloud,$domainPath"

$user=[System.Security.Principal.NTAccount]"$Domain\cluster-dbclus$"
$compPath="AD:\CN=sql-server,OU=Computers,OU=Cloud,$domainPath"

$acl= Get-Acl $compPath
$ace=New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
$User,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($ace)
Set-Acl $compPath $acl

Enable-SqlAlwaysOn -ServerInstance $node1 -Force
Enable-SqlAlwaysOn -ServerInstance $node2 -Force

#create a directory
New-Item -ItemType directory -Path C:\SQLData
New-Item -ItemType directory -Path C:\SQLLog

$CreateDatabaseSQLScript =  @"
USE [PIFD]
Exec dbo.sp_changedbowner @loginame = 'sa', @map = false;
ALTER DATABASE [PIFD] SET RECOVERY FULL;
GO
BACKUP DATABASE PIFD to disk = '\\$node2\SQLBackup\PIFD.bak' WITH INIT
GO
"@
Invoke-Sqlcmd -Query $CreateDatabaseSQLScript -ServerInstance $node1
#
#$Domain = "osi-pi-test.com"#gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone us-central1-a


$Database="PIFD"
$BackupFolder="SQLBackup"
$SharedLocation="\\$node2\$BackupFolder"
$ListenerName="sql-server"
$AGName="MainAG"
$PrimaryServer = "$node1.$Domain\MSSQLSERVER"
$SecondaryServer = "$node2.$Domain\MSSQLSERVER"


#take sql backup and restore
Backup-SqlDatabase `
    -Database $Database -Initialize `
    -BackupFile "$SharedLocation\$Database.bak" `
    -ServerInstance $node1
Restore-SqlDatabase `
    -Database $Database `
    -BackupFile "$SharedLocation\$Database.bak" `
    -ServerInstance $node2 `
    -NORECOVERY
Backup-SqlDatabase `
    -Database $Database -Initialize `
    -BackupFile "$SharedLocation\$Database.log" `
    -ServerInstance $node1 `
    -BackupAction Log
Restore-SqlDatabase `
    -Database $Database `
    -BackupFile "$SharedLocation\$Database.log" `
    -ServerInstance $node2 `
    -RestoreAction Log `
    -NORECOVERY
$endpoint1=New-SqlHADREndpoint -Port 5022 -Owner sa `
    -Encryption Supported -EncryptionAlgorithm Aes `
    -Name AlwaysonEndpoint1 `
    -Path "SQLSERVER:\SQL\$node1.$Domain\Default"
Set-SqlHADREndpoint -InputObject $endpoint1 -State Started
$endpoint2=New-SqlHADREndpoint -Port 5022 -Owner sa `
    -Encryption Supported -EncryptionAlgorithm Aes `
    -Name AlwaysonEndpoint2 `
    -Path "SQLSERVER:\SQL\$node2.$Domain\Default"
Set-SqlHADREndpoint -InputObject $endpoint2 -State Started


Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" -ServerInstance $node1
Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" -ServerInstance $node2


###
$EndpointUrlSQLServer1="TCP://" + $node1 + "." + $Domain + ":5022"
$EndpointUrlSQLServer2="TCP://" + $node2 + "." + $Domain + ":5022"
##
$PrimaryReplica = New-SqlAvailabilityReplica -Name $node1 `
    -EndpointUrl $EndpointUrlSQLServer1 `
    -FailoverMode "Automatic" `
    -AvailabilityMode "SynchronousCommit" `
    -AsTemplate -Version 13
$SecondaryReplica = New-SqlAvailabilityReplica -Name $node2 `
    -EndpointUrl $EndpointUrlSQLServer2 `
    -FailoverMode "Automatic" `
    -AvailabilityMode "SynchronousCommit" `
    -AsTemplate -Version 13
New-SqlAvailabilityGroup -Name $AGName `
    -AvailabilityReplica @($PrimaryReplica, $SecondaryReplica) `
    -Path "SQLSERVER:\SQL\$node1.$Domain\Default" `
    -Database $Database
Join-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\$node2\Default" -Name $AGName
Add-SqlAvailabilityDatabase `
    -Path "SQLSERVER:\SQL\$node2\Default\AvailabilityGroups\$AGName" `
    -Database $Database
New-SqlAvailabilityGroupListener -Name $ListenerName `
    -Port 1433 `
    -StaticIp @("$ipWSListener1/255.255.255.0","$ipWSListener2/255.255.255.0") `
    -Path SQLSERVER:\Sql\$node1\Default\AvailabilityGroups\$AGName

try{
    gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=sql1Ready="True"
}catch{
    $Error[0] | Out-Null
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

while(!($flag =gsutil stat gs://$storage/collective_success.txt))
    {
        Start-Sleep -s 10
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

$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone

$node1 = "pimssql1"
$node2 = "pimssql2"
$nameWSFC = "cluster-dbclus" 
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
$ipWSFC2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC2)' --zone $zone
$ipWSListener1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener1)' --zone $zone
$ipWSListener2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener2)' --zone $zone

$domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)

Set-Location -Path C:\install

#Check if sql server is running on node1
$SQLServer1IsReady=$False
For ($i=0; $i -le 30; $i++) {
    $SqlCatalog = "master"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server = $node1;" + `
        "Database = $SqlCatalog; Integrated Security = True"
    try {
        $SqlConnection.Open()
        Write-Host "Connection to the server $node1 was successful"
        $SQLServer1IsReady=$True
        $SqlConnection.Close()
        break
    }
    catch {
        Write-Host "SQL server $node1 is not ready, waiting for 60s"
        Start-Sleep -s 60 #Wait for 60 seconds
    }
}
#check if sql server is running on node2
$SQLServer2IsReady=$False
For ($i=0; $i -le 30; $i++) {
    $SqlCatalog = "master"
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server = $node2;" + `
        "Database = $SqlCatalog; Integrated Security = True"
    try {
        $SqlConnection.Open()
        Write-Host "Connection to the server $node2 was successful"
        $SQLServer2IsReady=$True
        $SqlConnection.Close()
        break
    }
    catch {
        Write-Host "SQL server $node2 is not ready, waiting for 60s"
        Start-Sleep -s 60 #Wait for 60 seconds
    }
}
if($SQLServer2IsReady -eq $False) {
    Write-Error "$node2 is not responding. Was it deployed correctly?"
}
if($SQLServer1IsReady -eq $False) {
    Write-Error "$node1 is not responding. Was it deployed correctly?"
}

$databases = @('PIIntegratorDB','PIIntegratorStats','PIIntegratorLogs','PIVision','ReportServer','ReportServerTempDB')
$sa1 = -join($domain_trim,"\",'ds-pint-svc$')
$sa2 = -join($domain_trim,"\",'ds-pivs-svc$')
foreach($db in $databases){
    $vision = 'PIVision'
    $sa = $sa1
    if($db -eq $vision){
        $sa = $sa2
    }

    $Database=$db 
    $BackupFolder=$Database
    $SharedLocation="\\$node2\$BackupFolder"
    $ListenerName="sql-server"
    $ag = -join("$Database","_","AG")
    $AGName=$ag
    $PrimaryServer = "$node1.$Domain\MSSQLSERVER"
    $SecondaryServer = "$node2.$Domain\MSSQLSERVER"


    $CreateDatabaseSQLScript =  @"
    USE [$Database]

    ALTER DATABASE [$Database] SET RECOVERY FULL;
    GO
    BACKUP DATABASE $Database to disk = '\\$node2\$BackupFolder\$Database.bak' WITH INIT
    GO
"@ 

    Invoke-Sqlcmd -Query $CreateDatabaseSQLScript 

    #take sql backup and restore
    Backup-SqlDatabase `
        -Database $Database -Initialize `
        -BackupFile "$SharedLocation\$Database.bak" `
        -ServerInstance $node1

    Restore-SqlDatabase `
        -Database $Database `
        -BackupFile "$SharedLocation\$Database.bak" `
        -ServerInstance $node2 `
        -NORECOVERY

    Backup-SqlDatabase `
        -Database $Database -Initialize `
        -BackupFile "$SharedLocation\$Database.log" `
        -ServerInstance $node1 `
        -BackupAction Log

    Restore-SqlDatabase `
        -Database $Database `
        -BackupFile "$SharedLocation\$Database.log" `
        -ServerInstance $node2 `
        -RestoreAction Log `
        -NORECOVERY

    Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" 
    Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" 


    
    $EndpointUrlSQLServer1="TCP://" + $node1 + "." + $Domain + ":5022"
    $EndpointUrlSQLServer2="TCP://" + $node2 + "." + $Domain + ":5022"
    


    $PrimaryReplica = New-SqlAvailabilityReplica -Name $node1 `
        -EndpointUrl $EndpointUrlSQLServer1 `
        -FailoverMode "Automatic" `
        -AvailabilityMode "SynchronousCommit" `
        -AsTemplate -Version 13

    $SecondaryReplica = New-SqlAvailabilityReplica -Name $node2 `
        -EndpointUrl $EndpointUrlSQLServer2 `
        -FailoverMode "Automatic" `
        -AvailabilityMode "SynchronousCommit" `
        -AsTemplate -Version 13

    New-SqlAvailabilityGroup -Name $AGName `
        -AvailabilityReplica @($PrimaryReplica, $SecondaryReplica) `
        -Path "SQLSERVER:\SQL\$node1.$Domain\Default" `
        -Database $Database

    Join-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\$node2\Default" -Name $AGName

    Add-SqlAvailabilityDatabase `
        -Path "SQLSERVER:\SQL\$node2\Default\AvailabilityGroups\$AGName" `
        -Database $Database

    # New-SqlAvailabilityGroupListener -Name $ListenerName `
    #     -Port 1433 `
    #     -StaticIp @("$ipWSListener1/255.255.255.0","$ipWSListener2/255.255.255.0") `
    #     -Path SQLSERVER:\Sql\$node1\Default\AvailabilityGroups\$AGName
    Start-Sleep -S 10
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

Invoke-Command -ScriptBlock{
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
$dol = '$'
$ani1 = gcloud compute instances describe pibastion1 --format='value[](metadata.items.an1Name)' --zone $zone1 
$ani2 = gcloud compute instances describe pibastion1 --format='value[](metadata.items.an2Name)' --zone $zone1 
$an1 = $ani1 + $dol
$an2 = $ani2 + $dol
$machine_names = @($an1,$an2)

foreach ($mn in $machine_names){
    $domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)
    $name = -join("$domain_trim","\",$mn)
    Import-Module SqlServer
    cd SQLSERVER:\SQL\localhost\default\
    Add-SqlLogin -LoginName $name -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
    $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Server -ArgumentList 'pimssql2'
    $database = $sqlServer.Databases['PIIntegratorDB']
    $login = $sqlServer.Logins[$name]
    $dbUser = New-Object -TypeName Microsoft.SqlServer.Management.Smo.User -ArgumentList $database, $name
    $dbUser.Login = $name
    $dbUser.Create()
    $dbrole = $database.Roles['db_datareader']
    $dbrole.AddMember($name)
    
    }
} -ComputerName 'pimssql2'

Import-Module SqlServer
        
cd SQLSERVER:\SQL\localhost\default\

write-host "admin add"
Add-SqlLogin -LoginName BUILTIN\Administrators -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql1' , "BUILTIN\Administrators"
$sqlServer.AddToRole("sysadmin")
Remove-SqlLogin -LoginName "BUILTIN\Users" -Force 

$service_accounts = @('ds-pivs-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        Remove-SqlLogin -LoginName $name -Force
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql1' , $name
        $sqlServer.AddToRole("dbcreator")
        $sqlServer.AddToRole("securityadmin")
    }
Invoke-Command -ScriptBlock { 

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

Import-Module SqlServer
cd SQLSERVER:\SQL\localhost\default\
write-host "admin add"
Add-SqlLogin -LoginName BUILTIN\Administrators -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql2' , "BUILTIN\Administrators"
$sqlServer.AddToRole("sysadmin")
Remove-SqlLogin -LoginName "BUILTIN\Users" -Force  } -ComputerName 'pimssql2'


Add-ADGroupMember -Identity PIBuff -Members ds-pibufss-svc$
Add-ADGroupMember -Identity PIPointsAnalysisCreatorADGroup -Members ds-piaf-svc$,ds-pian-svc$


Start-Sleep -s 60

#Adding fileshare witness
Set-ClusterQuorum -NodeAndFileShareMajority \\PISQLWITNESS1\witness-share

Write-Host "Out of sleep. Creating intdb_success.txt file"
#Create sucess file flag for AF server
New-Item c:\temp\intdb_success.txt
gsutil cp c:\temp\intdb_success.txt gs://$storage/intdb_success.txt


#to be changed
Disable-ScheduledTask -TaskName "mssql1"
'@
    $MultilineComment | Out-File $PWD\mssql.ps1

$sync = @'

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

$node1 = "pimssql1"
$node2 = "pimssql2"
$nameWSFC = "cluster-dbclus" #Name of cluster
$ipWSFC1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC1)' --zone $zone
$ipWSFC2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSFC2)' --zone $zone
$ipWSListener1 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener1)' --zone $zone
$ipWSListener2 = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.ipWSListener2)' --zone $zone

$db = "PIFD"
$Database= $db
$BackupFolder="SQLBackup"
$SharedLocation="\\$node2\$BackupFolder"
$ListenerName="sql-server"
$AGName="MainAG"
$PrimaryServer = "$node1.$Domain\MSSQLSERVER"
$SecondaryServer = "$node2.$Domain\MSSQLSERVER"

######################### Availablity Group faiover configure ##############################################

Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\MainAG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\PIIntegratorDB_AG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\PIIntegratorLogs_AG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\PIIntegratorStats_AG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\PIVision_AG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\ReportServer_AG" -AllowDataLoss -Force
Switch-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\PIMSSQL1\Default\AvailabilityGroups\ReportServerTempDB_AG" -AllowDataLoss -Force
Start-Sleep -S 60

####################################################################################################################
Import-Module SqlServer
Remove-SqlAvailabilityGroup -Path SQLSERVER:\SQL\$node1.$Domain\Default\AvailabilityGroups\$AGName
invoke-sqlcmd -ServerInstance "pimssql2"  -Query "Drop database $db;"

Import-Module SqlServer
cd SQLSERVER:\SQL\localhost\default\
Add-SqlLogin -LoginName BUILTIN\Users -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
$sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql1' , "BUILTIN\Users"
$sqlServer.AddToRole("sysadmin")

 Invoke-Command -ScriptBlock { 
    Import-Module SqlServer
    cd SQLSERVER:\SQL\localhost\default\
    Add-SqlLogin -LoginName BUILTIN\Users -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
    $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pimssql2' , "BUILTIN\Users"
    $sqlServer.AddToRole("sysadmin") 
} -ComputerName 'pimssql2'

$CreateDatabaseSQLScript =  @"
USE [PIFD]
Exec dbo.sp_changedbowner @loginame = 'sa', @map = false;
ALTER DATABASE [PIFD] SET RECOVERY FULL;
GO
BACKUP DATABASE PIFD to disk = '\\$node2\SQLBackup\PIFD.bak' WITH INIT
GO
"@
Invoke-Sqlcmd -Query $CreateDatabaseSQLScript -ServerInstance $node1
#
#$Domain = "osi-pi-test.com"#gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone us-central1-a


$Database="PIFD"
$BackupFolder="SQLBackup"
$SharedLocation="\\$node2\$BackupFolder"
$ListenerName="sql-server"
$AGName="MainAG"
$PrimaryServer = "$node1.$Domain\MSSQLSERVER"
$SecondaryServer = "$node2.$Domain\MSSQLSERVER"


#take sql backup and restore
Backup-SqlDatabase `
    -Database $Database -Initialize `
    -BackupFile "$SharedLocation\$Database.bak" `
    -ServerInstance $node1
Restore-SqlDatabase `
    -Database $Database `
    -BackupFile "$SharedLocation\$Database.bak" `
    -ServerInstance $node2 `
    -NORECOVERY
Backup-SqlDatabase `
    -Database $Database -Initialize `
    -BackupFile "$SharedLocation\$Database.log" `
    -ServerInstance $node1 `
    -BackupAction Log
Restore-SqlDatabase `
    -Database $Database `
    -BackupFile "$SharedLocation\$Database.log" `
    -ServerInstance $node2 `
    -RestoreAction Log `
    -NORECOVERY


###
$EndpointUrlSQLServer1="TCP://" + $node1 + "." + $Domain + ":5022"
$EndpointUrlSQLServer2="TCP://" + $node2 + "." + $Domain + ":5022"
##
$PrimaryReplica = New-SqlAvailabilityReplica -Name $node1 `
    -EndpointUrl $EndpointUrlSQLServer1 `
    -FailoverMode "Automatic" `
    -AvailabilityMode "SynchronousCommit" `
    -AsTemplate -Version 13
$SecondaryReplica = New-SqlAvailabilityReplica -Name $node2 `
    -EndpointUrl $EndpointUrlSQLServer2 `
    -FailoverMode "Automatic" `
    -AvailabilityMode "SynchronousCommit" `
    -AsTemplate -Version 13
New-SqlAvailabilityGroup -Name $AGName `
    -AvailabilityReplica @($PrimaryReplica, $SecondaryReplica) `
    -Path "SQLSERVER:\SQL\$node1.$Domain\Default" `
    -Database $Database
Join-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\$node2\Default" -Name $AGName
Add-SqlAvailabilityDatabase `
    -Path "SQLSERVER:\SQL\$node2\Default\AvailabilityGroups\$AGName" `
    -Database $Database
New-SqlAvailabilityGroupListener -Name $ListenerName `
    -Port 1433 `
    -StaticIp @("$ipWSListener1/255.255.255.0","$ipWSListener2/255.255.255.0") `
    -Path SQLSERVER:\Sql\$node1\Default\AvailabilityGroups\$AGName
$databases = @('PIIntegratorDB','PIIntegratorStats','PIIntegratorLogs','PIVision','ReportServer','ReportServerTempDB')
$sa1 = -join($domain_trim,"\",'ds-pint-svc$')
$sa2 = -join($domain_trim,"\",'ds-pivs-svc$')
foreach($db in $databases){
    $vision = 'PIVision'
    $sa = $sa1
    if($db -eq $vision){
        $sa = $sa2
    }
    
    $Database=$db 
    $BackupFolder=$Database
    $SharedLocation="\\$node2\$BackupFolder"
    $ListenerName="sql-server"
    $ag = -join("$Database","_","AG")
    $AGName=$ag
    $PrimaryServer = "$node1.$Domain\MSSQLSERVER"
    $SecondaryServer = "$node2.$Domain\MSSQLSERVER"
    Import-Module SqlServer
    Remove-SqlAvailabilityGroup -Path SQLSERVER:\SQL\$node1.$Domain\Default\AvailabilityGroups\$AGName
    Start-Sleep -S 5
    invoke-sqlcmd -ServerInstance "pimssql2"  -Query "Drop database $db;"

    

    $CreateDatabaseSQLScript =  @"
    USE [$Database]

    ALTER DATABASE [$Database] SET RECOVERY FULL;
    GO
    BACKUP DATABASE $Database to disk = '\\$node2\$BackupFolder\$Database.bak' WITH INIT
    GO
"@ 

    Invoke-Sqlcmd -Query $CreateDatabaseSQLScript -ServerInstance $node1

    #take sql backup and restore
    Backup-SqlDatabase `
        -Database $Database -Initialize `
        -BackupFile "$SharedLocation\$Database.bak" `
        -ServerInstance $node1

    Restore-SqlDatabase `
        -Database $Database `
        -BackupFile "$SharedLocation\$Database.bak" `
        -ServerInstance $node2 `
        -NORECOVERY

    Backup-SqlDatabase `
        -Database $Database -Initialize `
        -BackupFile "$SharedLocation\$Database.log" `
        -ServerInstance $node1 `
        -BackupAction Log

    Restore-SqlDatabase `
        -Database $Database `
        -BackupFile "$SharedLocation\$Database.log" `
        -ServerInstance $node2 `
        -RestoreAction Log `
        -NORECOVERY

    Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" 
    Invoke-Sqlcmd -Query "select name, state_desc, port FROM sys.tcp_endpoints" 


    
    $EndpointUrlSQLServer1="TCP://" + $node1 + "." + $Domain + ":5022"
    $EndpointUrlSQLServer2="TCP://" + $node2 + "." + $Domain + ":5022"
    


    $PrimaryReplica = New-SqlAvailabilityReplica -Name $node1 `
        -EndpointUrl $EndpointUrlSQLServer1 `
        -FailoverMode "Automatic" `
        -AvailabilityMode "SynchronousCommit" `
        -AsTemplate -Version 13

    $SecondaryReplica = New-SqlAvailabilityReplica -Name $node2 `
        -EndpointUrl $EndpointUrlSQLServer2 `
        -FailoverMode "Automatic" `
        -AvailabilityMode "SynchronousCommit" `
        -AsTemplate -Version 13

    New-SqlAvailabilityGroup -Name $AGName `
        -AvailabilityReplica @($PrimaryReplica, $SecondaryReplica) `
        -Path "SQLSERVER:\SQL\$node1.$Domain\Default" `
        -Database $Database

    Join-SqlAvailabilityGroup -Path "SQLSERVER:\SQL\$node2\Default" -Name $AGName
    Start-Sleep -S 5
    Add-SqlAvailabilityDatabase `
        -Path "SQLSERVER:\SQL\$node2\Default\AvailabilityGroups\$AGName" `
        -Database $Database

    
    Start-Sleep -S 20
} 
cd SQLSERVER:\SQL\localhost\default\
Remove-SqlLogin -LoginName "BUILTIN\Users" -Force

 Invoke-Command -ScriptBlock { 
    Import-Module SqlServer
    cd SQLSERVER:\SQL\localhost\default\
    Remove-SqlLogin -LoginName "BUILTIN\Users" -Force  
} -ComputerName 'pimssql2'
'@
$sync | Out-File $PWD\sync.ps1

    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "$PWD\mssql.ps1" 
    Register-ScheduledTask -TaskName "mssql1" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "$PWD\sync.ps1" 
    Register-ScheduledTask -TaskName "sync" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer


}
