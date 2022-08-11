# Getting the projet details and finding zone. Needed for updating metadata of bastion server
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

# Check bastion servers metadata, if bastionReady key is present then start with SQL installation otherwise sleep for 60s
while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.bastionReady)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 60 sec"
    Start-Sleep -s 60
}

# Force gMSA task to run if exist on the boot. This will execute on the second boot. 
try{
    if (Get-ScheduledTask -taskname gMSA | ? state -eq Ready){
        write-host "Task is enable..will run now"
        Start-ScheduledTask -TaskName gMSA
    }else{
        throw "1"
    }
}catch{
   if ($_.Exception.Message -eq 1){
        "Schedule task not found/disabled"
    }
}

# Check if machine is domain joined. If yes then exit and do nothing.
$flag = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
if ($flag -eq "True"){
    Write-Host ("Machine is domain joined...exiting")
}else{
    $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone1
    
    # Read password from secret manager, remove whitespaces and extra characters 
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-object {$_.TrimStart('password: ')} |  ForEach-object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-object {$_.TrimStart('password: ')} |  ForEach-object {$_.TrimStart()}
    $username = "$domain\setupadmin"

    # Install Chrome Browser and make it default
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
    Write-Host "Chrome installation complete"
    
    # Create credentials object 
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)

    # Get bucket name where executables are stored.
    $storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone1
    
    # Join machine to domain
    Write-Host "Adding machine to domain"
    Add-Computer -DomainName $domain -Credential $cred

    # Install RSAT tools for AD management
    Install-WindowsFeature -Name "RSAT-AD-Tools" -IncludeAllSubFeature -IncludeManagementTools

    # Install Windows Identity Foundation 3.5 feature
    Install-WindowsFeature Windows-Identity-Foundation 

    # Create staging location for executables 
    New-Item -Path 'C:\temp\piserver\' -ItemType Directory
    Set-Location C:\temp\piserver
    write-host "inside directory "+$PWD

    # Download executbales for installation 
    gsutil -m cp -r gs://$storage/piserver/* .


    
    # Run installation job
    write-host "starting with installation"
    $cmd = .\PI-Server_2018-SP3-Patch-3_.exe /passive ADDLOCAL=FD_SQLServer,FD_SQLScriptExecution FDSQLDBNAME="PIFD" FDSQLDBSERVER="$env:computername" AFACKNOWLEDGEBACKUP="1" PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT="$env:computername"
    #.\PI-Server_2018-SP3-Patch-1_.exe /passive ADDLOCAL=FD_SQLServer,FD_SQLScriptExecution   SENDTELEMETRY="1" FDSQLDBNAME="PIFD" FDSQLDBSERVER="$env:computername" FDREMOTEAPPS="$afserver" AFACKNOWLEDGEBACKUP="1" PISQLDAS_REMOTEAPPS=$afserver PI_ARCHIVESIZE="2048" PI_AUTOARCHIVEROOT=$env:computername
    $cmd
    Start-Sleep -S 300

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
    # this helps to remove any unnecessary issue
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
    
    Add-SqlLogin -LoginName BUILTIN\Administrators -LoginType WindowsGroup -DefaultDatabase "master" -GrantConnectSql -Enable
    $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pisql-1' , "BUILTIN\Administrators"
    $sqlServer.AddToRole("sysadmin")

    Remove-SqlLogin -LoginName "BUILTIN\Users" -Force 

    $domain_trim = $domain.ToUpper().Substring(0,$domain.Length-4)

    $service_accounts = @('ds-pivs-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pisql-1' , $name
        $sqlServer.AddToRole("sysadmin")
        $sqlServer.AddToRole("dbcreator")
        $sqlServer.AddToRole("securityadmin")
    }
    
    $service_accounts = @('ds-pint-svc$')
    foreach ($sa in $service_accounts){
        $name = -join("$domain_trim","\",$sa)
        
        Add-SqlLogin -LoginName $name -LoginType WindowsUser -DefaultDatabase "master" -GrantConnectSql -Enable
        $sqlServer = New-Object Microsoft.SqlServer.Management.Smo.Login -ArgumentList 'pisql-1' , $name
        # $sqlServer.AddToRole("sysadmin")
        $sqlServer.AddToRole("dbcreator")
        $sqlServer.AddToRole("securityadmin")
    }

    try{
        gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=sqlReady="True"
    }catch{
        $Error[0] | Out-Null
    }

    New-Item -Path C:\sql_success.txt -ItemType file
    gsutil -m cp c:\sql_success.txt gs://$storage/

    Restart-Computer
}
