
# Getting the projet details and finding zone.
$project = gcloud config list --format=value'(core.project)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'
$zone3 = gcloud projects describe $project --format='value[](labels.zone3)'

while(!($flag = gcloud compute instances describe pibastion1 --format='value[](metadata.items.af1Ready)' --zone $zone1)){
    write-host $flag
    write-host "sleep for 10 sec"
    Start-Sleep -s 10
}

try{
    if (Get-ScheduledTask -taskname iscsi-installer | ? state -eq Ready){
        write-host "Task is enable..will run now"
        Start-ScheduledTask -TaskName iscsi-installer
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
    $domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone3
    $password1 = gcloud secrets versions access 1 --secret=osi-pi-secret
    $password1 = [string]::join("",($password1.Split("`n")))
    $password = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()} | ConvertTo-SecureString -asPlainText -Force
    $password2 = $password1 | ForEach-Object {$_.TrimStart('password: ')} |  ForEach-Object {$_.TrimStart()}
    $username = "$domain\setupadmin"
    $cred = New-Object System.Management.Automation.PSCredential($username,$password)
    #$storage = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.storage)' --zone $zone
    $LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)
    #Static IP address 
    $Network = Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:COMPUTERNAME -EA Stop | ? {$_.IPEnabled}
    $netmask  = $Network.IPSubnet[0]
    $static_ip = Get-NetIPAddress | Where-Object -FilterScript { $_.ValidLifetime -Lt ([TimeSpan]::FromDays(1)) } | Select-Object -ExpandProperty IPAddress
    $gateway = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty NextHop
    
    $dns_ips = Resolve-DnsName $domain | select -Property IPAddress
    $dns1 = $dns_ips.IPAddress.Split()[-1]
    $dns2 = $dns_ips.IPAddress.Split()[-2]
    
    netsh interface ip set address name=Ethernet static $static_ip $netmask $gateway 1
    $interface = (Get-NetAdapter).ifIndex
    Set-DnsClientServerAddress -InterfaceIndex $interface -ServerAddresses ("$dns1","$dns2")
    start-sleep -s 10
    Get-Disk | Where partitionstyle -eq "raw" | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter D -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "disk1" -Confirm:$false

    netsh advfirewall firewall add rule name="Open port for af server inbound" dir=in action=allow protocol=TCP localport=5457
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

    New-Item -ItemType directory -Path D:\iSCSI
    New-Item -ItemType directory -Path D:\temp


$iscsi_install = @'
$project = gcloud config list --format=value'(core.project)'
$zone3 = gcloud projects describe $project --format='value[](labels.zone3)'
$zone1 = gcloud projects describe $project --format='value[](labels.zone1)'

$node1_ip = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an1)' --zone $zone3
$node2_ip = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.an2)' --zone $zone3

Set-Location -Path D:\temp

Install-WindowsFeature -Name FS-Fileserver, FS-iSCSITarget-Server

New-IscsiVirtualDisk -Path "D:\iSCSI\vDISK1.vhdx" -Size 5GB
New-IscsiServerTarget -TargetName iSCSI-target1 -InitiatorId @("IPAddress:$node1_ip","IPAddress:$node2_ip")
Add-IscsiVirtualDiskTargetMapping -TargetName iSCSI-target1 -Path "D:\iSCSI\vDISK1.vhdx"

New-IscsiVirtualDisk -Path "D:\iSCSI\vDISK2.vhdx" -Size 10GB
Set-IscsiServerTarget -TargetName iSCSI-target1 -InitiatorId @("IPAddress:$node1_ip","IPAddress:$node2_ip")
Add-IscsiVirtualDiskTargetMapping -TargetName iSCSI-target1 -Path "D:\iSCSI\vDISK2.vhdx"

# New-IscsiVirtualDisk -Path "D:\iSCSI\vDISK3.vhdx" -Size 20GB
# Set-IscsiServerTarget -TargetName iSCSI-target1 -InitiatorId @("IPAddress:$node1_ip","IPAddress:$node2_ip")
# Add-IscsiVirtualDiskTargetMapping -TargetName iSCSI-target1 -Path "D:\iSCSI\vDISK3.vhdx"

# New-IscsiVirtualDisk -Path "D:\iSCSI\vDISK4.vhdx" -Size 20GB
# Set-IscsiServerTarget -TargetName iSCSI-target1 -InitiatorId @("IPAddress:$node1_ip","IPAddress:$node2_ip")
# Add-IscsiVirtualDiskTargetMapping -TargetName iSCSI-target1 -Path "D:\iSCSI\vDISK4.vhdx"

gcloud compute instances add-metadata pibastion1 --zone=$zone1 --metadata=iscsiReady="True"

'@
$iscsi_install | Out-File D:\temp\iscsi-installer.ps1


    $Trigger= New-ScheduledTaskTrigger -AtStartup
    $Action= New-ScheduledTaskAction -Execute "PowerShell" -Argument "D:\temp\iscsi-installer.ps1" 
    Register-ScheduledTask -TaskName "iscsi-installer" -Trigger $Trigger -User $username -Password $password2 -Action $Action -RunLevel Highest -Force

    Restart-Computer

}