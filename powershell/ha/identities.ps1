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

$Domain = gcloud compute instances describe $env:computername.ToLower() --format='value[](metadata.items.domain-name)' --zone $zone
$domain_arr = $Domain.split('.')
$domainPath = ''
for($i=0;$i -lt $domain_arr.Length;$i++){ 
    $domainPath = $domainPath+"DC="+$domain_arr[$i]+","
}
$domainPath = $domainPath.Substring(0,$domainPath.Length-1)

$PIDataArchive = Get-PIDataArchiveConnectionConfiguration -Default -ErrorAction Stop
$PIDataArchiveConnection = Connect-PIDataArchive -PIDataArchiveConnectionConfiguration $PIDataArchive -ErrorAction Stop

# Adding remaining WIS Identities and setting PI Identities security options
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Buffers" -Description "Identity for PI Buffer Subsystem and PI Buffer Server" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0 
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Interfaces" -Description "Identity for PI Interfaces" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Users" -Description "Identity for the users to get Read access on the PI Data Archive" -Enabled 1 -CanDelete 0 -AllowUseInMappings 1 -AllowUseInTrusts 1 -AllowExplicitLogin 0
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Points&Analysis Creator" -Description "Identity for PIACEService, PIAFService and users that can create and edit PI Points" -DisallowDelete
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Web Apps" -Description "Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler" -DisallowDelete
Add-PIIdentity -Connection $PIDataArchiveConnection -Name "PI Connector Relays" -Description "Identity for PI Connector Relays" -DisallowDelete

# Disabling PIWorld, pidemo and piusers
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "PIWorld" -Enabled 0 -CanDelete 0 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0.
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "pidemo" -Enabled 0 -CanDelete 1 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0
Set-PIIdentity -Connection $PIDataArchiveConnection -Name "piusers" -Enabled 0 -CanDelete 0 -AllowUseInMappings 0 -AllowUseInTrusts 0 -AllowExplicitLogin 0

$RenameIdentity = @(
    @{ExistingName = "PIEngineers"; NewName = 'PI Buffers';},
    @{ExistingName = "PIOperators"; NewName = 'PI Interfaces' ;},
    @{ExistingName = "PISupervisors"; NewName = 'PI Users' ;}
)

for($i=0 ; $i -lt $RenameIdentity.length; $i++){
    $ExistingName = $RenameIdentity[$i]['ExistingName']
    $NewName = $RenameIdentity[$i]['NewName']
    Rename-PIIdentity -Connection $PIDataArchiveConnection -ExistingName "$ExistingName" -NewName "$NewName" -ErrorAction SilentlyContinue
}
 
$PISecurityGroups = @(
    @{Name = 'PIBuff'; Description = 'Identity for PI Buffer Subsystem and PI Buffer Server'; }#,
    @{Name = 'PIInterfacesADGroup'; Description = 'Identity for PI Interfaces'; },
    @{Name = 'PIUsersADGroup'; Description = 'Identity for the Read-only users'; },
    @{Name = 'PIPointsAnalysisCreatorADGroup'; Description = 'Identity for PIACEService, PIAFService and users that can create and edit PI Points'; }
    @{Name = 'PIWebAppsADGroup'; Description = 'Identity for PI Vision, PI WebAPI, and PI WebAPI Crawler'; },
    @{Name = 'PIConnectorRelaysADGroup'; Description = 'Identity for PI Connector Relays'; },
    @{Name = 'PIDataCollectionManagersADGroup'; Description = 'Identity for PI Data Collection Managers'; }
)

for($i=0 ; $i -lt $PISecurityGroups.length; $i++){
    $name = $PISecurityGroups[$i]['Name']
    $description = $PISecurityGroups[$i]['Description']
    New-ADGroup -Name "$name" -SamAccountName "$name" -GroupCategory Security -GroupScope Global -Description "$description" -Path "OU=Computers,OU=Cloud,$domainPath"  
}

$PISecurityGroupsMap = @(
    @{Name = "BUILTIN\Administrators"; Identity = 'piadmins';},
    @{Name = "\Everyone"; Identity = 'piusers';},
    @{Name = "$domain\PIBuff"; Identity = 'PI Buffers';},
    @{Name = "$domain\PIInterfacesADGroup"; Identity = 'PI Interfaces' ;},
    @{Name = "$domain\PIUsersADGroup"; Identity = 'PI Users' ;},
    @{Name = "$domain\PIPointsAnalysisCreatorADGroup"; Identity = 'PI Points&Analysis Creator' ;}
    @{Name = "$domain\PIWebAppsADGroup"; Identity = 'PI Web Apps' ;},
    @{Name = "$domain\PIConnectorRelaysADGroup"; Identity = 'PI Connector Relays' ;},
    @{Name = "$domain\PIDataCollectionManagersADGroup"; Identity = 'PI Data Collection Managers' ;}
)

for($i=0 ; $i -lt $PISecurityGroupsMap.length; $i++){
    $name = $PISecurityGroupsMap[$i]['Name']
    $identity = $PISecurityGroupsMap[$i]['Identity']
    Add-PIMapping -Connection $PIDataArchiveConnection -Name "$name" -PrincipalName "$name" -Identity "$identity" -ErrorAction SilentlyContinue
}

# Editing the Security Databases according to KB00833
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIAFLINK" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIARCADMIN" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIARCDATA" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIAUDIT" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBACKUP" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBatch" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIBATCHLEGACY" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PICampaign" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIDBSEC" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIDS" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Points&Analysis Creator: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIHeadingSets" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIMAPPING" -Security "piadmins: A(r,w) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIModules" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIMSGSS" -Security "piadmins: A(r,w) | PIWorld: A(r,w)| PI Users: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIPOINT" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Interfaces: A(r) | PI Buffers: A(r,w) | PI Points&Analysis Creator: A(r,w) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIReplication" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITransferRecords" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITRUST" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PITUNING" -Security "piadmins: A(r,w)" -ErrorAction SilentlyContinue
Set-PIDatabaseSecurity -Connection $PIDataArchiveConnection -Name "PIUSER" -Security "piadmins: A(r,w) | PIWorld: A(r) | PI Users: A(r) | PI Web Apps: A(r)" -ErrorAction SilentlyContinue

#Testing
Add-ADGroupMember -Identity PIWebAppsADGroup -Members ds-piwe-svc$
