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

# get AF Server connection and root element
$afElement = Get-AFElement -Name "OSIsoft" -AFDatabase (Get-AFDatabase -Name "Configuration" -AFServer (Get-AFServer -Name "$env:computername"))
#display element
#$afElement

# get child element - repeat as necessary for each leaf of the tree
$afElement = Get-AFElement -Name "PIANO" -AFElement $afElement
$afElement = Get-AFElement -Name "AnalysisService" -AFElement $afElement
$afElement = Get-AFElement -Name "ServiceConfiguration" -AFElement $afElement
#
## get and view the latest value for an attribute
$afAttribute = Get-AFAttribute -Name "ServiceConfiguration" -AFElement $afElement
$afAttribute.GetValue().Value #| Out-File -FilePath C:\test.xml

#$xml = [xml](Get-Content C:\test.xml)
#$xml.ANServiceConfigurationDataContract.RegisteredHosts.ANRegisteredHostDataContract.HostName = "pranay"
#$xml.ANServiceConfigurationDataContract.CommonParameters.RuntimeStorageFolderPath = "C:\ProgramData\OSIsoft1"
#$xml.Save("C:\test-new1.xml")

#$xml = Get-Content C:\test-new1.xml
#Set-AFAttribute -AFAttribute $afAttribute -CheckIn -Value 1


# set a value and query to verify it was saved
#Set-AFAttribute -AFAttribute $afAttribute -CheckIn -Value 0    
#$afAttribute.GetValue(Object)