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