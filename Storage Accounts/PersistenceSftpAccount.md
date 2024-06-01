
```
AzureActivity
| where TimeGenerated >ago(34m)
| where OperationNameValue contains "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
| extend StorageAccount=Properties_d.resource
| extend SftpEnabled=iff(isnull(Properties_d.requestbody),parse_json(tostring((parse_json(tostring(parse_json(Properties_d.responseBody))).properties))).isSftpEnabled,parse_json(tostring((parse_json(tostring(parse_json(Properties_d.requestbody))).properties))).isSftpEnabled)
| extend LocalUserEnabled=parse_json(tostring((parse_json(tostring(parse_json(Properties_d.responseBody))).properties))).isLocalUserEnabled
| where SftpEnabled==true
| project TimeGenerated, OperationNameValue, ActivityStatusValue,StorageAccount, ResourceGroup,Caller,CallerIpAddress, SftpEnabled,LocalUserEnabled, Properties_d
```
```
AzureActivity
| where TimeGenerated >ago(40m)
| where OperationNameValue in  ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LOCALUSERS/WRITE","MICROSOFT.STORAGE/STORAGEACCOUNTS/LOCALUSERS/REGENERATEPASSWORD/ACTION")
| extend UserAccount=Properties_d.resource
| project TimeGenerated, OperationNameValue, ActivityStatusValue,UserAccount, ResourceGroup,Caller,CallerIpAddress
```
