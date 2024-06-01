### SFTP account
Attackers may create an SFTP account to maintain access to a target storage account. The SFTP account is local on the storage instance and is not subject to Azure RBAC permissions. The account is also unaffected in case of storage account access keys rotation.

### MITRE ATT&CK
| Tactic | Technique | Link    |
| ---  | --- | --- |
|MS-T809-Persistence|MS-T809-SFTP account|https://microsoft.github.io/Threat-matrix-for-storage-services/techniques/sftp-account/|  

### Detection
The below query helps you to detect if the sftp is enabled on the storage account.  

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
The below query helps you to detect if the local account was created(also password modification/creation changes) as part of sftp access.
```
AzureActivity
| where TimeGenerated >ago(40m)
| where OperationNameValue in  ("MICROSOFT.STORAGE/STORAGEACCOUNTS/LOCALUSERS/WRITE","MICROSOFT.STORAGE/STORAGEACCOUNTS/LOCALUSERS/REGENERATEPASSWORD/ACTION")
| extend UserAccount=Properties_d.resource
| project TimeGenerated, OperationNameValue, ActivityStatusValue,UserAccount, ResourceGroup,Caller,CallerIpAddress
```
