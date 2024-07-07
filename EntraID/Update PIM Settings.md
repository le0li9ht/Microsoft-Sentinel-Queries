```
AuditLogs
| where TimeGenerated >ago(20h)
| where OperationName=="Update role setting in PIM"
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedIp=tostring(InitiatedBy.user.ipAddress)
| mv-expand TargetResources
| extend ModifiedProperties=TargetResources.modifiedProperties
| extend RoleName=tostring(TargetResources.displayName)
| where TargetResources.type=="Role"
//| where isnotempty(RoleName)
| project TimeGenerated,OperationName,RoleName, ResultDescription, Result, LoggedByService, CorrelationId, TargetResources, AdditionalDetails
```
