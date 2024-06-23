SSPR
### Password Reset by admin
KQL Query for finding password reset operations performed by admins on behalf of a user

```
AuditLogs
| where TimeGenerated >ago(90d)
//| where LoggedByService=~"Self-service Password Management"
| where OperationName == "Reset password (by admin)"
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=InitiatedBy.user.userPrincipalName
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, Initiatedby,TargetUser,IpAddress, AdditionalDetails,Result, CorrelationId
```

Password change during expired password time.
```
AuditLogs
| where TimeGenerated >ago(4h)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Change password (self-service)"
| where Result == "success"
| extend TargetUser=TargetResources[0].userPrincipalName
| extend Actor=InitiatedBy.user.userPrincipalName
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName,ActivityDisplayName, Actor,IpAddress, TargetUser, LoggedByService, Result, ResultDescription, CorrelationId, AdditionalDetails
```
