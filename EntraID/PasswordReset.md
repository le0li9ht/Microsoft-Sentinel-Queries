SSPR
### Password Reset by admin
KQL Query for finding password reset operations performed by admins on behalf of a user

```
AuditLogs
| where TimeGenerated >ago(1d)
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
| where TimeGenerated >ago(1d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Change password (self-service)"
| where Result == "success"
| extend TargetUser=TargetResources[0].userPrincipalName
| extend Actor=InitiatedBy.user.userPrincipalName
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName,ActivityDisplayName, Actor,IpAddress, TargetUser, LoggedByService, Result, ResultDescription, CorrelationId, AdditionalDetails
```
Find multiple password reset by admin
```
AuditLogs
| where TimeGenerated >ago(1d)
//| where LoggedByService=~"Self-service Password Management"
| where OperationName == "Reset password (by admin)"
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, Initiatedby,TargetUser,IpAddress, AdditionalDetails,Result, CorrelationId
| summarize TargetUsers=make_set(TargetUser),count() by Initiatedby
| where array_length(TargetUsers)>2
```
User accounts that has not registered sspr and failed for SSPR
```
AuditLogs
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| where ResultReason=="User's account has insufficient authentication methods defined. Add authentication info to resolve this "
| project TimeGenerated, OperationName, Initiatedby,TargetUser,IpAddress,ResultDescription, AdditionalDetails,Result, CorrelationId
```

#### SSPR Reconnaisance
Examining SSPR initiations that were never completed from suspicious IPs can serve as an early warning of potential recon. A burst of these activities for multiple accounts—especially high-value targets—reveals that your organization is likely being targeted and can serve as justification for the reconfiguration or disabling of SSPR. If a SSPR flow is completed via SMS or phone call options from a rare and suspicious IP, it may indicate a potential SIM Swap attack that was then used to perform SSPR.  

```
AuditLogs
| where TimeGenerated >ago(1d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| where ResultDescription=="User was presented with verification options"
//where ResultDescription=="User cancelled before passing the required authentication methods" //optional also attacker can close browser tab instead of cancelling it. So not accurate but a worthwhile option.
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| join kind=leftanti (
AuditLogs
| where TimeGenerated >ago(1d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| where ResultDescription has_any ("User started the","verification option")) on CorrelationId
| project TimeGenerated, OperationName, Initiatedby,TargetUser,IpAddress, AdditionalDetails,Result, CorrelationId
```
### References  
https://cloudsecurityalliance.org/blog/2023/08/09/behind-the-breach-self-service-password-reset-sspr-abuse-in-azure-ad

?
