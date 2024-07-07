## Microsoft Entra self-service password reset
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

#### Find multiple password reset by admin
To find password reset operations performed by admins on behalf of multiple users in Entra Id
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

### Voluntary, or forced (due to expiry) password change.
"Change password (self-service)" operation is generated during following events
* Password change during expired password time
* If user voluntarily changes his/her password from [mysignins portal](https://mysignins.microsoft.com/security-info/password/change) or [myaccount portal(going to deprecate)](https://account.activedirectory.windowsazure.com/ChangePassword.aspx).
* When an admin resets a user's password, requiring the user to reset it again (often done when a user first joins the organization or if their password is reset for security reasons)
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
### Reset Password Via Entra Reset Password Service
Below KQL query finds Successful password reset via SSPR method from [Entra Reset Password Service or Microsoft Online Password Reset](https://passwordreset.microsoftonline.com/).
```
AuditLogs
| where TimeGenerated >ago(90d)
//| where LoggedByService=="Self-service Password Management"
| where OperationName contains "Reset password (self-service)"
| where ResultDescription=="Successfully completed reset."
| where Result=="success"
| extend User=InitiatedBy.user.userPrincipalName

                        (Or)

AuditLogs
| where TimeGenerated >ago(90d)
//| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| where ResultDescription=="User successfully reset password"
| where Result=="success"
| extend User=InitiatedBy.user.userPrincipalName
```
#### Multiple user password resets via SSPR method performed from a single IP address.
The query below identifies multiple user password resets via the Self-Service Password Reset (SSPR) method performed from a single IP address.  
**Expected FPs:**  
* Users are within the same subnet, such as within a company network sharing a common public IP.  
* A DevOps or developer may be changing passwords for both test accounts and their own account simultaneously.

```
AuditLogs
| where TimeGenerated >ago(1d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Reset password (self-service)"
| where ResultDescription=="Successfully completed reset."
| where Result=="success"
| extend TargetUser=TargetResources[0].userPrincipalName
| extend Actor=InitiatedBy.user.userPrincipalName
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| extend User=InitiatedBy.user.userPrincipalName
| summarize min(TimeGenerated),max(TimeGenerated),UserList=make_set(Actor), count() by IpAddress
| where array_length(UseList)>1

```

#### User accounts that has not registered sspr and failed for SSPR
```
AuditLogs
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IpAddress=tostring(InitiatedBy.user.ipAddress)
| where ResultReason=="User's account has insufficient authentication methods defined. Add authentication info to resolve this "
| project TimeGenerated, OperationName, Initiatedby,TargetUser,IpAddress,ResultDescription, AdditionalDetails,Result, CorrelationId
```

### SSPR Reconnaisance
Examining SSPR initiations that were never completed from suspicious IPs can serve as an early warning of potential recon. A burst of these activities for multiple accounts—especially high-value targets—reveals that your organization is likely being targeted and can serve as justification for the reconfiguration or disabling of SSPR.

KQL Query for identifying SSPR reconnaisance  

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


### Successful Password Reset Via SIM Swapping
If a SSPR flow is completed via SMS or phone call options from a rare and suspicious IP, it may indicate a potential SIM Swap attack that was then used to perform SSPR.

Query for detecting SSPR flows completed via SMS or phone call options from rare IP.  
```
AuditLogs
| where TimeGenerated >ago(90d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IPAddress=tostring(InitiatedBy.user.ipAddress)
//Only Verifications should present 
// User started the mobile SMS verification option
// User completed the mobile SMS verification option
// User completed the mobile voice call verification option
// User started the mobile voice call verification option
| summarize StartTime=min(TimeGenerated),EndTime=max(TimeGenerated),SSPRFlowEvents=make_set(ResultReason),count() by CorrelationId, TargetUser,IPAddress  
| where SSPRFlowEvents has_any ("User successfully reset password","Successfully completed reset") //Successfull password reset.
//Security Questions
// User started the security questions verification option
// User completed the security questions verification option
//Email-Verification
// User started the email verification option
// User completed the email verification option
//Authenticator App
// User started the mobile app notification verification option
// User completed the mobile app notification verification option
// User started the mobile app code verification option
// User started the mobile app notification verification option
| where not(SSPRFlowEvents has_any ("mobile app notification","mobile app code verification","email verification option","security questions verification option"))
| join kind=leftanti (
SigninLogs
| where TimeGenerated > ago(90d)
| where ResultType == 0 ) 
on IPAddress
```
Query for detecting SSPR flows completed via SMS or phone call options from TOR IP.  
```
let TorExitNodes=externaldata(ipAddress:string)[
"https://check.torproject.org/torbulkexitlist"];
AuditLogs
| where TimeGenerated >ago(90d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IPAddress=tostring(InitiatedBy.user.ipAddress)
| where IPAddress in (TorExitNodes)
//Only Verifications should present 
// User started the mobile SMS verification option
// User completed the mobile SMS verification option
// User completed the mobile voice call verification option
// User started the mobile voice call verification option
| summarize StartTime=min(TimeGenerated),EndTime=max(TimeGenerated),SSPRFlowEvents=make_set(ResultReason),count() by CorrelationId, TargetUser,IPAddress  
| where SSPRFlowEvents has_any ("User successfully reset password","Successfully completed reset") //Successfull password reset.
//Security Questions
// User started the security questions verification option
// User completed the security questions verification option
//Email-Verification
// User started the email verification option
// User completed the email verification option
//Authenticator App
// User started the mobile app notification verification option
// User completed the mobile app notification verification option
// User started the mobile app code verification option
// User started the mobile app notification verification option
| where not(SSPRFlowEvents has_any ("mobile app notification","mobile app code verification","email verification option","security questions verification option"))
```
### Successful Password Reset From TOR IPs
Successful password reset from TOR IPs using any methods.
```
let TorExitNodes=externaldata(ipAddress:string)[
"https://check.torproject.org/torbulkexitlist"];
AuditLogs
| where TimeGenerated >ago(90d)
| where LoggedByService=="Self-service Password Management"
| where OperationName=="Self-service password reset flow activity progress"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Initiatedby=tostring(InitiatedBy.user.userPrincipalName)
| extend IPAddress=tostring(InitiatedBy.user.ipAddress)
| where IPAddress in (TorExitNodes)
//Only Verifications should present 
// User started the mobile SMS verification option
// User completed the mobile SMS verification option
// User completed the mobile voice call verification option
// User started the mobile voice call verification option
| summarize StartTime=min(TimeGenerated),EndTime=max(TimeGenerated),SSPRFlowEvents=make_set(ResultReason),count() by CorrelationId, TargetUser,IPAddress  
| where SSPRFlowEvents has_any ("User successfully reset password","Successfully completed reset") //Successfull password reset.
```
MFA registration or MFA update followed by SSPR password reset.
```
AuditLogs
| where TimeGenerated >ago(1d)
| where OperationName =~"Reset password (self-service)"
| where ResultDescription=="Successfully completed reset."
| where Result=="success"
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser=tostring(TargetResources[0].userPrincipalName)
| project ResetTime=TimeGenerated, InitiatedUser, TargetUser, OperationName, Result
| join kind=inner (
AuditLogs
| where TimeGenerated >ago(1d)
| where OperationName in~ ("User registered all required security info","User registered security info","Admin registered security info","User changed default security info","Admin updated security info","User updated security info")
//| where Result=="success"
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName
| project ["MFARegistration/Update Time"]=TimeGenerated, InitiatedUser, TargetUser, Result, OperationName) on TargetUser
| where ['MFARegistration/Update Time']>ResetTime
| extend ['Reset to MFA change TimeGap']=datetime_diff('minute',["MFARegistration/Update Time"],ResetTime)
```

MFA method deletion followed by password reset.
```
AuditLogs
| where TimeGenerated >ago(1d)
| where OperationName =~"Reset password (self-service)"
| where ResultDescription=="Successfully completed reset."
| where Result=="success"
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser=tostring(TargetResources[0].userPrincipalName)
| project ResetTime=TimeGenerated, InitiatedUser, TargetUser, OperationName, Result
| join kind=inner (
AuditLogs
| where TimeGenerated >ago(1d)
| where OperationName in~ ("Admin deleted security info","User deleted security info")
//| where Result=="success"
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser=tostring(TargetResources[0].userPrincipalName)
| project ['MFA Method Deletion Time']=TimeGenerated, InitiatedUser, TargetUser, Result, OperationName) on TargetUser
| where ['MFA Method Deletion Time']>ResetTime
| extend ['Reset to MFA deletion TimeGap']=datetime_diff('minute',["MFARegistration/Update Time"],ResetTime)
```

### References  
https://cloudsecurityalliance.org/blog/2023/08/09/behind-the-breach-self-service-password-reset-sspr-abuse-in-azure-ad  
https://support.microsoft.com/en-us/account-billing/reset-your-work-or-school-password-using-security-info-23dde81f-08bb-4776-ba72-e6b72b9dda9e
