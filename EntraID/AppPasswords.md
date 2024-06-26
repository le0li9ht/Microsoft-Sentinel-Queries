Some older, non-browser apps like Office 2010 or earlier and Apple Mail before iOS 11 don't understand pauses or breaks in the authentication process. A Microsoft Entra multifactor authentication (Microsoft Entra multifactor authentication) user who attempts to sign in to one of these older, non-browser apps, can't successfully authenticate. To use these applications in a secure way with Microsoft Entra multifactor authentication enforced for user accounts, you can use app passwords. These app passwords replaced your traditional password to allow an app to bypass multifactor authentication and work correctly.  


![alt text](https://github.com/le0li9ht/Microsoft-Sentinel-Queries/blob/main/EntraID/Images/AppPasswords.png)    
  
This KQL Query checks if the App Passwords setting is enabled.

```
AuditLogs
| where TimeGenerated >ago(20m)
| where OperationName=="Set Company Information"
| mv-expand TargetResources
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend CompanyName=tostring(TargetResources.displayName)
| extend ipAddress=tostring(InitiatedBy.user.ipAddress)
| where Result=="success"
| mv-expand ModifiedProperties=TargetResources.modifiedProperties
| extend NewValues=parse_json(tostring(ModifiedProperties.newValue))[0]
| where ModifiedProperties.displayName == "StrongAuthenticationDetails"
| evaluate bag_unpack(NewValues)
| where BlockApplicationPassword == false
```
