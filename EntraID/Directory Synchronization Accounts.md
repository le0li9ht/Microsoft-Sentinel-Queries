Directory Synchronization Accounts role assigned to a user.
```
AuditLogs
| where TimeGenerated >ago(40m)
| where OperationName=="Add member to role"
| where Result=="success"
| mv-expand TargetResources
| extend RoleAssigned=iff(tostring(TargetResources.modifiedProperties[1].displayName)=="Role.DisplayName",tostring(TargetResources.modifiedProperties[1].newValue),'')
| extend RoleObjectID=iff(tostring(TargetResources.modifiedProperties[0].displayName)=="Role.ObjectID",tostring(TargetResources.modifiedProperties[0].newValue),'')//Specifies the ID of a directory role in Azure AD.
| extend RoleObjectName=iff(tostring(TargetResources.modifiedProperties[3].displayName)=="Role.WellKnownObjectName",tostring(TargetResources.modifiedProperties[3].newValue),'')
| extend ['User-Agent']=iff(AdditionalDetails[0].key=="User-Agent", AdditionalDetails[0].value,'')
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedVia=tostring(InitiatedBy.user.displayName)
| extend ipAddress=tostring(InitiatedBy.user.ipAddress)
| extend TargetPrincipalName=tostring(TargetResources.userPrincipalName)
| where RoleAssigned=~'"Directory Synchronization Accounts"'
| project TimeGenerated,AADOperationType,OperationName, InitiatedUser, InitiatedVia,ipAddress, TargetPrincipalName, RoleAssigned, RoleObjectID, RoleObjectName, ['User-Agent']
```
Another query to look for the role assignment.
```
IdentityInfo
| where TimeGenerated > ago(14d)
| where AssignedRoles contains "Directory Synchronization Accounts"
```

Removed The Role
```
AuditLogs
| where TimeGenerated >ago(40m)
| where OperationName=="Remove member from role"
| where Result=="success"
| mv-expand TargetResources
| extend RoleAssigned=iff(tostring(TargetResources.modifiedProperties[1].displayName)=="Role.DisplayName",tostring(TargetResources.modifiedProperties[1].oldValue),'')
| extend RoleObjectID=iff(tostring(TargetResources.modifiedProperties[0].displayName)=="Role.ObjectID",tostring(TargetResources.modifiedProperties[0].oldValue),'')//Specifies the ID of a directory role in Azure AD.
| extend RoleObjectName=iff(tostring(TargetResources.modifiedProperties[3].displayName)=="Role.WellKnownObjectName",tostring(TargetResources.modifiedProperties[3].oldValue),'')
| extend ['User-Agent']=iff(AdditionalDetails[0].key=="User-Agent", AdditionalDetails[0].value,'')
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedVia=tostring(InitiatedBy.user.displayName)
| extend ipAddress=tostring(InitiatedBy.user.ipAddress)
| extend TargetPrincipalName=tostring(TargetResources.userPrincipalName)
| where RoleAssigned=~'"Directory Synchronization Accounts"'
| project TimeGenerated,AADOperationType,OperationName, InitiatedUser, InitiatedVia,ipAddress, TargetPrincipalName, RoleAssigned, RoleObjectID, RoleObjectName, ['User-Agent']
```
