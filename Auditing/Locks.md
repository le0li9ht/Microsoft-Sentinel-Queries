```
AzureActivity
| where OperationNameValue in ("MICROSOFT.AUTHORIZATION/LOCKS/WRITE", "MICROSOFT.AUTHORIZATION/LOCKS/DELETE")
| extend LockName=tostring(Properties_d.resource)
| where ActivityStatusValue=="Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, ActivitySubstatusValue, LockName, ResourceProviderValue,ResourceGroup, SubscriptionId
```
