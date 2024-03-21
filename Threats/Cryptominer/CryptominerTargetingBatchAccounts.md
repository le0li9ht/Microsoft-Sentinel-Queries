//Batch Account Creation.
AzureActivity
| where OperationNameValue=~"MICROSOFT.BATCH/BATCHACCOUNTS/WRITE"
| where ActivityStatusValue=="Success"
| project TimeGenerated,OperationNameValue,ActivityStatusValue,ActivityStatus,ActivitySubstatus, ActivitySubstatusValue, BatchAccountName=Properties_d.resource,SubscriptionId=Properties_d.subscriptionId, ResourceGroup, Caller, CallerIpAddress,CorrelationId
| join kind=leftsemi (AzureActivity
| where OperationNameValue=~"MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE"
| where ActivityStatusValue=="Success"
| extend BatchAccountName=Properties_d.resource
//| where BatchAccountName startswith "microsoft.batchaccount" //optional condition for more granularity
| project TimeGenerated,OperationNameValue,ActivityStatusValue,ActivityStatus,ActivitySubstatus, ActivitySubstatusValue, BatchAccountName=Properties_d.resource,SubscriptionId=Properties_d.subscriptionId, ResourceGroup, Caller, CallerIpAddress,CorrelationId) on CorrelationId
