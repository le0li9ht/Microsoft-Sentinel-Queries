
Attackers are continuously devising new methods to mine cryptocurrencies. One such method involves targeting Azure Batch accounts.  
### Attack Flow:
- The attacker compromises any administrator account on Azure.
- The attacker creates a resource group and a batch account within it.
- The attacker creates a support ticket to increase the quota allocation for batch accounts(for boosting mining capacity).
- Later, the attacker creates a pool inside the batch account with a start task.
- The start task initiates the attack chain by downloading Docker and installing a malicious Docker image with a mining pool.
- Cryptomining begins...
  
If your organization doesn't use Batch accounts, the query below can help you identify if any new Batch accounts and their associated pools have been created.
### Detection
```
//Batch Account Creation.
AzureActivity
| where TimeGenerated >ago(24h)
| where OperationNameValue=~"MICROSOFT.BATCH/BATCHACCOUNTS/WRITE"
| where ActivityStatusValue=="Success"
| project TimeGenerated,OperationNameValue,ActivityStatusValue,ActivityStatus,ActivitySubstatus, ActivitySubstatusValue, BatchAccountName=Properties_d.resource,SubscriptionId=Properties_d.subscriptionId, ResourceGroup, Caller, CallerIpAddress,CorrelationId
| join kind=leftsemi (AzureActivity
| where TimeGenerated >ago(24h)
| where OperationNameValue=~"MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE"
| where ActivityStatusValue=="Success"
| extend BatchAccountName=Properties_d.resource
//| where BatchAccountName startswith "microsoft.batchaccount" //optional condition for more granularity
| project TimeGenerated,OperationNameValue,ActivityStatusValue,ActivityStatus,ActivitySubstatus, ActivitySubstatusValue, BatchAccountName=Properties_d.resource,SubscriptionId=Properties_d.subscriptionId, ResourceGroup, Caller, CallerIpAddress,CorrelationId) on CorrelationId
```
```
//Pool Creation
AzureActivity
| where TimeGenerated >ago(24h)
| where OperationNameValue=~"MICROSOFT.BATCH/BATCHACCOUNTS/POOLS/WRITE"
| where ActivityStatusValue=="Success"
| project TimeGenerated,OperationNameValue,ActivityStatusValue,ActivitySubstatusValue, BatchAccountName=Properties_d.resource,SubscriptionId=Properties_d.subscriptionId, ResourceGroup, Caller, CallerIpAddress,CorrelationId
```
### IOCs:
Files:
```
hxxps[:]//raw.githubusercontent.com/max313iq/Ssl/main/ba.sh
hxxps[:]//raw.githubusercontent.com/max313iq/Ssl/main/ip
```
Malicious Docker Images:
```
https://hub.docker.com/r/ubtssl/webappx
https://hub.docker.com/r/ubtssl/serveconnect
```
Pool IPs:
```
172.200.110.72:3333
45.61.129.122:3333
```
XMRIG miner Binary:
```
hxxps[:]//github.com/ddao2604/tech/releases/download/1.0/xm  
sha256: 01c6c81abf1206caf6c4004bae8c4999624228c8b1ce7514503e4150c10c21b5
hxxps[:]//github.com/max313iq/Ssl/releases/download/Xxx/xmm
sha256: 0216daee1c6690d2bb4be3bc7b8b2d585cb3dbc7c4bf4bbde03f4e8232fbcda7
```
Threat Actor Handles:
```
mail: m4xspo@gmail.com
https[:]//hub.docker.com/u/ubtssl
hxxps[:]//github.com/max313iq
hxxps[:]//github.com/ddao2604/
```
### Mitigations
- Enforce MFA for all administrator accounts.
- Implement Conditional Access Policies to disallow logins from other countries.
- Monitor for any anomalies by creating [anomaly alerts](https://learn.microsoft.com/en-us/azure/cost-management-billing/understand/analyze-unexpected-charges)

### Screenshots


### References:
https://twitter.com/red_cth/status/1754970064560763199  
https://dfir.ch/posts/azure_batch/
