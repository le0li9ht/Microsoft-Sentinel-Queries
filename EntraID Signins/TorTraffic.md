KQL query for finding signin events from TOR exit nodes.
```
let TorExitNodes=externaldata(ipAddress:string)[
"https://check.torproject.org/torbulkexitlist"];
SigninLogs
| where TimeGenerated >ago(90d)
| where IPAddress in (TorExitNodes)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription,AppDisplayName, ResourceDisplayName,UserAgent,RiskEventTypes_V2, AuthenticationRequirement, AuthenticationProtocol, DeviceDetail
```

Not accurate query but can be used.
```
SigninLogs
| where TimeGenerated >ago(90d)
| where RiskEventTypes_V2 has "anonymizedIPAddress"
```
