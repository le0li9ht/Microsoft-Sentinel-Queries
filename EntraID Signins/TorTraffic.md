Locate sign-in events coming from TOR exit node IP addresses.  
```
let TorExitNodes=externaldata(ipAddress:string)[
"https://check.torproject.org/torbulkexitlist"];
SigninLogs
| where TimeGenerated >ago(90d)
| where IPAddress in (TorExitNodes)
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, ResultDescription,AppDisplayName, ResourceDisplayName,UserAgent,RiskEventTypes_V2, AuthenticationRequirement, AuthenticationProtocol, DeviceDetail
```

For TOR traffic, the "anonymizedIPAddress" value may appear in the RiskEventTypes_V2 property, though its presence is not guaranteed.  
```
SigninLogs
| where TimeGenerated >ago(90d)
| where RiskEventTypes_V2 has "anonymizedIPAddress"
```
