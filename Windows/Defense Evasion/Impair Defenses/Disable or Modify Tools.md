
```
//Disable RealTime Protection
WindowsEvent
| where Channel=="Microsoft-Windows-Windows Defender/Operational"
| where EventID==5001
| project TimeGenerated, Computer, EventID,Operation="RealtimeProtectionDisbaled", Product=EventData["Product Name"], Version=EventData['Product Version'], Channel, Provider 
```
```
//Defender Path Exclusion
WindowsEvent
| where Channel=="Microsoft-Windows-Windows Defender/Operational"
| where EventID==5007
| where EventData['New Value'] has @"\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\"
| extend ExcludedPath=extract(@"\\Paths\\(.*?)\s+=", 1, tostring(EventData['New Value']))
| project TimeGenerated, Computer, EventID,Channel, Provider,Operation="PathExclusion",ExcludedPath,NewValue=EventData.["New Value"], OldValue=EventData.["Old Value"],Product=EventData["Product Name"], Version=EventData['Product Version']
```
