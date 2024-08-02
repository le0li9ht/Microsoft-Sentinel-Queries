
```
//Disable RealTime Protection
WindowsEvent
| where Channel=="Microsoft-Windows-Windows Defender/Operational"
| where EventID==5001
| project TimeGenerated, Computer, EventID,Operation="RealtimeProtectionDisbaled", Product=EventData["Product Name"], Version=EventData['Product Version'], Channel, Provider 
```
