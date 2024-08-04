certutil can be used to decode binaries hidden inside certificate files as Base64 information. Also certutil can encode the files to base64.
Certutil also can be used for encoding into hex format.
```
SecurityEvent
| where EventID==4688
| where CommandLine has "certutil" and CommandLine has_any ('encode','decode', 'encodehex','decodehex')
| project TimeGenerated, Computer, Account,EventID, Activity, CommandLine, ParentProcessName, NewProcessName, NewProcessId, ProcessId
```
