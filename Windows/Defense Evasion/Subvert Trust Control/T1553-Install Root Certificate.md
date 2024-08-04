certutil can be used to install browser root certificates as a precursor to performing Adversary-in-the-Middle between connections to banking websites. Example command: certutil -addstore -f -user ROOT ProgramData\cert512121.der  
```
SecurityEvent
| where EventID==4688
| where CommandLine has "certutil" and CommandLine has_any ('addstore', 'user') and CommandLine has_any (
  ".crt",
  ".cer",
  ".pem",
  ".der",
  ".p7b",
  ".pfx",
  ".ca-bundle") 
| project TimeGenerated, Computer, Account,EventID, Activity, CommandLine, ParentProcessName, NewProcessName, NewProcessId, ProcessId
```
