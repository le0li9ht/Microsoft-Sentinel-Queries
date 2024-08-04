Certutil Download   
**MITRE Technique:**
[T1570-Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570/)
```
let url_pattern=@"(ftp?|https?|smb?|tftp?|sftp?|nfs?):\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)";
SecurityEvent
| where EventID==4688
| where CommandLine has_all ("certutil",'//') and CommandLine has_any ('urlcache','verifyctl','split','-f','-"f"',"-'f'")
| extend DownloadUrl=extract(url_pattern, 0, CommandLine)
| project TimeGenerated, Computer, Account,EventID, Activity, CommandLine, DownloadUrl, ParentProcessName, NewProcessName, NewProcessId, ProcessId
```
