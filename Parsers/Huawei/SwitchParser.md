### Huwei Switch Parser
The following parser works for the Huawei CloudEngine 9800,8800,6800,5800 switches.
```
Syslog
//| where Facility=="local2" // If the huawei logs are coming to specific facility filter the same.
//| where Computer contains "<SwitchIPs>" // Mention your swtich IPs
| extend Config=extract(@"%%\d+(.+)\(.\)",1,SyslogMessage)
| extend LogVersion=extract(@"%%(\d+)",1,SyslogMessage)
| extend ModuleName=extract(@"%%\d+(\w+)",1,SyslogMessage)
| extend Severity=extract(@"%%\d+\w+\/(\w)",1,SyslogMessage)
| extend Brief=extract(@'%%\d+\w+\/\w+\/(\w+)',1,SyslogMessage)
| extend InformationType=extract(@"%%\d+\w+\/\w+\/\w+\((.)\)",1,SyslogMessage)
| extend ["System Component/Alarm ID"]=extract(@"%%\d+\w+\/\w+\/\w+\(.\)\: CID=(\S+) ",1,SyslogMessage)
| extend Description=extract(@"%%\d+\w+\/\w+\/\w+\(.\)\: CID=\S+ (.+)\.",1,SyslogMessage)
| extend rawparameters=extract(@"%%\d+\w+\/\w+\/\w+\(.\)\: CID=\S+ .+\.\s?\((.*)\)",1,SyslogMessage)
| mv-apply Splitdata = split(rawparameters, ", ") on (
    parse Splitdata with key "=" value
    | summarize Parameters = make_bag(pack(key, value))
)
| project TimeGenerated,Computer,HostIP,Facility,SeverityLevel,Config,LogVersion, ModuleName,Severity, Brief, InformationType,['System Component/Alarm ID'],Description,Parameters, SyslogMessage
```
