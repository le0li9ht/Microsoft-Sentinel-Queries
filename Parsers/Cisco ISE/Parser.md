#### Cisco ISE parser:  
Note: Customize according to your environment since in some environments the cisco ISE logs are not coming with segmentation and id values.  
```
//Author: Ashok Krishna Vemuri
let AdminandPostureEvents=Syslog
| where ProcessName has_any ("CISE", "CSCO")
| where ProcessName !in ("CISE_MONITORING_DATA_PURGE_AUDIT","CISE_Alarm")
| extend SegmetnId=extract(@"^(\d+) \d{1} \d{1} ",1,SyslogMessage)
| extend TotalSegment=extract(@"^\d+ (\d{1}) ",1,SyslogMessage)
| extend SegmetNum=extract(@"^\d+ \d{1} (\d{1}) ",1,SyslogMessage)
| extend Timestamp=todatetime(extract(@" ?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) +",1,SyslogMessage))
| extend TimeZone=extract(@" (\+\d{2}:\d{2}) ",1,SyslogMessage)
| extend SequenceNum=extract(@" \+\d{2}:\d{2} (\d+) ",1,SyslogMessage)
| extend MessageCode=extract(@" \+\d{2}:\d{2} \d+ (\d+) ",1,SyslogMessage)
| extend Severity=extract(@" \+\d{2}:\d{2} \d+ \d+ ([A-Z]+) ",1,SyslogMessage)
| extend MessageClass=extract(@" \+\d{2}:\d{2} \d+ \d+ [A-Z]+ (.*?): ",1,SyslogMessage)
| extend MessageText=extract(@" \+\d{2}:\d{2} \d+ \d+ [A-Z]+ .*?: (.*?), ",1,SyslogMessage)
| extend kv_pairs = extract(@"(\b\w+=.*)", 1, SyslogMessage)
| project Timestamp,ProcessName,TimeZone,SegmetnId,TotalSegment,SegmetNum, SequenceNum, MessageCode,MessageClass,MessageText,kv_pairs,SyslogMessage
| sort by SegmetnId,SegmetNum asc 
| summarize FullMessage = strcat_array(make_list(kv_pairs), "") by SegmetnId
| join kind=rightouter(
Syslog
| where ProcessName has_any ("CISE", "CSCO")
| where ProcessName !in ("CISE_MONITORING_DATA_PURGE_AUDIT","CISE_Alarm")
| extend SegmetnId=extract(@"^(\d+) \d{1} \d{1} ",1,SyslogMessage)
| extend TotalSegment=extract(@"^\d+ (\d{1}) ",1,SyslogMessage)
| extend SegmetNum=extract(@"^\d+ \d{1} (\d{1}) ",1,SyslogMessage)
| extend Timestamp=todatetime(extract(@" ?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) +",1,SyslogMessage))
| extend TimeZone=extract(@" (\+\d{2}:\d{2}) ",1,SyslogMessage)
| extend SequenceNum=extract(@" \+\d{2}:\d{2} (\d+) ",1,SyslogMessage)
| extend MessageCode=extract(@" \+\d{2}:\d{2} \d+ (\d+) ",1,SyslogMessage)
| extend Severity=extract(@" \+\d{2}:\d{2} \d+ \d+ ([A-Z]+) ",1,SyslogMessage)
| extend MessageClass=extract(@" \+\d{2}:\d{2} \d+ \d+ [A-Z]+ (.*?): ",1,SyslogMessage)
| extend MessageText=extract(@" \+\d{2}:\d{2} \d+ \d+ [A-Z]+ .*?: (.*?), ",1,SyslogMessage)
| extend kv_pairs = extract(@"(\b\w+=.*)", 1, SyslogMessage)
| project Timestamp,Computer,HostIP,ProcessName,TimeZone,SegmetnId,TotalSegment,SegmetNum, SequenceNum, MessageCode,MessageClass,MessageText,kv_pairs,SyslogMessage
| sort by SegmetnId,SegmetNum asc 
| where isnotempty(Timestamp) and isnotempty(MessageCode)) on SegmetnId
| project-reorder Timestamp,Computer,ProcessName,TimeZone,SegmetnId,TotalSegment,SegmetNum, SequenceNum, MessageCode,MessageClass,MessageText,FullMessage,kv_pairs,SyslogMessage
| project-away kv_pairs,SegmetnId1;
let PurgeEvents=
Syslog
| where ProcessName has_any ("CISE", "CSCO")
| where ProcessName=~"CISE_MONITORING_DATA_PURGE_AUDIT"
| extend Timestamp=extract(@"?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) +",1,SyslogMessage)
//| extend SequenceNum=extract(@" \+\d{2}:\d{2} (\d+) ",1,SyslogMessage)
| extend MessageCode=extract(@" \+\d+ (\d+) ",1,SyslogMessage)
| extend Severity=extract(@" \+\d+ \d+ ([A-Z]+) ",1,SyslogMessage)
| extend MessageClass=extract(@" \+\d+ \d+ [A-Z]+ (.*?): ",1,SyslogMessage)
| extend MessageText=extract(@" \+\d+ \d+ [A-Z]+ .*?: (.*?), ",1,SyslogMessage)
| extend FullMesssage=extract(@"(\b\w+=.*)", 1, SyslogMessage)
| project Timestamp,Computer,ProcessName,HostIP,MessageCode, Severity, MessageClass, MessageText, FullMesssage, SyslogMessage;
let Failures=Syslog
| where ProcessName=~'CISE_Alarm'
//| where ProcessName has_any ("CISE", "CSCO")
| extend Severity = extract(@"\b(NOTICE|INFO|WARN|WARNING|ERROR|FATAL|DEBUG|CRITICAL)\b", 1, SyslogMessage)
| extend Alarm = extract(@": (.*?) [A-Za-z\s]+=", 1, SyslogMessage)
| extend Alarm=iff(isempty(Alarm),extract(@": (.*)", 1, SyslogMessage),trim_end(@'\.',trim_end(':',Alarm)))
| extend Message = extract(@"(\b\w+=.*)", 1, SyslogMessage)
| project
    TimeGenerated,
    EventTime,
    Computer,
    ProcessName,
    Severity,
    Alarm,
    Message,
    SyslogMessage;
union isfuzzy=true AdminandPostureEvents,PurgeEvents,Failures
```
