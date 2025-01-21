API_Audit Logs Parser for Nutanix
```
Syslog
| where TimeGenerated >ago(90d)
| where ProcessName=="api_audit" or ProcessName=="api_audit_v3"
| extend Severity=trim_start(@"message repeated [0-9]+ times: \[ ",(extract(@"^(message repeated [0-9]+ times: \[ [a-zA-z]+|[a-zA-Z]+)",1,SyslogMessage)))
| extend EventTime1=extract(@"(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:[0-9,]+Z?)", 1, SyslogMessage)
| extend Trimmed=trim_end("]",trim_start(@".*(\d{4}\-\d{2}\-\d{2} \d{2}\:\d{2}\:[0-9,]+Z?)",SyslogMessage))
| mv-apply s = split(Trimmed, "||") on (
    parse s with key "=" value
    | summarize ParsedMessage = make_bag(pack(key, value))
)
| project TimeGenerated, 
Computer, 
EventTime, 
EventTime1, 
Facility, 
HostName,
ProcessName,
HostIP, 
Severity,
ClientType=tostring(ParsedMessage.clientType),
HTTPMethod=tostring(ParsedMessage.httpMethod),
NutanixAPIVersion=tostring(ParsedMessage.NutanixApiVersion),
EntityUUID=tostring(ParsedMessage.entityUuid),
Payload=tostring(ParsedMessage.payload),
QueryParams=tostring(ParsedMessage.queryParams),
RestEndpointURI=(ParsedMessage.restEndpoint),
UserName=tostring(ParsedMessage.userName),
userLogin=tostring(ParsedMessage.userLogin),
ParsedMessage

```
