Nutanix audit logs parser.  
```
let Audit=() {
    Syslog
    | where ProcessName in ("audispd", "auditd", "audisp-remote")
    | where SyslogMessage startswith "node"
    | parse SyslogMessage with * "node=" NodeName " type=" Type " msg=audit(" Timestamp: real ":" SerialNumber "): " Message
    | extend ['Timestamp[IST]']=datetime_add('minute',30,datetime_add('hour', 5, unixtime_seconds_todatetime(Timestamp))) //IST TimeZone. Change it according to your environment.
    | extend SerialNumber=extract(@'msg=audit\([0-9.]+:([0-9]+)\):', 1, SyslogMessage)
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        Message,
        SyslogMessage
};
let ErrorAudit=() {
    Syslog
    | where ProcessName in ("audispd", "auditd", "audisp-remote")
    | where SyslogMessage !startswith "node"
    | project TimeGenerated, HostName, ProcessName, Facility, SeverityLevel, SyslogMessage
};
let MostTypes=() {
    Audit
    | where Type !in ('EXECVE', 'PROCTITLE', "USER_ACCT", "USER_CMD", "USER_START", "USER_END", "USER_AUTH", "SERVICE_STOP", "SERVICE_START", "USER_AVC", "USER_ROLE_CHANGE", "CRYPTO_KEY_USER", "USER_SELINUX_ERR", "CRYPTO_SESSION", "USER_LOGOUT", "USER_LOGIN", "ROLE_ASSIGN", "VIRT_CONTROL", "VIRT_MACHINE_ID", "VIRT_RESOURCE", "USER_MGMT", 'CRED_ACQ', 'CRED_DISP', 'CRED_REFR', 'AVC')
    | mv-apply parsed = split(Message, " ") on (
        parse parsed with key "=" value
        | summarize Parameters = make_bag(pack(key, value))
        )
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        Parameters,
        Message,
        SyslogMessage
};
let PROCTITLEHEX=() {
    Audit
    | where Type == "PROCTITLE"
    | where Message !startswith 'proctitle="'
    | extend HexCMD=trim_start('proctitle=', Message)
    | extend FortmattedHex = replace_regex(HexCMD, @"(.{2})", @"\1 ")
    | mv-apply HexByte = split(FortmattedHex, " ") on (
        summarize nums = make_list(tolong(strcat("0x", iff(HexByte == "00", "20", HexByte)))) //replace the null values with spaces 00 to 20
        )
    | extend CommandLine =  make_string(nums)
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        CommandLine,
        Message,
        SyslogMessage
};
let PROCTITLE=() {
    Audit
    | where Type == "PROCTITLE"
    | where Message startswith 'proctitle="'
    | extend CommandLine=trim_start('proctitle=', Message)
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        CommandLine,
        Message,
        SyslogMessage
}; 
let EXECVE=() {
    Audit
    | where Type == "EXECVE"
    | extend CommandLine=replace_regex(Message, @'\"?[[:space:]]a[0-9]+=\"', ' ')
    | extend CommandLine=trim_end('"', trim_start(@"argc=[0-9]+ ", CommandLine))
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        CommandLine,
        Message,
        SyslogMessage
};
let AVC=() {
    Audit
    | where Type == "AVC"
    | parse Message with * "avc: " Action " for " Message 
    | mv-apply s = split(Message, " ") on (
        parse s with key "=" value
        | summarize Parameters = make_bag(pack(key, value))
        )
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        Parameters,
        Message,
        SyslogMessage
};
let CRED=() {
    Audit
    | where Type in ("USER_ACCT", "USER_CMD", "USER_START", "USER_END", "USER_AUTH", "SERVICE_STOP", "SERVICE_START", "USER_AVC", "USER_ROLE_CHANGE", "CRYPTO_KEY_USER", "USER_SELINUX_ERR", "CRYPTO_SESSION", "USER_LOGOUT", "USER_LOGIN", "ROLE_ASSIGN", "VIRT_CONTROL", "VIRT_MACHINE_ID", "VIRT_RESOURCE", "USER_MGMT", 'CRED_ACQ', 'CRED_DISP', 'CRED_REFR')
    | extend Mess=split(Message, " msg=")
    | extend msgg=trim_end("'", trim_start("'", tostring(Mess[1])))
    | mv-apply s = split(tostring(Mess[0]), " ") on (
        parse s with key "=" value
        | summarize Parameters = make_bag(pack(key, value))
        )
    | mv-apply d = split(tostring(msgg), " ") on (
        parse d with key "=" value
        | summarize msg = make_bag(pack(key, value))
        )
    | project
        TimeGenerated,
        ['Timestamp[IST]'],
        HostName,
        ProcessName,
        SeverityLevel,
        NodeName,
        Type,
        SerialNumber,
        Parameters,
        msg,
        Message,
        SyslogMessage
};
(union isfuzzy=true MostTypes, ErrorAudit, EXECVE, AVC, PROCTITLE, PROCTITLEHEX, CRED)
```
