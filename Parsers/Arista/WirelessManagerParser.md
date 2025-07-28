## Arista Wireless Manager Parser.
I developed a custom parser for Arista Wireless Manager logs, specifically designed to handle the syslog message format described in Arista’s documentation [here](https://arista.my.site.com/AristaCommunity/s/article/how-do-i-change-the-syslog-message-header-format) as shown:
<img width="1836" height="291" alt="image" src="https://github.com/user-attachments/assets/00143c7c-74b8-4ece-9ff2-ea040cee1294" />

**Tested for following messages:** 
- Login failed for user on server
- User deleted
- Login succeeded for user on server
- New user added
- User logged out of server
- Events marked as Read or Unread
- User configuration updated
- Start: Rouge AP
- Stop: Rouge AP
- Start: Banned AP
- Stop Banned AP

### Parser:

```
Syslog
//where HostIP contains "" 
| where SyslogMessage contains ">Wireless Manager "
| extend DeviceMac=replace_string(extract(@"<(.*?)>Wireless Manager",1,SyslogMessage)," ","")
| extend DeviceVendor="Arista"
| extend DeviceProduct="Wireless Manager"
| extend DeviceVersion=extract(@"Wireless Manager (.*?) :",1,SyslogMessage)
| extend Message=extract(@"Wireless Manager .*? : (.*?)\. :",1,SyslogMessage)
| extend Location=extract(@"Wireless Manager .*\. : (.*) : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} ",1,SyslogMessage)
| extend ReceiveTime=extract(@"Wireless Manager .* : (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}) ",1,SyslogMessage)
| extend Severity=extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : ([a-zA-Z]+) : ",1,SyslogMessage)
| extend Category=iff(SyslogMessage has_any (" Rogue AP"," Banned AP"),extract(@"Wireless Manager [a-z\.\-0-9]+ : ([A-Za-z\s:]+) \[",1,SyslogMessage) ,extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z]+ : \d+ : ([a-zA-Z ]+) :",1,SyslogMessage))
| extend TargetUser=extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z]+ : \d+ : [a-zA-Z ]+ : \d+ : \d+ : (.*?) :",1,SyslogMessage)
| extend UserType=extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z]+ : \d+ : [a-zA-Z ]+ : \d+ : \d+ : .*? : (.*?) :",1,SyslogMessage)
| extend Reason=extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z]+ : \d+ : [a-zA-Z ]+ : \d+ : \d+ : .*? : .*? : (.*?) :",1,SyslogMessage)
| extend Description=iff(SyslogMessage has_any (" Rogue AP"," Banned AP"),extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z ]+ : \d+ : \d+ : \d+ : \d+\s?:.*?\. (.*)",1,SyslogMessage), extract(@"Wireless Manager .* : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2} : [a-zA-Z]+ : \d+ : [a-zA-Z ]+ : \d+ : \d+ : .*? : .*? : .*? :(.*)",1,SyslogMessage))
| extend Rouge_or_Banned_AP=extract(@"Wireless Manager [a-z\.\-0-9]+ : [A-Za-z\s:]+ \[(.*?)\]",1,SyslogMessage)
| extend SSID=extract(@"SSID\s?\[(.*?)\],",1,SyslogMessage)
| extend ClosestSensor=extract(@"Closest Sensor \[(.*?)\]",1,SyslogMessage)
```

### References:
https://arista.my.site.com/AristaCommunity/s/article/how-do-i-change-the-syslog-message-header-format
https://arista.my.site.com/AristaCommunity/s/article/syslog-server-integration-with-cloudvision-wifi
https://www.arista.com/en/ug-cv-cue/cv-cue-third-party-servers#A24B8122-D240E51-82527AC050C5125-75AB11

