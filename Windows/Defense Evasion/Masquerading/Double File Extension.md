```
SecurityEvent
| where EventID==4688
| where Process matches regex "^(.*)\\.(\\w*[a-zA-Z]\\w*)\\.(\\w*[a-zA-Z]\\w*)$"
```
