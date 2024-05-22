## Disable/Delete audit logs
Attackers may disable storage account audit logs to prevent event tracking and avoid detection. Audit logs provide a detailed record of operations performed on a target storage account and may be used to detect malicious activities. Thus, disabling these logs can leave a resource vulnerable to attacks without being detected.  
### MITRE ATT&CK
| Tactic | Technique | Link    |
| ---  | --- | --- |
| TA0005-Defense Evasion | MS-T810-Disable audit logs | https://attack.mitre.org/techniques/T1562/008/  
|| T1562.008-Impair Defenses: Disable or Modify Cloud Logs| https://microsoft.github.io/Threat-matrix-for-storage-services/techniques/disable-audit-logs/|

The below query detects deletion of azure diagnostic settings for disabling the logs.
```
AzureActivity
| where OperationNameValue=~"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
| where ResourceProviderValue=~"MICROSOFT.STORAGE"
| where ActivityStatusValue=="Success"
| extend DiagnosticSettingName=tostring(Properties_d.resource)
| extend Scope = tostring(Properties_d.entity)
| extend Role=tostring(parse_json(Authorization).evidence.role) //Use this role value to pivor further
| project TimeGenerated,Caller,CallerIpAddress,OperationNameValue, ActivityStatusValue, DiagnosticSettingName,ResourceGroup, ResourceProviderValue, Scope,Role

```
The below query detects the modification of diagnostic settings for disabling specific category of logs. The below rule prone to false positives.

