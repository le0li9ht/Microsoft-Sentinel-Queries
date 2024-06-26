# [MITRE Technique-T1562.008: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)  

## Disable Unified Audit Logs  
### Emulation:  
```
Connect-ExchangeOnlineManagement
Get-AdminAuditLogConfig |Select-Object -ExpandProperty UnifiedAuditLogIngestionEnabled
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false
```

###
### Detection:
#### OfficeActivity logs
The below KQL query detects disabling of Unified Audit Logs.  
```
OfficeActivity
| where OfficeWorkload=="Exchange"
| where Operation=="Set-AdminAuditLogConfig"
| where ResultStatus==true
| mv-expand Parameters=parse_json(Parameters)
| where Parameters.Name=="UnifiedAuditLogIngestionEnabled" and Parameters.Value=="False"
| extend AppName=iff(AppId=="fb78d390-0c51-40cd-8e17-fdbfab77341b","Microsoft Exchange REST API Based Powershell",AppId)
| project TimeGenerated,ElevationTime, UserType,Operation,ResultStatus, OfficeObjectId, UserId, ClientIP, ExternalAccess, AppName, OrganizationName
```
#### Defender XDR
Disabling Unified Audit Logs generates an Incident in Microsoft Defender XDR(Microsoft 365 Defender) as shown.
* **Incident Name**: Unified audit log ingestion was turned off involving one user
* **AlertName**: Unified audit log ingestion was turned off

![Defender Alert](Images/UnifiedAuditLogDisabled.png)  
#### Via Powershell
You can also detect via powershell commands.  
```Search-AdminAuditLog -Cmdlets Set-AdminAuditLogConfig -Parameters UnifiedAuditLogIngestionEnabled```  
![](Images/DetectUnifiedAuditLogDisabled.png)

## Disable Admin Audit Logs  
### Emulation
```
Get-AdminAuditLogConfig | Format-List AdminAuditLogEnabled
Set-AdminAuditLogConfig -AdminAuditLogEnabled $False
```
### Detection: 
The below KQL query detects disabling of Admin Audit Logs.  
```
OfficeActivity
| where OfficeWorkload=="Exchange"
| where Operation=="Set-AdminAuditLogConfig"
| where ResultStatus==true
| mv-expand Parameters=parse_json(Parameters)
| where Parameters.Name=="AdminAuditLogEnabled" and Parameters.Value=="False"
| extend AppName=iff(AppId=="fb78d390-0c51-40cd-8e17-fdbfab77341b","Microsoft Exchange REST API Based Powershell",AppId)
| project TimeGenerated,ElevationTime, UserType,Operation,ResultStatus, OfficeObjectId, UserId, ClientIP, ExternalAccess, AppName, OrganizationName
```
