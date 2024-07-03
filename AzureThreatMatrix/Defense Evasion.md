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
## Disable Mailbox Auditing
### Emulation

```
# Get to know the mailbox auditing enabled for the organization
Get-OrganizationConfig | Format-List AuditDisabled
#Get to know the mailbox auditing enabled or disabled for a user.
Get-MailboxAuditBypassAssociation -Identity <UserEmail> | select AuditBypassEnabled
Get-Mailbox -Identity <UserMail> | select AuditEnabled                 
#Bypass mailbox auditing for a user
Set-MailboxAuditBypassAssociation -Identity <UserEmail> -AuditBypassEnabled $true
#Bypass Detection query using -Confirm parameter
Set-MailboxAuditBypassAssociation -Identity <UserEmail> -AuditBypassEnabled $true -Confirm:$true 
Set-MailboxAuditBypassAssociation -Identity <UserEmail> -AuditBypassEnabled $true -Confirm:$false
#Attempt to disable mailbox auditing for a user
Set-Mailbox -Identity "<UserEmail>" -AuditEnabled $false 
```
### Detection
The following query detects _mailbox auditing bypass_. This detection also identifies attempts to bypass detection by appending the Confirm parameter.
```
OfficeActivity
| where TimeGenerated >ago(1h)
| where Operation == "Set-MailboxAuditBypassAssociation"
| extend AuditBypassEnabled=iff(parse_json(Parameters)[0].Name=="AuditBypassEnabled",parse_json(Parameters)[0].Value,iff(parse_json(Parameters)[1].Name=="AuditBypassEnabled",parse_json(Parameters)[1].Value,''))
| where AuditBypassEnabled=="True"
| extend TargetUser=iff(parse_json(Parameters)[1].Name=="Identity",parse_json(Parameters)[1].Value,iff(parse_json(Parameters)[2].Name=="Identity",parse_json(Parameters)[2].Value,''))
| where ResultStatus=="True"
| project TimeGenerated, Operation, UserId, TargetUser,  AuditBypassEnabled, ClientIP, UserType, RecordType,ResultStatus,ExternalAccess, Parameters
```
The below query detects the attempts to disable to mailbox auditing via Set-Mailbox command.  
```
OfficeActivity
| where TimeGenerated >ago(1h)
| where Operation=="Set-Mailbox"
| extend parsedParam=parse_json(Parameters) 
| extend AppName=iff(AppId=="fb78d390-0c51-40cd-8e17-fdbfab77341b","Microsoft Exchange REST API Based Powershell",'')
| mv-expand parsedParam
| extend AuditingEnabled=iff(parse_json(parsedParam).Name=="AuditEnabled",parse_json(parsedParam).Value,'')
| where AuditingEnabled=="False"
| where ResultStatus=="True"
| project TimeGenerated,RecordType,UserType,ClientIP, UserId,AuditingEnabled,Operation,SourceRecordId,ResultStatus, Parameters,ExternalAccess, AppId, AppName
| join kind=inner(
OfficeActivity
| where TimeGenerated >ago(1h)
| where Operation=="Set-Mailbox"
| extend parsedParam=parse_json(Parameters) 
| mv-expand parsedParam
| extend TargetUser=iff(parse_json(parsedParam).Name=="Identity",parse_json(parsedParam).Value,'')
| where isnotempty(TargetUser)
| project TimeGenerated,UserId, SourceRecordId, TargetUser, Operation) on SourceRecordId,UserId
| project TimeGenerated,ClientIP, UserId,AuditingEnabled,Operation,TargetUser,ResultStatus,RecordType,UserType,SourceRecordId, Parameters,ExternalAccess, AppId, AppName
```
