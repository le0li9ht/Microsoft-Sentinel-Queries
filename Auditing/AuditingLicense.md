Auditing Licenses
//Final One: Find Newly Assigned Licenses
AuditLogs
| where TimeGenerated > ago(10d)
| where OperationName == "Change user license"
| mv-expand TargetResources
| extend InitiatedApp=tostring(InitiatedBy.app.displayName)
| extend InitiatedPrincipalId=tostring(InitiatedBy.app.servicePrincipalId)
| extend InitiatedUser=tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser=tostring(TargetResources.userPrincipalName)
| extend ipAddress=tostring(InitiatedBy.user.ipAddress)
| extend value=parse_json(AdditionalDetails[2].value)
| extend AppDisplayName=tostring(InitiatedBy.user.displayName)
| extend sequence=iff(AdditionalDetails[1].key == "seq", toint(AdditionalDetails[1].value), toint(AdditionalDetails[1].value))
//| extend maximumlength=iff(AdditionalDetails[3].key == "c", toint(AdditionalDetails[3].value), toint(AdditionalDetails[3].value))
| sort by sequence asc 
| summarize TimeGenerated=min(TimeGenerated),OperationName=make_set(OperationName)[0],InitiatedVia=make_list(AppDisplayName)[0],InitiatedUser=make_list(InitiatedBy.user.userPrincipalName)[0],InitiatedApp=make_list(InitiatedApp)[0],InitiatedPrincipalId=make_list(InitiatedPrincipalId)[0], TargetUser=make_list(TargetUser)[0], ipAddress=make_list(ipAddress)[0],LicenceUpdateProperties=strcat_array(make_list(value), '') by CorrelationId
| extend UserAgent=parse_json(tostring(parse_json(LicenceUpdateProperties).additionalDetails)).["User-Agent"]
//| extend AssignedLicense=parse_json(tostring(parse_json(LicenceUpdateProperties).targetUpdatedProperties))[0]
| extend AssignedLicenseNewValue=array_sort_asc(parse_json(tostring(parse_json(LicenceUpdateProperties).targetUpdatedProperties))[0].NewValue)
| extend AssignedLicenseOldValue=array_sort_asc(parse_json(tostring(parse_json(LicenceUpdateProperties).targetUpdatedProperties))[0].OldValue)
| where isnotempty(AssignedLicenseNewValue[0])
| where array_length(AssignedLicenseNewValue) > array_length(AssignedLicenseOldValue)
| mv-expand AssignedLicenseOldValue, AssignedLicenseNewValue
| extend AssignedLicenseOldValue=iff(isnotempty(AssignedLicenseOldValue), parse_json(strcat('{"',substring(replace_string(replace_string(replace_string(replace_string(replace_string(tostring(parse_json(AssignedLicenseOldValue)),'=[','":["'),"=",'":"'),",",'","'),"]]",'"]}'),'" ','"'),1))),parse_json(''))
| extend OldSkuName=tostring(AssignedLicenseOldValue.SkuName)
| extend AssignedLicenseNewValue=iff(isnotempty(AssignedLicenseNewValue),parse_json(strcat('{"',substring(replace_string(replace_string(replace_string(replace_string(replace_string(tostring(parse_json(AssignedLicenseNewValue)),'=[','":["'),"=",'":"'),",",'","'),"]]",'"]}'),'" ','"'),1))),parse_json(''))
| extend NewSkuName=tostring(AssignedLicenseNewValue.SkuName)
//| project TargetUser,AssignedLicenseNewValue, AssignedLicenseOldValue, LicenceUpdateProperties
| summarize 
TimeGenerated=min(TimeGenerated),
OperationName=make_set(OperationName)[0],
InitiatedVia=make_set(InitiatedVia)[0],
InitiatedUser=make_set(InitiatedUser)[0], 
TargetUser=make_set(TargetUser)[0], 
ipAddress=make_set(ipAddress)[0],
LicenceUpdateProperties=make_set(LicenceUpdateProperties)[0],
OldSkuName=make_list(OldSkuName),
UserAgent=make_list(UserAgent)[0],
NewSkuName=make_list(NewSkuName),
InitiatedApp=make_list(InitiatedApp)[0],
InitiatedPrincipalId=make_list(InitiatedPrincipalId)[0] 
by CorrelationId
| extend ['Assigned New Licenses']=tostring(set_difference(NewSkuName,OldSkuName))
| project TimeGenerated, OperationName, InitiatedUser,InitiatedApp,UserAgent,ipAddress,TargetUser,['Assigned New Licenses'],InitiatedVia,InitiatedPrincipalId,LicenceUpdateProperties, OldSkuName, NewSkuName
