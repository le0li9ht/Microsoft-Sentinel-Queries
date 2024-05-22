## Disable cloud workload protection 
Attackers may disable the cloud workload protection service which raises security alerts upon detection of malicious activities in cloud storage services. 
![](Images/CWP2.png)
### MITRE ATT&CK
| Tactic | Technique | Link    |
| ---  | --- | --- |
| TA0005-Defense Evasion | MS-T811-Disable cloud workload protection | https://microsoft.github.io/Threat-matrix-for-storage-services/techniques/disable-protection-service/|
| |T1562.001-Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

Removing Cloud Workload Protection for storage accounts generates several events. Among these, the EVENTSUBSCRIPTIONS/DELETE event is the most specific and relevant for constructing KQL queries. However, for full clarity, please also consider the other events occurring at the same time during your investigation.  

- _MICROSOFT.SECURITY/PRICINGS/WRITE_
- _MICROSOFT.SECURITY/ADVANCEDTHREATPROTECTIONSETTINGS/WRITE_  
- _MICROSOFT.SECURITY/DEFENDERFORSTORAGESETTINGS/WRITE_  
- _**MICROSOFT.EVENTGRID/SYSTEMTOPICS/DELETE**_  
- _**MICROSOFT.EVENTGRID/EVENTSUBSCRIPTIONS/DELETE**_  
- _MICROSOFT.SECURITY/DATASCANNERS/DELETE_

![](Images/CWP.png)  
![](Images/CWP1.png)

