### RDP tunneing via ngrok can be detected using following event ID's  
Windows Security Auditing  
Event:4624  
Application and service logs -> Microsoft -> Windows -> TerminalServices - (LocalsessionManager/RemoteConnectionManager)  
Event:1149  
Event:21  
Event:24  
Event:25  

### How to collect TerminalServices logs into microsoft sentinel
Go to Microsoft sentinel-> settings->Workspace settings-> Agent Congiruatioon -> Add Windows Event Log and select the logs as shown  

![alt text](https://github.com/le0li9ht/Microsoft-Sentinel-Queries/blob/main/Windows/T1572-ProtocolTunneling/LogCollectionGuide-For-ngrok.png?raw-true)
