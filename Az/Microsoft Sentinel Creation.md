```
assignee=user@example.com
az login
//create the resource group in southeeast asia location 
az group create --name RedTeamSentinel --location southeastasia  
//Find the userId
userid=$(az ad user show --id "user@example.com" --query "id")  
//Find the role Id  
role_id=$(az role definition list --name "Log Analytics Contributor" --query "[].name" -o tsv)
//az role definition list --name "Log Analytics Contributor"  
//Find the scope(resourceId)  
//az group list --query "[].{name:name, id:id}" --output tsv
resourceid=$(az group list --query "[].id" --output tsv)
//Assign the role   
az role assignment create --assignee $userid --role "$role_id" --scope "$resourceid"
//Create Log Analytics workspace
az monitor log-analytics workspace create --resource-group RedTeamSentinel --workspace-name RedTeamSentinel

