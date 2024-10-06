az login  
az group create --name RedTeamSentinel --location southeastasia  
//Find the userId  
az ad user show --id "user@example.com" --query "id"  
//Find the role Id  
az role definition list --query "[].{name:name, roleType:roleType, roleName:roleName}" --output tsv | grep "Log Analytics Contributor"  
az role definition list --name "Log Analytics Contributor"  
//Find the scope(resourceId)  
az group list --query "[].{name:name, id:id}" --output tsv  
//Assign the role   
az role assignment create --assignee "User@example.com" --role "92aaf0da-9dab-42b6-94a3-d43ce8d16293" --scope "subscriptions/<subscriptionid>/resourceGroups/RedTeamSentinel"  


