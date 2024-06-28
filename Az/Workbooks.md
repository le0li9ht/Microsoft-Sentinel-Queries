List all workbooks name from a resource group
```
resourceGroupName = "<ResoruceGroupName>"
az resource list --resource-group $resourceGroupName --resource-type "microsoft.insights/workbooks" --query "[].name" --output table
```
