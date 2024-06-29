#!/bin/bash
subscriptionId="<subscriptionID>" #subscription Id
resourceGroupName="<resourcegroup>" #resource group name where workbooks are present.
apiVersion="2021-08-01" 
canFetchContent="true"  # Set to 'true' to fetch content

# Function to fetch and process workbook content
download_workbook_gallery_content() {
    local workbookId="$1"
    # Fetch workbook content
    local response=$(az rest --method get --url \
        "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/workbooks/$workbookId?api-version=$apiVersion&canFetchContent=$canFetchContent" | jq -r)
    #fetch workbookname from output
    workbookname=$(echo "$response" | jq -r ".properties.displayName")
    echo "Exporting $workbookname ......"
    #export each workbook content to .json files
    echo "$response" | jq -r ".properties.serializedData" | jq -r >"${workbookname}.json"
}

# Get workbook Ids and process each
az resource list --resource-group "$resourceGroupName" --resource-type "microsoft.insights/workbooks" --query "[].name" --output tsv | while IFS= read -r workbookId; do
    download_workbook_gallery_content "$workbookId"
done
