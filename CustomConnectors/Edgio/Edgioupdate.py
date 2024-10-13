import http.client
import json
import requests
from urllib.parse import quote_plus

tenant_id = "Your_Azure_Tenant_ID"
#Registered Entra ID app Credentials
app_id = "Your_Entra_ID_Application_Client_ID"
app_secret = "Your_Entra_ID_App_Secret_Value"
#DCR values
dcr_immutable_id = "dcr-xxxxxxxxxxxxx" #Your_DCR_Immutable_ID
dce_endpoint = "https://Your_Data_Collection_Endpoint_URI/dataCollectionRules/{DCR_Immutable_ID}/streams/{Stream_Name}?api-version=2023-01-01"
# URL encoding the scope value
scope = "https://monitor.azure.com/.default"
# Prepare the body for the POST request
body = {
    "client_id": app_id,
    "scope": scope,
    "client_secret": app_secret,
    "grant_type": "client_credentials"
}
# Headers
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}
# URI for obtaining the access token from azure application.
uri = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
# Send the POST request
response = requests.post(uri, data=body, headers=headers)
print("****** Azure Token********")
# Check if the request was successful and retrieve the access token(Bearer Token)
if response.status_code == 200:
    token_info=response.json()
    bearer_token1 = "Bearer "+response.json().get("access_token")
    print("Bearer ",bearer_token1)
    print('TokenExpiry:',token_info.get("expires_in"),'\n')
    print('TokeType:',token_info.get('token_type'),'\n')
    print('Scope:',token_info.get('scope'),'\n')
else:
    print(f"Error: {response.status_code}, {response.text}")

# Step 1: Obtain the Bearer Token for Edgio
#token_url = "https://id.vdms.io/connect/token"
token_url = "https://id.edgio.app/connect/token"
token_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
}
token_data = {
    "client_id": "Your_Edgio_API_Client_ID",  # Replace with your actual client_id
    "client_secret": "Your_Edgio_API_Secret_Value",  # Replace with your actual client_secret
    "grant_type": "client_credentials",
    "scope": "app.rtld"
}
print("**********************Edgio Token*******************")
# Make the POST request to get the bearer token
token_response = requests.post(token_url, headers=token_headers, data=token_data)
if token_response.status_code == 200:
    # Parse the JSON response to get the token
    token_info = token_response.json()
    bearer_token ="Bearer "+token_info.get("access_token")
    print('TokenExpiry:',token_info.get("expires_in"),'\n')
    print('TokeType:',token_info.get('token_type'),'\n')
    print('Scope:',token_info.get('scope'),'\n')
    if not bearer_token:
        print("Error: 'access_token' not found in the response.")
        exit()
    print("Bearer Token:", bearer_token,'\n')
else:
    print("Error obtaining token:", token_response.status_code, token_response.text)
    exit()

conn = http.client.HTTPSConnection("edgioapis.com")
payload={"environment_id":"Your_Environment_ID","delivery_method": {"type":"http_post","authentication": { "type": "custom_authentication","token":bearer_token1},"destination_endpoint":dce_endpoint,"log_format": "json_array"},"description": "For Microsoft Sentinel","enabled": True,"fields":["rule_message", "rule_tags", "client_country_code", "client_country", "client_city", "sub_events_count", "sub_events","waf_instance_name", "waf_profile_name", "action_type", "waf_profile_type", "timestamp", "client_ip", "server_port", "url", "host","user_agent", "referer", "account_number", "uuid", "client_tls_ja3_md5", "rtld_profile_name"],"filters": {},"profile_name": "Sentinel"}
print(payload)
headers={'Authorization': bearer_token}
print (headers)
payload=json.dumps(payload)
payload=payload.encode('utf-8')
conn.request("PUT", "/rtld/v1/waf/profiles/<ProfileId>?environment_id=Your_Environment_ID", payload, headers)
res = conn.getresponse()
data = res.read()
print(data.decode("utf-8"))
