import io
import json
import base64
import oci
import logging
import hashlib

from fdk import response

# Create a default config using DEFAULT profile in default location
# Refer to
# https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File
# for more info


#Initializing variables
compartment_id=vault_id=secret_value=secret_ocid=""

#Get secret values and compare with secret value passed by the user
def get_vault_secret(vault_id,compartment_id,secretval):
    logging.getLogger().info("Str of compart id"+str(compartment_id))

    #Authorize the user
    signer = oci.auth.signers.get_resource_principals_signer()
    #Use the OCI Vault Client and pass the Signer
    vault_client = oci.vault.VaultsClient({}, signer=signer)   
    
    #list all the secrets in a vault
    list_secrets_response = vault_client.list_secrets(
    compartment_id=compartment_id,
    sort_by="NAME",
    sort_order="ASC",
    vault_id=vault_id)
    logging.getLogger().info(len(list_secrets_response.data))

    auth=0
    #Compare the secret value passed by the user matches the value in the vault
    for i in range(0,len(list_secrets_response.data)):
        #We get the value of secret_ocid from list of secrets 
        secret_ocid= list_secrets_response.data[i].id   

        #Call the function "get_text_secret" and pass the secret_ocid as an argument to get back the value of the secret 
        secret_value= str(get_text_secret(secret_ocid))
        logging.getLogger().info("secret_value: "+ secret_value)

        #if the secret value received from the function matches secret value passed by the user, then return Authorized
        if secret_value == secretval:
            auth=+1
    
    if auth==1:
        return "Authorized"
    else: 
        return "Not Authorized"
        #return compartment_id

# Get the value of the secret for the given secret_ocid
def get_text_secret(secret_ocid):
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        client = oci.secrets.SecretsClient({}, signer=signer)
        secret_content = client.get_secret_bundle(secret_ocid).data.secret_bundle_content.content.encode('utf-8')
        decrypted_secret_content = base64.b64decode(secret_content).decode("utf-8")
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    return decrypted_secret_content


def handler(ctx, data: io.BytesIO=None):

    #Arguments passed from the command line or in the body of the API gateway
    try:   
        body = json.loads(data.getvalue())
        secretval= body["secretval"]
    except Exception:
        error = """
                Input a JSON object in the format: '{"secretval": "<secretval>"}'
                """
        raise Exception(error)

    logging.getLogger().info("secretval:" + secretval)

    #Pass the config variables to the function
    cfg = dict(ctx.Config())
    vault_id = cfg["vault_id"]
    logging.getLogger().info("vault_id = " + vault_id)
    compartment_id = cfg["compartment_id"]
    logging.getLogger().info("compartment_id = " + compartment_id) 

    #Call the function to Authorize the secret value passed by the user
    resp = get_vault_secret(vault_id,compartment_id,secretval)
    logging.getLogger().info("function end")
    
    #Return the response
    return response.Response(
        ctx, 
        response_data=resp,
        headers={"Content-Type": "application/json"}
    )