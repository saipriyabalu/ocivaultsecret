import io
import json
import base64
import oci
import logging
import hashlib
import datetime
 
from datetime import timedelta
from fdk import response
 
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
    expiresAt = (datetime.datetime.utcnow() + timedelta(seconds=60)).replace(tzinfo=datetime.timezone.utc).astimezone().replace(microsecond=0).isoformat()
    compartment_id=auth_token=token=vault_id=secret_value=secret_ocid=""
    try:
        #auth_token = json.loads({"type": "USER_DEFINED", "data": {"apikey": "request.headers[X-Api-Key]"}})
        token = json.loads(data.getvalue())["data"]["apikey"]
        logging.getLogger().info("Token:"+token)
        cfg = dict(ctx.Config())
        vault_id = cfg["vault_id"]
        compartment_id = cfg["compartment_id"]
        signer = oci.auth.signers.get_resource_principals_signer()
        vault_client = oci.vault.VaultsClient({}, signer=signer)
        list_secrets_response = vault_client.list_secrets(
        compartment_id=compartment_id,
        sort_by="NAME",
        sort_order="ASC",
        vault_id=vault_id)
        logging.getLogger().info(len(list_secrets_response.data))
        auth=0
        for i in range(0,len(list_secrets_response.data)):
            secret_ocid= list_secrets_response.data[i].id
            secret_value= str(get_text_secret(secret_ocid))
            if secret_value == token:
                auth=+1
 
        if auth==1:
            return response.Response(
                ctx,
                status_code=200,
                response_data=json.dumps({"active": True, "principal": "foo", "scope": "bar", "clientId": "1234", "expiresAt": expiresAt, "context": {"username": token}})
                )
 
    except (Exception, ValueError) as ex:
        logging.getLogger().info('error parsing json payload: ' + str(ex))
        pass
 
    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": "API-key", "content": token})
        )
