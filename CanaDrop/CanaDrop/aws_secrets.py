import boto3
from botocore.exceptions import ClientError
import json

def get_secret(secret_name, region_name="us-east-2"):
    client = boto3.client('secretsmanager', region_name=region_name)

    try:
        response = client.get_secret_value(SecretId=secret_name)
        return json.loads(response['SecretString'])
    except ClientError as e:
        raise e
