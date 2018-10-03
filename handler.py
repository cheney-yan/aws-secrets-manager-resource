#!/usr/bin/env python
# -*- coding: utf-8 -*-
from botocore.exceptions import ClientError
import boto3
import json
import logging
from urllib.request import urlopen, Request, HTTPError, URLError
from urllib.parse import urlencode

logger = logging.getLogger('SecretsManagerHandler')
logger.setLevel(logging.INFO)


def to_plain_object(object):
    result = {}
    for k, v in object.items():
        if 'password'in k.lower() or 'plaintext'in k.lower():
            result[k] = '***'
        elif isinstance(v, dict):
            result[k] = to_plain_object(v)
        else:
            result[k] = v
    return result


def lambda_handler(event, context):
    secret_result = {}
    if 'LogLevel'in event['ResourceProperties']:
        logger.setLevel(event['ResourceProperties']['LogLevel'])
    logger.debug("Received request: %s", json.dumps(to_plain_object(event)))
    # Initialize the CloudFormation response dict
    response = {
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Status": "SUCCESS",
        "NoEcho": True,
        "Data": {}
    }
    try:
        # Assign the physical resource id
        response['PhysicalResourceId'] = physical_resource_id(event)

        # Only execute AWS Secrets Manager actions on CloudFormation Create requests
        if event['RequestType'] == 'Create'or event['RequestType'] == 'Update':
            if event['ResourceProperties']['SecretAction'] == 'get':
                secret_result, response = get_secret_password(
                    event=event, response=response)
            else:
                secret_result, response = create_or_update_secret(
                    event=event, response=response)
        elif event['RequestType'] == 'Delete':
            logger.warn('Delete is handled by AWS automatically')
        else:
            logger.warn('%s is not supported. Nothing to do.',
                        event['RequestType'])

        # Construct and send a response to CloudFormation
        respond_to_cloudformation(event=event, response=response)

        return secret_result
    except Exception as e:
        logger.exception(e)
        respond_to_cloudformation(event=event, response={
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Status": "FAILED",
            "NoEcho": True,
            "Data": {'Exception': str(e)}
        })

# Return the event object physical_resource_id


def physical_resource_id(event):
    if event.get('PhysicalResourceId', False):
        return event['PhysicalResourceId']
    return event['LogicalResourceId'] + '-12345'


def generate_random_pwd(region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )
    secret_pwd = client.get_random_password()
    secret_pwd = secret_pwd['RandomPassword']
    return secret_pwd

# Wrapper function that implements the `get` action
# Calls the get_secret fucntion to retrieve the password for a given SecretName


def get_secret_password(event, response):
    logger.info("Retrieving current password")
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']
    logger.debug(
        'SecretAction is `get` - Getting value for secret: %s ', secret_name)
    secret_result = get_secret(
        secret_name=secret_name, region_name=region_name)
    if secret_result.get("Error", False):
        logger.error('Value for secret %s retrieve FAILED ', secret_name)
        response['Status'] = "FAILED"
        response['Reason'] = secret_result['Error']['Message']
    else:
        logger.info('Value for secret %s successfully retrieved ',
                    (secret_name))
        secret_string_json = json.loads(secret_result['SecretString'])
        response['PhysicalResourceId'] = secret_result['ARN']
        response['Data']['SecretPassword'] = secret_string_json['password']
    return json.dumps(secret_result, indent=4, sort_keys=True, default=str), response

# Calls the get_secret_value method to retrieve the password for a given SecretName


def get_secret(secret_name, region_name):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_response = client.get_secret_value(SecretId=secret_name)
        return get_secret_response
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error(
                '>>>>> The specified secret cannot be found - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            logger.error(
                '>>>>> The requested secret cannot be decrypted - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error(
                '>>>>> The request was invalid - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error(
                '>>>>> The request had invalid parameters - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logger.error(
                '>>>>> An error occurred on the server side - the full error message is: %s <<<<<', e)
            return e.response

# Mock method
def delete_secret(event, response):
    logger.info("Delete secret")
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )
    try:
        delete_secret_response = client.delete_secret(
            SecretId=secret_name,
        )
        logger.info(
            'The requested secret %s has been successfully deleted, retation period as default.', secret_name)
        return delete_secret_response
    except ClientError as e:
        logger.error(
            '>>>>> Failed to delete secrets. - the full error message is: %s <<<<<', e)
        return e.response


def create_or_update_secret(event, response):
    logger.info("Creating or update secret")
    secret_name = event['ResourceProperties']['SecretName']
    region_name = event['ResourceProperties']['Region']
    # it is username, pasword type:
    if 'SecretUsername'in event['ResourceProperties']:
        if 'SecretPassword'not in event['ResourceProperties']:
            logger.info(
                'SecretAction is `upsert` - Creating or updating secret %s with randomly generated password ', secret_name)
            secret_pwd = generate_random_pwd(region_name=region_name)
            response['Data']['SecretPassword'] = secret_pwd
        else:
            secret_pwd = event['ResourceProperties']['SecretPassword']
            logger.info(
                'SecretAction is `upsert` - Creating or updating secret: %s with provided password ', secret_name)
        secret_string = json.dumps(
            {'Username': event['ResourceProperties']['SecretUsername'], 'Password': secret_pwd})
    else:  # plain text type
        # generate a new one
        if 'SecretPlaintext'not in event['ResourceProperties']:
            logger.info(
                'SecretAction is `upsert` - Creating or updating secret %s with randomly generated plain text ', secret_name)
            secret_string = generate_random_pwd(region_name=region_name)
            response['Data']['SecretPlaintext'] = secret_string
        else:
            secret_string = event['ResourceProperties']['SecretPlaintext']
    secret_result = upsert_secret(event=event, secret_string=secret_string)
    if secret_result.get('Error', False):
        response['Status'] = "FAILED"
        response['Reason'] = secret_result['Error']['Message']
    else:
        response['PhysicalResourceId'] = secret_result['ARN']

    return secret_result, response

# Calls the create_secret method to create the requested SecretName, or
# calls the put_secret_value method to update the requested SecretName


def upsert_secret(event, secret_string):
    region_name = event['ResourceProperties']['Region']
    secret_desc = event['ResourceProperties']['SecretDescription']
    secret_name = event['ResourceProperties']['SecretName']
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )
    try:
        if 'KMSAlias'in event['ResourceProperties']:
            upsert_secret_response = client.create_secret(
                Name=secret_name,
                Description=secret_desc,
                SecretString=secret_string,
                KmsKeyId=event['ResourceProperties']['KMSAlias']
            )
        else:
            upsert_secret_response = client.create_secret(
                Name=secret_name,
                Description=secret_desc,
                SecretString=secret_string
            )
        logger.info(
            'The requested secret %s has been successfully created ' % secret_name)
        return upsert_secret_response
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceExistsException':
            try:
                if 'KMSAlias'in event['ResourceProperties']:
                    put_secret_value_response = client.put_secret_value(
                        SecretId=secret_name,
                        SecretString=secret_string,
                    )
                else:
                    put_secret_value_response = client.put_secret_value(
                        SecretId=secret_name,
                        SecretString=secret_string
                    )
                logger.info(
                    'The requested secret %s has been successfully updated ' % secret_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidRequestException':
                    logger.error(
                        '>>>>> The request was invalid - the full error message is: %s <<<<<', e)
                    return e.response
                elif e.response['Error']['Code'] == 'InvalidParameterException':
                    logger.error(
                        '>>>>> The request had invalid parameters - the full error message is: %s <<<<<', e)
                    return e.response
                elif e.response['Error']['Code'] == 'EncryptionFailure':
                    logger.error(
                        '>>>>> The requested secret cannot be encrypted - the full error message is: %s <<<<<', e)
                    return e.response
                elif e.response['Error']['Code'] == 'InternalServiceError':
                    logger.error(
                        '>>>>> An error occurred on the server side - the full error message is: %s <<<<<', e)
                    return e.response
                elif e.response['Error']['Code'] == 'LimitExceededException':
                    logger.error(
                        '>>>>> The request exceeds Secrets Manager internal limits - the full error message is: %s <<<<<', e)
                    return e.response
                elif e.response['Error']['Code'] == 'MalformedPolicyDocumentException':
                    logger.error(
                        '>>>>> The policy provided is invalid - the full error message is: %s <<<<<', e)
                    return e.response
            return put_secret_value_response
        if e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error(
                '>>>>> The request was invalid - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error(
                '>>>>> The request had invalid parameters - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'EncryptionFailure':
            logger.error(
                '>>>>> The requested secret cannot be encrypted - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'InternalServiceError':
            logger.error(
                '>>>>> An error occurred on the server side - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'LimitExceededException':
            logger.error(
                '>>>>> The request exceeds Secrets Manager internal limits - the full error message is: %s <<<<<', e)
            return e.response
        elif e.response['Error']['Code'] == 'MalformedPolicyDocumentException':
            logger.error(
                '>>>>> The policy provided is invalid - the full error message is: %s <<<<<', e)
            return e.response

# Serialize, encode, and post the response object to CloudFormation


def respond_to_cloudformation(event, response):
    serialized = json.dumps(response)
    req_data = serialized.encode('utf-8')

    # Mask the password before logging out the CloudFormation response
    response['Data']['SecretPassword'] = '***'
    serialized = json.dumps(response)
    logger.info("Responding to CloudFormation with: %s" %
                (serialized))

    req = Request(
        event['ResponseURL'],
        data=req_data,
        headers={'Content-Length': len(req_data),
                 'Content-Type': ''}
    )
    req.get_method = lambda: 'PUT'

    try:
        urlopen(req)
        logger.info('Request to CFN API succeeded, nothing to do here ')
    except HTTPError as e:
        logger.error(
            '>>>>> Callback to CFN API failed with status %d <<<<<', e.code)
        logger.error('>>>>> Response: %s', e.reason)
    except URLError as e:
        logger.error('>>>>> Failed to reach the server - %s <<<<<', e.reason)
