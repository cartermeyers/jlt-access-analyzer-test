'''
Project: Sensitive Data Analyzer (SDA)
Function name: sda-macie-check-status
Description: Check the status of a Macie classification job based on the given job id
Version:
1.0 - Initial version
2.0 - Added functionality to check is there is any finding.
    - Process custom input event
    - Returns string "In Progress" until all the Macie jobs are finished (COMPLETE,CANCELLED,PAUSED, USER_PAUSED)
      OR returns the expected response
3.0 - Ignore input event item for skipped Macie scan which does not have Macie job id

'''

import boto3
import json
import datetime
import os
import logging

# Define Amazon Macie client
macie_client = boto3.client('macie2')

# Set logging level
logger = logging.getLogger()
logLevel = os.environ['LOG_LEVEL']
if logLevel == 'DEBUG':
    logger.setLevel(logging.DEBUG)
if logLevel == 'INFO':
    logger.setLevel(logging.INFO)
if logLevel == 'WARNING':
    logger.setLevel(logging.WARNING)
if logLevel == 'ERROR':
    logger.setLevel(logging.ERROR)
if logLevel == 'CRITICAL':
    logger.setLevel(logging.CRITICAL)
logger.debug('LOG_LEVEL: ' + logLevel)

    
def lambda_handler(event, context):
    
    logger.debug('Print event value:')
    logger.debug(event)
    
    responseItems = []
    itemList = event['items']
    
    for i in itemList:
        bucketArn = i['bucketArn']
        macieJobId = i['macieJobId']
        macieJobArn = i['macieJobArn']
        
        ## Check Macie job status
        try:
            response = macie_client.describe_classification_job(
                jobId = macieJobId
            )
            
            logger.info("Macie classification job status retrieved successfully for job ID: " + macieJobId)
            logger.debug("Response from api call describe_classification_job: ")
            logger.debug(response)
            macieJobStatus = response.get('jobStatus')
            logger.info('Macie job current status: ' + macieJobStatus)
            
            ## Return "In Progress" if status of any job is running
            if macieJobStatus not in ('COMPLETE','CANCELLED','PAUSED', 'USER_PAUSED'):
                return "In Progress"
        
        except Exception as macieDescJobError:
            logger.critical("Failed to retrieve Macie classification job status!")
            logger.critical(macieDescJobError)
            return macieDescJobError

        ## Check if there is any finding
        if checkMacieFinding(macieJobId):
            sensitiveData = 'yes'
        else:
            sensitiveData = 'no'
        
        responseItem={
                "bucketArn": bucketArn,
                "macieJobArn": macieJobArn,
                "macieJobStatus": macieJobStatus,
                "sensitiveData": sensitiveData
            }
        responseItems.append(responseItem)

    response = {}
    response['items'] = responseItems
    logger.debug("Response from Lambda:")
    logger.debug(response)
    return response


def checkMacieFinding(macieJobId):
    '''
    Desc: Checks if there is any finding by the Macie classification job
    Arguments:
        macieJobId: Macie classification job id
    Returns:
        Boolean
    '''
    
    try:
        respMacieFinding = macie_client.get_finding_statistics(groupBy='classificationDetails.jobId')
        logger.debug(f'Response from api call get_finding_statistics: {respMacieFinding}')
        if respMacieFinding:
            for i in respMacieFinding['countsByGroup']:
                if i.get('groupKey') == macieJobId:
                    return True

        return False
    except Exception as macieFindingError:
        logger.info('Failed to retrive Macie finding statistics!')
        logger.critical(macieFindingError)
        return macieFindingError
