'''
Project: Sensitive Data Analyzer (SDA)
Function name: sda-macie-submit-scan
Description: Process Access Analyzer findings related to S3 bucket external access and launch Macie classification job
Version:
1.0 - Initial version
2.0 - Changed db query period to minutes(configurable)
    - Added cost optimization functinality to avoid Macie scan if the bucket is already scanned within last <n> minutes using Macie api calls
2.1 - Returns custom response for Macie classification job
2.2 - Added functionality to return response for tagged bucket
	  Added functionality to return response for bucket scanned prior
3.0 - Query and update DDB for Macie scan status and checking bucket scanned prior
      Added environment variables for DynamoDB table names

'''

import boto3
import json
import datetime
import os
import logging
from boto3.dynamodb.conditions import Key, Attr


# Define Amazon Macie client
macie_client = boto3.client('macie2')

# Define Amazon S3 client
s3 = boto3.client('s3')

# Define DynamoDB client
dynamodb = boto3.resource('dynamodb')


# Set logging level
logger = logging.getLogger()
logLevel = os.environ['logLevel']
if logLevel == 'debug':
    logger.setLevel(logging.DEBUG)
if logLevel == 'info':
    logger.setLevel(logging.INFO)
if logLevel == 'warning':
    logger.setLevel(logging.WARNING)
if logLevel == 'error':
    logger.setLevel(logging.ERROR)
if logLevel == 'critical':
    logger.setLevel(logging.CRITICAL)
logger.debug('logLevel: ' + logLevel)

# Read env vars
macieScanPeriodOffset = int(os.environ['macieScanPeriodOffset'])
bucketTagKey = os.environ['bucketTagKey']
bucketTagValue = os.environ['bucketTagValue']
tableAaFindings = os.environ['tableAaFindings']
tableMacieScanStatus = os.environ['tableMacieScanStatus']


def lambda_handler(event, context):

    ## Print env vars
    logger.info(f'macieScanPeriodOffset = {macieScanPeriodOffset}')
    logger.info(f'bucketTagKey = {bucketTagKey}')
    logger.info(f'bucketTagValue = {bucketTagValue}')
    logger.info(f'tableAaFindings = {tableAaFindings}')
    logger.info(f'tableMacieScanStatus = {tableMacieScanStatus}')
    
    #tableSdaAaFindings = dynamodb.Table('sda-aaFindings2')
    #tableSdaMacieScanStatus = dynamodb.Table('sda-MacieScanStatus')
    tableSdaAaFindings = dynamodb.Table(tableAaFindings)
    tableSdaMacieScanStatus = dynamodb.Table(tableMacieScanStatus)
    
    ## Get AA findings from the database
    ####resp_queryAccessAnalyzerFindings = queryAccessAnalyzerFindings(aaFindingPeriodOffset)
    resp_queryAccessAnalyzerFindings = queryAccessAnalyzerFindingsV2(tableSdaAaFindings)

    logger.info("Response from queryAccessAnalyzerFindings():")
    logger.info(resp_queryAccessAnalyzerFindings)
    
    ## Check if there is any bucket to process
    if resp_queryAccessAnalyzerFindings['Count'] == 0:
        logger.info('No S3 bucket to process')
        return ('No S3 bucket to process')

    ## Process AA findings from the database
    responseItems = []
    bucketsToScan = []
    for item in resp_queryAccessAnalyzerFindings['Items']:
        createDate = item['createDate']
        aaFindingId = item['aaFindingId']
        bucketArn = item['resourceName']
        bucketName = bucketArn.replace('arn:aws:s3:::', '')
        bucketAccountId = item['resourceAccountId']
        bucketRegion = item['resourceRegion']
        extPrincipal = item['extPrincipal']
        #bucketsToScan.add((bucketName,bucketAccountId,bucketRegion))
        bucketsToScan.append({'bucketName':bucketName,'bucketArn':bucketArn,'bucketAccountId':bucketAccountId,'bucketRegion':bucketRegion})

    # Sprint-6 changes - removed dedup - Need to check SH reporting for dup bkt in response 
    ### Discard duplicate buckets and process
    #for i in dict((v['bucketName'],v) for v in bucketsToScan).values():
    #    bucketName = i['bucketName']
    #    bucketArn = i['bucketArn']
    #    bucketAccountId = i['bucketAccountId']

        logger.info("###########################")
        logger.info(f'Processing s3 bucket: {bucketName}')
        logger.info("###########################")

        ## Check if s3 bucket is tagged
        if isBucketTagged(bucketName, bucketAccountId, bucketTagKey, bucketTagValue):
            logger.info("Skipping Macie scan. S3 bucket (" + bucketName + ") contains tags: (" + bucketTagKey + ":" + bucketTagValue + ")" )
            responseItem={
                    "resourceAccountId": bucketAccountId,
                    #"extPrincipal": extPrincipal,
                    "aaFindingId": aaFindingId,
                    "bucketArn": bucketArn,
                    "scanStatus": "skipped",
                    "tagName": bucketTagKey,
                    "tagValue": bucketTagValue}
            responseItems.append(responseItem)
            
            ## update DDB scanStatus:skipped, skipScanReason:tag, processStatusFlag:1, processTimestamp:timestamp (UTC)
            tableSdaAaFindings.update_item(
                Key={
                    'createDate': createDate,
                    'aaFindingId': aaFindingId
                },
                UpdateExpression="set scanStatus=:1, skipScanReason=:2, processStatusFlag=:3, processTimestamp=:4",
                ExpressionAttributeValues={
                    ':1': 'skipped',
                    ':2': 'tag',
                    ':3': 1,
                    ':4': datetime.datetime.now(datetime.timezone.utc).isoformat()
                },
                ReturnValues="UPDATED_NEW"
            )
            
        else:
            ## Check if bucket was scanned prior
            if macieScanPeriodOffset >= 0:
                #bucketPriorScanStatus = isBucketScanned(bucketArn, macieScanPeriodOffset, bucketRegion, bucketAccountId)
                bucketPriorScanStatus = isBucketScannedV2(tableSdaMacieScanStatus, bucketArn, macieScanPeriodOffset, bucketRegion, bucketAccountId)    ## !!!!!!!!!!!!!!!

            if bucketPriorScanStatus:
                logger.info("Skipping Macie scan. S3 bucket (" + bucketName + ") was scanned within past " + str(macieScanPeriodOffset) + " minutes by Macie classification job (" + str(bucketPriorScanStatus) + ")")
                responseItem={
                        "resourceAccountId": bucketAccountId,
                        #"extPrincipal": extPrincipal,
                        "aaFindingId": aaFindingId,
                        "bucketArn": bucketArn,
                        "scanStatus": "skipped",
                        "macieJobArn": bucketPriorScanStatus
                    }
                responseItems.append(responseItem)
                
                ## update DDB scanStatus:skipped, skipScanReason:prior-scan, processStatusFlag:1, processTimestamp:timestamp (UTC)
                tableSdaAaFindings.update_item(
                    Key={
                        'createDate': createDate,
                        'aaFindingId': aaFindingId
                    },
                    UpdateExpression="set scanStatus=:1, skipScanReason=:2, processStatusFlag=:3, processTimestamp=:4",
                    ExpressionAttributeValues={
                        ':1': 'skipped',
                        ':2': 'prior-scan',
                        ':3': 1,
                        ':4': datetime.datetime.now(datetime.timezone.utc).isoformat()
                    },
                    ReturnValues="UPDATED_NEW"
                )
                
            else:
                logger.info(f'Launching Macie classification job for s3 bucket: {bucketName}')
                date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S%Z")
                try:
                    responseMacieScan = macie_client.create_classification_job(
                        description = 'SDA S3 bucket scan',
                        initialRun = True,
                        jobType = 'ONE_TIME',
                        name = f'sda-s3bkt-scan-{bucketName}-{date_time}',
                        s3JobDefinition = {
                            'bucketDefinitions': [{
                                'accountId': bucketAccountId, 
                                'buckets': [bucketName]
                            }]
                        }
                    )
                    
                    logger.info(f'Macie classification job submitted successfully for S3 bucket: {bucketName}')
                    logger.debug("Response: ")
                    logger.debug(responseMacieScan)
                    
                    responseItem={
                        "resourceAccountId": bucketAccountId,
                        #"extPrincipal": extPrincipal,
                        "aaFindingId": aaFindingId,
                        "bucketArn": bucketArn,
                        "scanStatus": "scanned",
                        "macieJobArn": responseMacieScan.get('jobArn'),
                        "macieJobId": responseMacieScan.get('jobId')
                    }
                    responseItems.append(responseItem)

                    ## Update DDB table sda-MacieScanStatus
                    tableSdaMacieScanStatus.put_item(
                        Item={
                            'resourceName': bucketArn,
                            'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            'macieJobId': responseMacieScan.get('jobId'),
                            'macieJobArn': responseMacieScan.get('jobArn')
                             })
                    
                    ## update DDB scanStatus:scanned, processStatusFlag:1, processTimestamp:timestamp (UTC)
                    tableSdaAaFindings.update_item(
                        Key={
                            'createDate': createDate,
                            'aaFindingId': aaFindingId
                        },
                        UpdateExpression="set scanStatus=:1, processStatusFlag=:3, processTimestamp=:4",
                        ExpressionAttributeValues={
                            ':1': 'scanned',
                            ':3': 1,
                            ':4': datetime.datetime.now(datetime.timezone.utc).isoformat()
                        },
                        ReturnValues="UPDATED_NEW"
                    )

                except Exception as e:
                    logger.critical('Macie create classification job failed!')
                    logger.critical(e)
                    return

    response = {}
    response['items'] = responseItems
    logger.debug("Response from Lambda:")
    logger.debug(response)
    return response


def isBucketTagged(bucketName, bucketAccountId, tagKey, tagValue):
    '''
    Desc: 
        Checks if the bucket is tagged to be excluded from Macie scan
    Arguments:
        bucketName: s3 bucket name
        bucketAccountId: S3 bucket account id
        tagKey: Tag key
        tagValue: Tag value
    Returns:
        Boolean
    '''
    logger.info(f'Verifying if S3 bucket contains tag')
    try:
        response = s3.get_bucket_tagging(
            Bucket=bucketName,
            ExpectedBucketOwner=(bucketAccountId)
            )
        tags = response['TagSet']
        logger.debug("Response from s3.get_bucket_tagging():")
        logger.debug(tags)

        for tag in tags:
            if tag['Key'] == tagKey and tag['Value'] == tagValue:
                #logger.debug("S3 bucket " + bucketName + " contains tags: (" + tagKey + ":" + tagValue + ")" )
                return True
        return False
    except Exception as bktTagError:
        logger.info(f'S3 bucket ({bucketName}) does not contain tag')
        #logger.critical(bktTagError)
        return False


def queryAccessAnalyzerFindings(aaFindingPeriodOffset):
    '''
    Desc: 
        Queries DynamoDB to get findings published by IAM Access Analyzer within last <n> minutes
    Arguments:
        aaFindingPeriodOffset: Period in minutes
    Returns:
        dict
    '''
    
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('sda-aaFindings')
    
    last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=aaFindingPeriodOffset)
    logger.debug("Current time in UTC minus " + str(aaFindingPeriodOffset) + " minutes: " + str(last_scan_time))

    #response = table.scan(FilterExpression=Attr('createdAt').gt('2021-04-27T21:09:30.172Z'))
    response = table.scan(FilterExpression=Attr('createdAt').gt(datetime.datetime.strftime(last_scan_time,'%Y-%m-%dT%H:%M:%S.%f%z')))
    return response


def queryAccessAnalyzerFindingsV2(dynamoDbTable):
    '''
    Desc: 
        Queries DynamoDB to get findings published by IAM Access Analyzer with processStatusFlag=0
    Arguments:
        dynamoDbTable: DynamoDB table name
    Returns:
        dict
    '''
    
    #dynamodb = boto3.resource('dynamodb')
    #table = dynamodb.Table('sda-aaFindings2')
    #table = dynamodb.Table(tableName)

    
    #last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=aaFindingPeriodOffset)
    #logger.debug("Current time in UTC minus " + str(aaFindingPeriodOffset) + " minutes: " + str(last_scan_time))

    #response = table.scan(FilterExpression=Attr('createdAt').gt('2021-04-27T21:09:30.172Z'))
    #response = table.scan(FilterExpression=Attr('createdAt').gt(datetime.datetime.strftime(last_scan_time,'%Y-%m-%dT%H:%M:%S.%f%z')))
    #Sprint-6 changes
    response = dynamoDbTable.scan(FilterExpression=Attr('processStatusFlag').eq(0))
    return response


def isBucketScanned(bucketArn, macieScanPeriodOffset, sourceRegion, resourceAccountId):
    '''
    Desc: 
        Checks if the bucket was scanned by Macie in last <n> minutes
    Arguments:
        bucketArn: ARN of s3 bucket
        macieScanPeriodOffset: Period in minutes
        sourceRegion: S3 bucket region
        resourceAccountId S3 bucket account id
    Returns:
        Last Macie classification job Id (string) | False (boolean)
    '''

    logger.info("Past scan period offset (in minutes): " + str(macieScanPeriodOffset))
    logger.info(f'Verifying if S3 bucket ({bucketArn}) was scanned by Macie in last {str(macieScanPeriodOffset)} minutes')
    
    ## Get buckets scaned by Macie
    try:
        descBucketsResponse = macie_client.describe_buckets()
        logger.debug("Respose:")
        logger.debug(descBucketsResponse)
    except Exception as e:
        logger.critical("Failed to describe buckets with Amazon Macie!")
        logger.critical(e)
        return
    
    #current_time = datetime.datetime.now()
    #print(current_time - datetime.timedelta(days=1))   ## last 24 hrs
    #print(datetime.datetime.utcnow())  ##naive
    logger.debug("Current time in UTC: " + str(datetime.datetime.now(datetime.timezone.utc)))  ##tz aware

    #last_scan_time = datetime.datetime.utcnow() - datetime.timedelta(days=1)  ##naive
    #last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)  ##tz aware
    #last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)  ##tz aware
    last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=macieScanPeriodOffset)  ##tz aware
    logger.debug("Current time in UTC minus " + str(macieScanPeriodOffset) + " minutes: " + str(last_scan_time))
    
    bucketList = descBucketsResponse.get('buckets')

    if bucketList: 
        for i in bucketList:
            if (i.get('jobDetails').get('isDefinedInJob') == 'TRUE') and \
                (i.get('jobDetails').get('lastJobRunTime') >= last_scan_time) and \
                (i.get('bucketArn') == bucketArn):
                logger.debug("S3 bucket was scanned within past " + str(macieScanPeriodOffset) + " minutes:" + "\nS3 bucket ARN: " + i.get('bucketArn') + "\nLast scan timestamp: " + str(i.get('jobDetails').get('lastJobRunTime')) + "\nMacie classification job Id: " + str(i.get('jobDetails').get('lastJobId')))
                macieJobArn = 'arn:aws:macie2:' + sourceRegion+':' + resourceAccountId + ':classification-job/' + str(i.get('jobDetails').get('lastJobId'))
                return(macieJobArn)
                break
        
        logger.info("S3 bucket was not scaned by Macie")
        return(False)

    else:
        return(False)


def isBucketScannedV2(dynamoDbTable, bucketArn, macieScanPeriodOffset, sourceRegion, resourceAccountId):
    '''
    Desc: 
        Checks if the bucket was scanned by Macie in last <n> minutes
    Arguments:
        dynamoDbTable: DynamoDB table name
        bucketArn: ARN of s3 bucket
        macieScanPeriodOffset: Period in minutes
        sourceRegion: S3 bucket region
        resourceAccountId S3 bucket account id
    Returns:
        Last Macie classification job Id (string) | False (oolean)
    '''

    logger.info("Past Macie scan period offset (in minutes): " + str(macieScanPeriodOffset))
    logger.info(f'Verifying if S3 bucket ({bucketArn}) was scanned by Macie in last {str(macieScanPeriodOffset)} minutes')
    
    #current_time = datetime.datetime.now()
    #print(current_time - datetime.timedelta(days=1))   ## last 24 hrs
    #print(datetime.datetime.utcnow())  ##naive
    logger.debug("Current time in UTC: " + str(datetime.datetime.now(datetime.timezone.utc)))  ##tz aware

    #last_scan_time = datetime.datetime.utcnow() - datetime.timedelta(days=1)  ##naive
    #last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)  ##tz aware
    #last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)  ##tz aware
    last_scan_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=macieScanPeriodOffset)  ##tz aware
    logger.debug("Current time in UTC minus " + str(macieScanPeriodOffset) + " minutes: " + str(last_scan_time))
    
    ## Query DynamoDB table sda-MacieScanStatus
    #table = dynamodb.Table('sda-MacieScanStatus')
    
    response = dynamoDbTable.query(
        KeyConditionExpression=
            Key('resourceName').eq(bucketArn) & Key('createdAt').gt(datetime.datetime.strftime(last_scan_time,'%Y-%m-%dT%H:%M:%S.%f%z'))
    )
    logger.debug(f'Response from DDB sda-MacieScanStatus query: {response}')

    if response['Count'] == 0:
        logger.info("S3 bucket was not scaned by Macie")
        return(False)
    else:
        for item in response['Items']:
            bucketArn = item['resourceName']
            bucketName = bucketArn.replace('arn:aws:s3:::', '')
            macieJobArn = item['macieJobArn']
            return(macieJobArn)
            break
        
        logger.info("S3 bucket was not scaned by Macie")
        return(False)
