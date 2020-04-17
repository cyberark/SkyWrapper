from utilities.Boto3Utilities import client_session_creator
from structures.TrailBucket import TrailBucket
from handlers.AthenaHandler import AthenaHandler
from handlers.ConfigHandler import ConfigHandler
from exceptions.AthenaBadQueryException import AthenaBadQueryException
from exceptions.CloudTrailBucketMissingLogsTableException import CloudTrailBucketMissingLogsTableException
import logging

class CloudTrailHandler(object):
    def __init__(self):
        self.__logger = logging.getLogger(__name__)
        self.__config = ConfigHandler.get_instance().get_config()
        self.trails = None
        self.__raw_trails_list = []

    def get_account_cloud_trails(self):
        if self.trails is None:
            self.trails  = []
            cloudtrail_client = client_session_creator('cloudtrail')
            trails_dict = cloudtrail_client.describe_trails()
            trail_list = trails_dict["trailList"]
            self.__raw_trails_list = trail_list
            self.parse_cloudtrail_list(trail_list)
        return self.trails

    def parse_cloudtrail_list(self, trail_list):
        for trail in trail_list:
            self.trails.append(TrailBucket(
                trail["Name"],
                trail["IncludeGlobalServiceEvents"],
                trail["IsOrganizationTrail"],
                trail["TrailARN"],
                trail["LogFileValidationEnabled"],
                trail["IsMultiRegionTrail"],
                trail["HasCustomEventSelectors"],
                trail["S3BucketName"],
                trail["HomeRegion"]
            ))

    def handle_creation_cloudtrail_logs_table(self, trail_object):
        self.__logger.warning(
            "There is no existing logs table for the trail {trail_name}.".format(trail_name=trail_object.trail_name))
        create_logs_table = None
        while create_logs_table is None:
            user_answer = input("Would you like to create one? (Y=yes / N=No)").lower()
            if user_answer == "y":
                create_logs_table = True
            elif user_answer == "n":
                create_logs_table = False
            else:
                self.__logger.warning("Incorrect input!")
        if not create_logs_table:
            raise CloudTrailBucketMissingLogsTableException()
        else:
            self.create_cloudtrail_logs_table(trail_object)

    def is_cloudtrail_logs_table_exists(self, trail_object):
        table_name = self.__config["athena"]["table_name"].format(table_name=trail_object.get_converted_s3_bucket_name_to_table_name())
        output_location = self.__config["athena"]["output_location"].format(account_id=self.__config["account"]["account_id"], region=trail_object.home_region)
        check_cloudtrail_existing_query = "select * from \"{table_name}\" limit 1".format(table_name=table_name)
        athena_handler = AthenaHandler(trail_object.home_region)
        try:
            athena_handler.fetchall_athena(check_cloudtrail_existing_query,
                                     self.__config["athena"]["database_name"],
                                     output_location
                                     )
        except AthenaBadQueryException as e:
            if " does not exist" in e.args[0]:
                self.handle_creation_cloudtrail_logs_table(trail_object)

    def create_cloudtrail_logs_table(self, trail_object):
        account_id = self.__config["account"]["account_id"]
        creating_default_database = "CREATE DATABASE IF NOT EXISTS default;"
        cloudtrails_logs_create_table_query = """
        CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs_{cloudtrail_table_name} (
            eventVersion STRING,
            userIdentity STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                invokedBy: STRING,
                accessKeyId: STRING,
                userName: STRING,
                sessionContext: STRUCT<
                    attributes: STRUCT<
                        mfaAuthenticated: STRING,
                        creationDate: STRING>,
                    sessionIssuer: STRUCT<
                        type: STRING,
                        principalId: STRING,
                        arn: STRING,
                        accountId: STRING,
                        userName: STRING>>>,
            eventTime STRING,
            eventSource STRING,
            eventName STRING,
            awsRegion STRING,
            sourceIpAddress STRING,
            userAgent STRING,
            errorCode STRING,
            errorMessage STRING,
            requestParameters STRING,
            responseElements STRING,
            additionalEventData STRING,
            requestId STRING,
            eventId STRING,
            resources ARRAY<STRUCT<
                arn: STRING,
                accountId: STRING,
                type: STRING>>,
            eventType STRING,
            apiVersion STRING,
            readOnly STRING,
            recipientAccountId STRING,
            serviceEventDetails STRING,
            sharedEventID STRING,
            vpcEndpointId STRING
        )
        COMMENT 'CloudTrail table for {cloudtrail_bucket_name} bucket'
        ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
        STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
        OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
        LOCATION 's3://{cloudtrail_bucket_name}/AWSLogs/{account_id}/CloudTrail/'
        TBLPROPERTIES ('classification'='cloudtrail');
        """.format(account_id=account_id, cloudtrail_bucket_name= trail_object.s3_bucket_name, cloudtrail_table_name=trail_object.get_converted_s3_bucket_name_to_table_name())

        athena_handler = AthenaHandler(trail_object.home_region)
        output_location = self.__config["athena"]["output_location"].format(account_id=self.__config["account"]["account_id"], region=trail_object.home_region)
        self.__logger.info("Creating logs tables to the selected trail")
        athena_handler.run_query(creating_default_database,
                                 None,
                                 output_location
                                 )
        athena_handler.run_query(cloudtrails_logs_create_table_query,
                                 self.__config["athena"]["database_name"],
                                 output_location
                                 )
