from handlers.StsHistoryHandler import StsHistoryHandler, ROOT_AKIA_TOKENS_USED_FOR_REFRESH_STS
from handlers.ExportStsHistoryHandler import ExportStsHistoryHandler
from utilities.AwsAccountMetadataUtilities import get_account_id
from utilities.StsTreeStructureUtilities import print_root_access_key_sts_tree
from handlers.ConfigHandler import ConfigHandler
from handlers.CloudTrailHandler import CloudTrailHandler
from exceptions.ZeroBucketsFoundException import ZeroBucketsFoundException
from utilities.ArgParseUtilities import str2bool
from utilities.FileUtilities import get_project_root
import traceback
import argparse
import logging
import os
import time
from utilities.SkyWrapperConstants import SKYWRAPPER_INTRO

def logger_setup():
    config = ConfigHandler.get_instance().get_config()
    logging.root.setLevel(logging.INFO)
    formatter = logging.basicConfig(format='%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    fh = logging.FileHandler(
        os.path.join(get_project_root(), "run_log_account_{0}-{1}.log".format(config["account"]["account_id"], config["run_timestamp"])))
    logging.root.addHandler(fh)
    for handler in logging.root.handlers:
        handler.setFormatter(formatter)


def get_user_cloudtrail_bucket(logger):
    cloudtrail_handler = CloudTrailHandler()
    account_cloudtrails = cloudtrail_handler.get_account_cloud_trails()

    if len(account_cloudtrails) == 0:
        raise ZeroBucketsFoundException("No cloudtrail buckets found!\nFor runing this script you must to have at least one bucket trail")
    logger.info("The CloudTrail's trails in your account:")
    for index, cloudtrail in enumerate(account_cloudtrails):
        logger.info("{index}. Trail name: {cloudtail_name} Trail's S3 Bucket name: {s3_bucket_name}".format(index=index+1, cloudtail_name=cloudtrail.trail_name, s3_bucket_name=cloudtrail.s3_bucket_name))

    user_cloudtrail_bucket_choice = None
    while user_cloudtrail_bucket_choice is None:
        try:
            user_index_input = int(input("Enter the bucket number for the script to run on: ")) - 1
            if user_index_input > len(account_cloudtrails) - 1 or user_index_input < 0:
                # Invalid input - raising ValueError exception
                raise ValueError()
            else:
                user_cloudtrail_bucket_choice = account_cloudtrails[user_index_input]
        except ValueError:
            logger.warning("Invalid bucket number")

    logger.info("[+] Validating CloudTrail table for the chosen trail")
    cloudtrail_handler.is_cloudtrail_logs_table_exists(user_cloudtrail_bucket_choice)

    return user_cloudtrail_bucket_choice


def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--export-results", "-er", type=str2bool, default=True,
                            required=False)
        parser.add_argument("--print-sts-refresh-tree", required=False, type=str2bool,
                            default=False)
        options = parser.parse_args()

        # Settings configuration
        config = ConfigHandler.get_instance().get_config()
        run_timestamp = int(time.time())
        account_id = get_account_id()
        config["account"]["account_id"] = account_id
        config["run_timestamp"] = run_timestamp
        logger_setup()
        logger = logging.getLogger("Main")
        logger.info(SKYWRAPPER_INTRO)
        # Get the user's CloudTrail Bucket
        user_cloudtrail_bucket = get_user_cloudtrail_bucket(logger)

        # Continue the settings configuration
        config["athena"]["table_name"] = config["athena"]["table_name"].format(table_name=user_cloudtrail_bucket.get_converted_s3_bucket_name_to_table_name())
        config["athena"]["output_location"] = config["athena"]["output_location"].format(account_id=account_id, region=user_cloudtrail_bucket.home_region)
        logger.info("[+] Getting the temporary tokens history")

        # Main program logic
        sts_history = StsHistoryHandler(user_cloudtrail_bucket)

        # Export results options
        if options.print_sts_refresh_tree:
            print_root_access_key_sts_tree(sts_history.root_tokens[ROOT_AKIA_TOKENS_USED_FOR_REFRESH_STS])

        if options.export_results:
            export_handler = ExportStsHistoryHandler(sts_history)
            export_handler.export_results()

    except Exception as e:
        logger = logging.getLogger("Main")
        logger.warning("SkyWrapper failed to run - Exception was raised")
        logger.warning("Exception details: {0}".format(e.args[0]))
        if "Unable to verify/create output bucket" in e.args[0]:
            logger.warning("Couldn't access the trail bucket. It might be insufficient permissions issue.")
        logger.warning(traceback.format_exc())


if __name__ == "__main__":
    main()
