from utilities.Boto3Utilities import client_session_creator
from handlers.ConfigHandler import ConfigHandler

def get_account_id():
    config = ConfigHandler.get_instance().get_config()
    sts_client = client_session_creator('sts')
    aws_account_id = sts_client.get_caller_identity().get('Account')
    return aws_account_id