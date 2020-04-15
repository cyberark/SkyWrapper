import boto3
from handlers.ConfigHandler import ConfigHandler
import re


def client_session_creator(client_name, **kwargs):
    """
        Creates client session based on the credentials the users entered in the config file
        or it goes to the default AWS credentials
    """
    config = ConfigHandler.get_instance().get_config()
    if "verify" in kwargs:
        overridden_verify_value = kwargs.pop("verify")
    if config["account"]["aws_access_key_id"] is not None and config["account"]["aws_access_key_id"] != "" \
            and config["account"]["aws_secret_access_key"] is not None and config["account"]["aws_secret_access_key"] != "":
        kwargs["aws_access_key_id"] = config["account"]["aws_access_key_id"]
        kwargs["aws_secret_access_key"] = config["account"]["aws_secret_access_key"]
    if config["account"]["aws_session_token"] is not None and config["account"]["aws_session_token"] != "":
        kwargs["aws_session_token"] = config["account"]["aws_session_token"]

    return boto3.client(client_name, verify=config["verify_https"], **kwargs)


def instance_id_validator(instance_string):
    if re.match("(^i-(\w{8}|\w{17})$)|(^mi-\w{17}$)]", instance_string):
        return True
    else:
        return False