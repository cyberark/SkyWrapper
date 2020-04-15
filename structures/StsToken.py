from datetime import datetime
from datetime import date
from handlers.RolePermissionsHandler import RolePermissionsHandler
from handlers.RolePermissionsHandler import ATTACHED_POLICIES, INLINE_POLICIES
from parsers.PoliciesPermissionsParser import PoliciesPermissionsParser
import re

USER_IDENTITY_FILED = "useridentity"
# Suspicion Flags
EC2_ASIA_REFRESHED_MANUAL_FLAG = "EC2_ASIA_REFRESHED_MANUAL"
LIVE_REFRESHED_TOKEN_FLAG = "EC2_ASIA_REFRESHED_MANUAL"
# Token Source Constants
EC2_TOKEN_SOURCE = "EC2"
LAMBDA_TOKEN_SOURCE = "Lambda"
MANUAL_TOKEN_SOURCE = "Manual"
OTHER_TOKEN_SOURCE = "Other"


class StsToken(object):
    def __init__(self, athena_row=None):
        self.token = ""
        self.children = []
        self.athena_row = athena_row
        self.parent_access_key_id = None
        self.parent_node = None
        self.root_parent_node = None
        self.expiration_time = None
        self.expired = False
        self.event_name = None
        self.event_time = None
        self.user = None
        self.source_ip_address = None
        self.user_agent = None
        self.permissions = None
        self.aws_region = None
        self.request_id = None
        self.event_id = None
        self.event_type = None
        self.event_source = None
        self.role_permissions = None
        self.role_arn = None
        self.role_name = None
        self.role_session_name = None
        self.parent_token = None
        self.living_days = 0
        self.token_source = None
        self.suspicious_token = {
            "EC2_ASIA_REFRESHED_MANUAL": False,
            "LIVE_REFRESHED_TOKEN": False,
        }
        self.__suspicious_reason = []

        if athena_row is not None:
            self.__parse()

    def get_suspicious_reason(self):
        return ", ".join(self.__suspicious_reason)

    def set_suspicious_reason(self, val):
        if val not in self.__suspicious_reason:
            self.__suspicious_reason.append(val)

    def get_root_parent_node(self, return_also_assumed=True):
        """
        Returns the parent node and handles cases which the parent node not assain to the local variable
        In case the token created after our root token scan the STSToken instance won't have token root key reference.
        Because of that we need to re assign the root token key to the current STSToken instance
        """
        if self.root_parent_node is None and self.parent_node is not None:
            root_token_found = False
            parent_token_instance = self.parent_node
            root_token_instance = None
            while not root_token_found:
                if parent_token_instance.root_parent_node is not None:
                    root_token_instance = parent_token_instance.root_parent_node
                    root_token_found = True
                    break
                if parent_token_instance.parent_access_key_id is None or parent_token_instance.parent_node is None:
                    # Finish going up in the reference child-parent tree
                    # The root parent not found and We can't assume that the top node is for sure the Root token
                    # which created the current token
                    if return_also_assumed:
                        root_token_instance = parent_token_instance
                    break
                parent_token_instance = parent_token_instance.parent_node
            self.root_parent_node = root_token_instance
        return self.root_parent_node

    suspicious_reason = property(get_suspicious_reason)

    def __parse(self):
        response_elements = self.athena_row.data["responseelements"]
        request_parameters = self.athena_row.data["requestparameters"]
        credentials_object = response_elements["credentials"]
        self.event_name = self.athena_row.data["eventname"]
        self.event_time = datetime.strptime(self.athena_row.data["eventtime"], "%Y-%m-%dT%H:%M:%SZ")
        if self.event_name == "AssumeRole":
            self.role_arn = request_parameters["roleArn"]
            self.role_name = self.role_arn.split("/")[-1]
            self.role_session_name = self.athena_row.data["requestparameters"]["roleSessionName"]
            if self.athena_row.data["sourceipaddress"] == "ec2.amazonaws.com":
                self.user = self.role_session_name
        if self.athena_row.data["useridentity"].type == "IAMUser" or self.athena_row.data["useridentity"].type == "Root":
            self.user = self.athena_row.data["useridentity"].username
        self.token = credentials_object["accessKeyId"]
        self.parent_access_key_id = self.athena_row.data[USER_IDENTITY_FILED].access_key_id
        self.expiration_time = datetime.strptime(credentials_object["expiration"].replace(",", ""), '%b %d %Y %I:%M:%S %p')
        self.expired = self.expiration_time < datetime.utcnow()
        self.source_ip_address = self.athena_row.data["sourceipaddress"]
        self.user_agent = self.athena_row.data["useragent"]
        if "ec2.amazonaws.com" == self.source_ip_address:
            self.token_source = EC2_TOKEN_SOURCE
        elif "lambda.amazonaws.com" == self.source_ip_address:
            self.token_source = LAMBDA_TOKEN_SOURCE
        elif re.match(".+\.amazonaws\.com$", self.source_ip_address):
            aws_service = re.findall("^(.*?)\.amazonaws\.com$", self.source_ip_address)
            self.token_source = aws_service[0] if len(aws_service) > 0 else OTHER_TOKEN_SOURCE
        elif "amazonaws.com" not in self.source_ip_address:
            self.token_source = MANUAL_TOKEN_SOURCE
        else:
            self.token_source = OTHER_TOKEN_SOURCE
        self.aws_region = self.athena_row.data["awsregion"]
        self.request_id = self.athena_row.data["requestid"]
        self.event_id = self.athena_row.data["eventid"]
        self.event_type = self.athena_row.data["eventtype"]
        self.event_source = self.athena_row.data["eventsource"]

    def get_token_source_string(self):
        token_source_string = ""
        if self.token_source == EC2_TOKEN_SOURCE:
            token_source_string = "EC2: {ec2_machine_id}".format(ec2_machine_id=self.role_session_name)
        elif self.token_source == LAMBDA_TOKEN_SOURCE:
            token_source_string = "Lambda: {lambda_name}".format(lambda_name=self.role_session_name)
        elif self.suspicious_token[EC2_ASIA_REFRESHED_MANUAL_FLAG] is True:
            root_parent_node = self.get_root_parent_node()
            if root_parent_node is None:
                # In case the current token is the root token, then the root_parent_node points to None.
                # Therefore, we set the root_parent_token to point on self.
                root_parent_node = self
            principal = root_parent_node.athena_row.data["useridentity"].object["principalid"].split(":")
            ec2_machine_id = "N/A" if len(principal) != 2 else principal[1]
            token_source_string = "EC2: {ec2_machine_id}".format(ec2_machine_id=ec2_machine_id)
        elif self.token_source == MANUAL_TOKEN_SOURCE:
            root_parent_node = self.get_root_parent_node()
            if root_parent_node is None and self.user is not None and self.user != "N/A" and "AKIA" in self.parent_access_key_id:
                user_access_key_id = self.parent_access_key_id
            elif root_parent_node is not None and root_parent_node.parent_access_key_id is not None and "AKIA" in root_parent_node.parent_access_key_id :
                user_access_key_id = root_parent_node.parent_access_key_id
            else:
                user_access_key_id = "N/A"
            token_source_string = "User: {user_name} User's Akia: {user_access_key_id}".format(
                user_name=self.get_user_or_ec2_name(), user_access_key_id=user_access_key_id)
        elif self.token_source is OTHER_TOKEN_SOURCE:
            token_source_string = "Other/Unknown"
        elif self.token_source is not None:
            token_source_string = self.token_source
        return token_source_string

    def get_user_or_ec2_name(self):

        if self.user is None:
            parent_node = self.get_root_parent_node()
            if parent_node is not None and parent_node.user is not None:
                    self.user = parent_node.user
            else:
                # Couldn't find the user which created the token or the token didn't created by a user (most likely by some service)
                self.user = "N/A"
        return self.user

    def get_living_days(self):
        root_parent_node = self.get_root_parent_node()
        if root_parent_node is not None:
            return (date.today() - self.get_root_parent_node().event_time.date()).days
        else:
            return 0

    def fetch_token_permissions(self):
        if self.role_name is not None:
            role_permissions_handler = RolePermissionsHandler.get_instance()
            self.role_permissions = role_permissions_handler.get_role_policy_permissions(self.role_name)


    def get_token_privileged_information(self, detailed=False):
        """
        The function parses the permissions that token has,
        then it returns if the token has "Admin" access to any of aws services and which service.
        The function doesn't check the condition part in the statement..
        :return:
        """
        # For now we only supporting AssumeRole event for permissions parsing
        if self.event_name != "AssumeRole":
            return ""
        token_permissions_policies = self.get_token_permissions()
        token_policies_permissions = token_permissions_policies[INLINE_POLICIES].copy()
        token_policies_permissions.update(token_permissions_policies[ATTACHED_POLICIES])
        policies_permission_parser = PoliciesPermissionsParser(token_policies_permissions)
        policies_permission_parser.parse()
        if not detailed:
            return policies_permission_parser.get_permissions_status()
        else:
            return policies_permission_parser.get_detailed_permissions_status()

    def get_token_permissions(self):
        if self.role_permissions is None:
            self.fetch_token_permissions()
        return self.role_permissions

    def is_suspicious_token(self):
        for suspicion_reason in self.suspicious_token:
            if self.suspicious_token[suspicion_reason]:
                return True
        return False

    def number_of_suspicious_reasons(self):
        return len(self.__suspicious_reason)

    def rate_of_privilege_token(self):
        rate = 0
        privilege_token_string = self.get_token_privileged_information()
        if "AWS Account" in privilege_token_string:
            # If the token has full admin access set to high number for setting this token high in the sort process
            rate = 10000
        privileges = privilege_token_string.split(",")
        # It won't add point to non privileged tokens
        if privileges != [""]:
            rate += len(privileges)
        return rate

    def is_expired(self):
        return self.expiration_time < datetime.utcnow()

    def __repr__(self):
        return str(self.__dict__)



















