from utilities.Boto3Utilities import client_session_creator
import logging
from handlers.ConfigHandler import ConfigHandler
from exceptions.SingletonClassException import SingletonClassException
from policyuniverse.policy import Policy

ATTACHED_POLICIES = "AttachedPolicies"
INLINE_POLICIES = "InlinePolicies"

class RolePermissionsHandler(object):
    __instance = None
    @staticmethod
    def get_instance():
        if RolePermissionsHandler.__instance is None:
            RolePermissionsHandler()
        return RolePermissionsHandler.__instance

    def __init__(self):
        if RolePermissionsHandler.__instance is not None:
            raise SingletonClassException("This class is a singleton!")
        else:
            self.__config = ConfigHandler.get_instance().get_config()
            self.__logger = logging.getLogger(__name__)
            self.__roles = {}
            self.__attached_policies = {}
            RolePermissionsHandler.__instance = self

    def get_role_policy_permissions(self, role):
        if role not in self.__roles:
            try:
                iam_client = client_session_creator('iam')

                self.__logger.debug("Getting the permissions attached to the role: {0}".format(role))

                attached_role_policies = iam_client.list_attached_role_policies(RoleName=role)
                role_policies = iam_client.list_role_policies(RoleName=role)


                attached_role_policies_list = attached_role_policies['AttachedPolicies']
                policy_permissions = {
                    INLINE_POLICIES:{},
                    ATTACHED_POLICIES:{}
                }
                for attached_policy in attached_role_policies_list:
                    attached_role_arn = attached_policy["PolicyArn"]
                    if attached_role_arn not in self.__attached_policies:
                        current_policy_version = iam_client.get_policy(PolicyArn=attached_role_arn)['Policy']['DefaultVersionId']
                        policy_permissions_statement_list = iam_client.get_policy_version(PolicyArn=attached_role_arn, VersionId=current_policy_version)['PolicyVersion']['Document']
                        policy_object = Policy(policy_permissions_statement_list)
                        policy_permissions_statement_list = policy_object.statements
                        self.__attached_policies[attached_role_arn] = policy_permissions_statement_list
                    policy_permissions[ATTACHED_POLICIES][attached_role_arn] = self.__attached_policies[attached_role_arn]

                role_policies_list = role_policies["PolicyNames"]
                for policy in role_policies_list:
                    policy_data = iam_client.get_role_policy(RoleName=role, PolicyName=policy)
                    policy_object = Policy(policy_data["PolicyDocument"])
                    policy_statement_list = policy_object.statements
                    policy_permissions[INLINE_POLICIES][policy] = policy_statement_list
            except Exception as e:
                policy_permissions = {
                    INLINE_POLICIES: {},
                    ATTACHED_POLICIES: {}
                }
            self.__roles[role] = policy_permissions
        return self.__roles[role]




