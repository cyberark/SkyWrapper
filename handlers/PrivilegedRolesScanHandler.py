from utilities.Boto3Utilities import client_session_creator
from handlers.RolePermissionsHandler import RolePermissionsHandler
from parsers.PoliciesPermissionsParser import PoliciesPermissionsParser
from handlers.RolePermissionsHandler import ATTACHED_POLICIES, INLINE_POLICIES


class PrivilegedRolesScanHandler(object):
    def __init__(self):
        self._role_permission_handler = RolePermissionsHandler.get_instance()
        self.privileged_roles = []
        self.refresh_privileged_roles = []

    def scan_for_privileged_roles(self):
        """
        Scan for privileged roles in the account
        :return:
        """
        iam_client = client_session_creator('iam')
        role_list_response = None
        marker = None
        while (role_list_response is None or role_list_response['IsTruncated'] is True):
            if marker is None:
                role_list_response = iam_client.list_roles()
            else:
                role_list_response = iam_client.list_roles(Marker=marker)
            if "Roles" in role_list_response:
                roles_list = role_list_response
                for role in roles_list["Roles"]:
                    if self.__is_a_privileged_role(role):
                        self.privileged_roles.append(role)
                    if self.__is_role_can_be_use_for_persistence(role):
                        self.refresh_privileged_roles.append(role)


            if role_list_response['IsTruncated']:
                marker = role_list_response['Marker']

    def get_privileges_roles(self):
        return self.privileged_roles

    def get_refresh_privileges_roles(self):
        return self.refresh_privileged_roles

    def __is_a_privileged_role(self, role):
        role_permissions = self._role_permission_handler.get_role_policy_permissions(role["RoleName"])
        role_policies_permissions = role_permissions[INLINE_POLICIES].copy()
        role_policies_permissions.update(role_permissions[ATTACHED_POLICIES])
        policies_permission_parser = PoliciesPermissionsParser(role_policies_permissions)
        policies_permission_parser.parse()
        if len(policies_permission_parser.get_permissions_status()) > 0:
            return True
        return False

    def __is_role_can_be_use_for_persistence(self, role):
        role_permissions = self._role_permission_handler.get_role_policy_permissions(role["RoleName"])
        role_policies_permissions = role_permissions[INLINE_POLICIES].copy()
        role_policies_permissions.update(role_permissions[ATTACHED_POLICIES])
        policies_permission_parser = PoliciesPermissionsParser(role_policies_permissions)
        policies_permission_parser.parse()
        if policies_permission_parser.is_permission_allowed(["sts:AssumeRole", "sts:*"]):
            return True
        return False
