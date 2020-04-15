import re

PRIVILEGED_STATEMENT_RULES = {
    "\*:\*": "Full AWS Account Admin",
    "^[A-Za-z0-9]+:\*$": "Full {service} Admin"
}

FIND_SERVICE_REGEX = "^([A-Za-z0-9]+)(?=:)"

RESOURCE_ARN_WITH_SERVICE_REGEX = "^arn:aws(-cn|):{service}:.+"

class PoliciesPermissionsParser(object):
    def __init__(self, policies):
        self.__policies = policies
        self.__permissions = {}
        self.__disallowed_permissions = {}
        self.__allowed_permissions = {}


    @staticmethod
    def __push_resource_permission(permissions_dict, statement):
        resources = statement.resources
        for action in statement.actions:
            action_service = re.findall(FIND_SERVICE_REGEX, action)
            if len(action_service) > 0:
                for resource in resources:
                    is_arn_service_resource = re.match(RESOURCE_ARN_WITH_SERVICE_REGEX.format(service=action_service[0]), resource)
                    if is_arn_service_resource or resource == "*":
                        if resource not in permissions_dict:
                            permissions_dict[resource] = []
                        permissions_dict[resource].append(action)

    def is_action_disallowed(self, deny_statement_rules, action_permission_rule):
        action_service_matches = re.findall(FIND_SERVICE_REGEX, action_permission_rule)
        if len(action_service_matches) > 0:
            action_service = action_service_matches[0]
            # Not matching permissions like ec2:list* - It doesn't support
            if action_service in deny_statement_rules and (action_permission_rule in deny_statement_rules[action_service]
                                                                  or action_service+":*" in deny_statement_rules[action_service]):
                return True
        return False

    def is_permission_allowed(self, permissions_name, permission_resource=None):
        if permissions_name is str:
            permissions_name = [permissions_name]
        if permission_resource is None:
            for permission_resource in self.__permissions.keys():
                for permission_name in permissions_name:
                    if permission_name in self.__permissions[permission_resource]:
                        return True
        else:
            if permission_resource in self.__permissions:
                for permission_name in permissions_name:
                    if permission_name in self.__permissions[permission_resource]:
                        return True
        return False

    def parse(self):
        for policy_arn, attached_policy_statement in self.__policies.items():
            for statement in attached_policy_statement:
                if statement.effect == "Deny":
                    self.__push_resource_permission(self.__disallowed_permissions, statement)
                elif statement.effect == "Allow":
                    # Goes to function which parse the permissions and the resources (Get a statement)
                    self.__push_resource_permission(self.__allowed_permissions, statement)
        for resource, actions in self.__allowed_permissions.items():
            for action in actions:
                if not self.is_action_disallowed(self.__disallowed_permissions, action):
                    if resource in self.__permissions:
                        self.__permissions[resource].add(action)
                    else:
                        self.__permissions[resource] = set()
                        self.__permissions[resource].add(action)

    def __statement_policy_privilege_parser(self, action_permission):
        """
        The function takes a action permission as an input and returns in a string any high privileged permissions it has
        """
        action_permission_overview = ""
        for rule in PRIVILEGED_STATEMENT_RULES:
            if re.search(rule, action_permission):
                service = re.findall(FIND_SERVICE_REGEX, action_permission)
                if len(service) > 0:
                    action_permission_overview = PRIVILEGED_STATEMENT_RULES[rule].format(service=service[0])
                else:
                    action_permission_overview = PRIVILEGED_STATEMENT_RULES[rule].format(service=action_permission)
                break

        return action_permission_overview

    def get_detailed_permissions_status(self):
        permissions_status = ""
        if 0 < len(self.__permissions.keys()):
            permissions_status += "Allowed permissions\r\n"
        for resource in self.__permissions.keys():
            permissions_status += "    {resource}:\r\n".format(resource=resource)
            for action_permission in self.__permissions[resource]:
                permissions_status += "        {action_permission}\n".format(action_permission=action_permission)
        if 0 < len(self.__disallowed_permissions):
            permissions_status += "Disallowed permissions:\r\n"
            for resource in self.__disallowed_permissions:
                permissions_status += "    {resource}:\r\n".format(resource=resource)
                for permission in self.__disallowed_permissions[resource]:
                    permissions_status += "        {permission}\n".format(permission=permission)
        return permissions_status

    def get_permissions_status(self):
        permissions_status = set()
        for resource in self.__permissions.keys():
            for action_permission in self.__permissions[resource]:
                policy_privilege_parser = self.__statement_policy_privilege_parser(action_permission)
                if policy_privilege_parser != "":
                    permissions_status.add(policy_privilege_parser)
        return ", ".join(permissions_status)