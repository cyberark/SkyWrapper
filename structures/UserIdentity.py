from parsers import UserIdentityParser

# User identity properties
USER_IDENTITY_TYPE = "type"
USER_IDENTITY_PRINCIPAL_ID = "principalid"
USER_IDENTITY_ARN = "arn"
USER_IDENTITY_ACCOUNT_ID = "accountid"
USER_IDENTITY_INVOKED_BY = "invokedby"
USER_IDENTITY_ACCESS_KEY_ID = "accesskeyid"
USER_IDENTITY_USERNAME = "username"
USER_IDENTITY_SESSION_CONTEXT = "sessioncontext"

class UserIdentity(object):
    def __init__(self, user_identity_data):
        self.user_identity_data = user_identity_data
        self.type = None
        self.principal_id = None
        self.arn = None
        self.account_id = None
        self.invoked_by = None
        self.access_key_id = None
        self.username = None
        self.session_context = None
        self.object = None
        self.__parse()

    def __parse(self):
        self.object = UserIdentityParser.parse_user_identity_filed(self.user_identity_data)
        self.type = self.object[USER_IDENTITY_TYPE]
        self.principal_id = self.object[USER_IDENTITY_PRINCIPAL_ID]
        self.arn = self.object[USER_IDENTITY_ARN]
        self.account_id = self.object[USER_IDENTITY_ACCOUNT_ID]
        self.invoked_by = self.object[USER_IDENTITY_INVOKED_BY]
        self.access_key_id = self.object[USER_IDENTITY_ACCESS_KEY_ID]
        self.username = self.object[USER_IDENTITY_USERNAME]
        self.session_context = self.object[USER_IDENTITY_SESSION_CONTEXT]

    def __repr__(self):
        return str(self.__dict__)