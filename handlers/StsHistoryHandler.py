from handlers.AthenaHandler import AthenaHandler
from handlers.ConfigHandler import ConfigHandler
from structures.StsToken import StsToken, EC2_ASIA_REFRESHED_MANUAL_FLAG, LIVE_REFRESHED_TOKEN_FLAG
import logging
from utilities.Boto3Utilities import instance_id_validator

# Query Constants
GET_ACCESS_TOKENS_FROM_STS_QUERY = """SELECT * FROM \"{0}\" WHERE useridentity.accesskeyid LIKE '%ASIA%' and requestparameters LIKE '%"roleArn"%' and responseelements LIKE '%"accessKeyId":"ASIA%' order by eventtime desc;"""
GET_ORIGIN_ACCESS_TOKENS_FROM_STS_QUERY =  """SELECT * FROM \"{0}\" WHERE useridentity.accesskeyid LIKE '%AKIA%' and requestparameters LIKE '%"roleArn"%' And responseelements LIKE '%"accessKeyId":"ASIA%' order by eventtime desc;"""
GET_LIVE_TEMPORARY_TOKENS_QUERY= """with temporary_tokens as (SELECT *, REPLACE(json_extract_scalar(responseelements, '$.credentials.expiration'), ',', '') AS ext FROM \"{0}\" WHERE responseelements LIKE '%"accessKeyId":"ASIA%' and requestparameters LIKE '%"roleArn"%' and eventTime > to_iso8601(current_timestamp - interval '36' hour) order by eventtime desc)
select * from temporary_tokens where date_parse(ext, '%b %e %Y %l:%i:%s %p')> date(current_timestamp)"""

# constants for extraction of keys
USER_IDENTITY_FILED = "useridentity"
ACCESS_KEY_ID_FILED = "accessKeyId"
# Constants for suspicious tokens
EC2_ASIA_REFRESHED_MANUAL = "Token generated for EC2 machine refreshed manually"
LIVE_REFRESHED_TOKEN = "This token is a refreshed token"
# ROOTS KEYS CONSTANTS
ROOT_AKIA_TOKENS_USED_FOR_REFRESH_STS = 0
REGULAR_AKIA_TOKENS = 1
ROOT_STS_TOKENS_USED_TO_REFRESH_STS = 2

class StsHistoryHandler(object):
    def __init__(self, cloudwatch_trail_object):
        config_handler = ConfigHandler.get_instance()
        config = config_handler.config
        self.__logger = logging.getLogger(__name__)
        self.cloudwatch_trail_object = cloudwatch_trail_object
        self.athena_handler = AthenaHandler(cloudwatch_trail_object.home_region)
        self.suspicious_tokens = []

        # Gets all the temporary (Role Access tokens) used to create other Access tokens
        self.__logger.info("[+] Searching for refreshed temporary tokens")
        self.tokens_created_by_temporary_token_athena_rows = self.athena_handler.fetchall_athena(
            GET_ACCESS_TOKENS_FROM_STS_QUERY.format(config["athena"]["table_name"]),
            config["athena"]["database_name"],
            config["athena"]["output_location"]
        )
        self.access_keys_to_check = self.access_keys_ids_dict_generator(self.tokens_created_by_temporary_token_athena_rows)

        # Pair nodes to their parents
        self.__match_parent_node_to_child(self.access_keys_to_check)

        # Gets all the AKIA (User Access tokens) used to create other Access tokens
        self.__logger.info(
            "[+] Searching after users that their keys used for creating temporary tokens")
        self.created_sts_tokens_from_main_access_keys_athena_rows = self.athena_handler.fetchall_athena(
            GET_ORIGIN_ACCESS_TOKENS_FROM_STS_QUERY.format(config["athena"]["table_name"]),
            config["athena"]["database_name"],
            config["athena"]["output_location"]
        )
        self.sts_persistence_root_temporary_keys_id_set = self.parse_athena_rows_sts_persistence_root_temporary_keys(self.access_keys_to_check)
        self.root_tokens = self.parse_athena_rows_akia_access_key_id_for_root_sts(self.created_sts_tokens_from_main_access_keys_athena_rows,
                                                                                  self.sts_persistence_root_temporary_keys_id_set)
        self.root_temporary_tokens = self.root_tokens[ROOT_STS_TOKENS_USED_TO_REFRESH_STS]

        # Get all the live temporary tokens in the account
        self.__logger.info(
            "[+] Searching after live temporary tokens under the AWS account")
        self.live_temporary_tokens_athena_rows = self.athena_handler.fetchall_athena(
            GET_LIVE_TEMPORARY_TOKENS_QUERY.format(config["athena"]["table_name"]),
            config["athena"]["database_name"],
            config["athena"]["output_location"]
        )
        self.live_temporary_tokens = self.parse_athena_rows_live_temporary_tokens(self.live_temporary_tokens_athena_rows)
        self.get_info_for_live_temporary_tokens()
        self.flag_suspicious_tokens()

    def flag_suspicious_tokens(self):
        self.__logger.info("[+] Examining the scraped tokens")
        self.__logger.info("Has there been a token refresh process in the account according to the trail bucket? - {status}".
                           format(status=(len(self.root_temporary_tokens) > 0)))
        # EC2 STS tokens which used for persistent
        ec2_refreshed_keys_counter = 0

        for root_token_key_id in self.sts_persistence_root_temporary_keys_id_set:
            for child_token in self.sts_persistence_root_temporary_keys_id_set[root_token_key_id]:
                principal = child_token.athena_row.data["useridentity"].object["principalid"].split(":")
                issuer_arn = child_token.athena_row.data["useridentity"].arn.split("/")
                if len(principal) == 2 and principal[1] == issuer_arn[-1] and child_token.source_ip_address != "ec2.amazonaws.com" and instance_id_validator(issuer_arn[-1]):
                    child_token.suspicious_token[EC2_ASIA_REFRESHED_MANUAL_FLAG] = True
                    child_token.set_suspicious_reason(EC2_ASIA_REFRESHED_MANUAL)
                    ec2_refreshed_keys_counter += 1
                    self.suspicious_tokens.append(child_token)
                    ec2_refreshed_keys_counter += self.flag_token_children(child_token, EC2_ASIA_REFRESHED_MANUAL)

        live_ec2_refreshed_keys_counter = 0
        for suspected_key in self.suspicious_tokens:
            if suspected_key.is_expired() is False and suspected_key.suspicious_token[EC2_ASIA_REFRESHED_MANUAL_FLAG] is True:
                live_ec2_refreshed_keys_counter += 1

        self.__logger.info("The number of refreshed tokens created from stolen EC2 access keys: {0}, while {1} out of them are live tokens".format(ec2_refreshed_keys_counter, live_ec2_refreshed_keys_counter))

        # STS tokens which used for persistent that origin from AKIA
        sts_refreshed_keys_counter = 0
        for live_temporary_token in self.live_temporary_tokens:
            if live_temporary_token.parent_node is not None:
                live_temporary_token.suspicious_token[LIVE_REFRESHED_TOKEN_FLAG] = True
                live_temporary_token.set_suspicious_reason(LIVE_REFRESHED_TOKEN)
                sts_refreshed_keys_counter += 1
                self.suspicious_tokens.append(live_temporary_token)
        self.__logger.info("The number of live refreshed tokens: {0}".format(
            sts_refreshed_keys_counter + live_ec2_refreshed_keys_counter))

    def flag_token_children(self, node, flag_reason):
        """
        :param node: token node
        :param flag_reason: string
        :return: the number of flagged tokens
        """
        counter = 0
        for child in node.children:
            child.suspicious_token[EC2_ASIA_REFRESHED_MANUAL_FLAG] = True
            child.set_suspicious_reason(flag_reason)
            counter += 1
            self.suspicious_tokens.append(child)
            counter += self.flag_token_children(child, flag_reason)
        return counter

    def parse_athena_rows_live_temporary_tokens(self, data):
        live_temporary_tokens = []
        for row in data:
            sts_row_token = StsToken(row)
            if sts_row_token.token in self.access_keys_to_check:
                sts_row_token = self.access_keys_to_check[sts_row_token.token]
            elif sts_row_token.parent_access_key_id is not None and sts_row_token.parent_access_key_id in self.access_keys_to_check:
                sts_row_token.parent_node = self.access_keys_to_check[sts_row_token.parent_access_key_id]
            if not sts_row_token.is_expired():
                live_temporary_tokens.append(sts_row_token)
        return live_temporary_tokens

    def parse_athena_rows_sts_persistence_root_temporary_keys(self, root_temporary_keys):
        sts_persistence_root_keys_ids = {}
        for key in root_temporary_keys:
            if root_temporary_keys[key].parent_node is None:
                root_key = root_temporary_keys[key].parent_access_key_id
                if root_key in sts_persistence_root_keys_ids:
                    sts_persistence_root_keys_ids[root_key].append(root_temporary_keys[key])
                else:
                    sts_persistence_root_keys_ids[root_key] = [root_temporary_keys[key]]
        return sts_persistence_root_keys_ids

    def __set_root_token_to_node_children(self, node, root_key=None):
        if root_key is None:
            root_key = node
        for child_node in node.children:
            child_node.root_parent_node = root_key
            self.__set_root_token_to_node_children(child_node, root_key)

    def parse_athena_rows_akia_access_key_id_for_root_sts(self, data, root_persistence_temporary_keys):
        akia_tokens = {}
        root_temporary_tokens = {}
        regular_sts_token_created_by_akia = {}
        temp_root_persistence_temporary_keys = root_persistence_temporary_keys.copy()
        for row in data:
            response_elements = row.data["responseelements"]
            credentials_object = response_elements["credentials"]
            sts_row_token = StsToken(row)
            if credentials_object["accessKeyId"] in temp_root_persistence_temporary_keys:
                # Set to all of the token child the root temporary token
                # Saving every root temporary tokens to a key value format
                root_temporary_tokens[credentials_object["accessKeyId"]] = sts_row_token
                temp_root_persistence_temporary_keys.pop(credentials_object["accessKeyId"])
                for key in self.access_keys_to_check:
                    if self.access_keys_to_check[key].parent_access_key_id == sts_row_token.token:
                        sts_row_token.children.append(self.access_keys_to_check[key])
                        self.access_keys_to_check[key].parent_node = sts_row_token
                self.__set_root_token_to_node_children(sts_row_token)
                if sts_row_token.parent_access_key_id in akia_tokens:
                    akia_tokens[sts_row_token.parent_access_key_id].append(sts_row_token)
                else:
                    akia_tokens[sts_row_token.parent_access_key_id] = [sts_row_token]
            else:
                if sts_row_token.parent_access_key_id in regular_sts_token_created_by_akia:
                    regular_sts_token_created_by_akia[sts_row_token.parent_access_key_id].append(sts_row_token)
                else:
                    regular_sts_token_created_by_akia[sts_row_token.parent_access_key_id] = [sts_row_token]

        if len(temp_root_persistence_temporary_keys) > 0:
            self.__logger.warning(
                "Couldn't find the Akia token used to generate the following temporary tokens: {0}".format(", ".join(temp_root_persistence_temporary_keys.keys())))

        return akia_tokens, regular_sts_token_created_by_akia, root_temporary_tokens

    def is_temporary_token_used_for_persistence(self, athena_row):
        if "IAMUser" == athena_row.data[USER_IDENTITY_FILED].type:
            return False
        if "ASIA" not in athena_row.data[USER_IDENTITY_FILED].access_key_id:
            return False
        return True

    def __match_parent_node_to_child(self, dict_of_nodes):
        iterate_token_nodes = dict_of_nodes
        for sts_token_access_key_id in iterate_token_nodes:
            parent_access_key_id = iterate_token_nodes[sts_token_access_key_id].parent_access_key_id
            for sts_token_to_check in iterate_token_nodes:
                suspected_parent = iterate_token_nodes[sts_token_to_check]
                if parent_access_key_id == suspected_parent.token:
                    suspected_parent.children.append(iterate_token_nodes[sts_token_access_key_id])
                    iterate_token_nodes[sts_token_access_key_id].parent_node = suspected_parent
                    iterate_token_nodes[sts_token_access_key_id].parent_access_key_id = suspected_parent.token
                    break

    def access_keys_ids_dict_generator(self, data):
        access_key_dict = {}
        for row in data:
            if self.is_temporary_token_used_for_persistence(row):
                sts_token = StsToken(row)
                if sts_token.token not in access_key_dict.keys():
                    access_key_dict[sts_token.token] = sts_token

        return access_key_dict

    def get_info_for_live_temporary_tokens(self):
        if len(self.live_temporary_tokens) > 0:
            self.__logger.info("[+] Getting the permissions for the live tokens")
            for live_temporary_token in self.live_temporary_tokens:
                live_temporary_token.fetch_token_permissions()
        else:
            self.__logger.info("No live temporary token has found")
