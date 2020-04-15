import xlsxwriter
from handlers.ConfigHandler import ConfigHandler
from utilities.FileUtilities import get_project_root
from utilities.StsTreeStructureUtilities import count_node_children_and_live_nodes
import os
from datetime import datetime
from structures.StsToken import MANUAL_TOKEN_SOURCE, EC2_TOKEN_SOURCE, LAMBDA_TOKEN_SOURCE, OTHER_TOKEN_SOURCE
from utilities.ExcelUtilities import *
from operator import methodcaller, attrgetter
from utilities.SkyWrapperConstants import SKYWRAPPER_INTRO
from handlers.PrivilegedRolesScanHandler import PrivilegedRolesScanHandler

TOKENS_SHEET_COLUMNS = [
                            "Token",
                            "Suspected Key",
                            "Suspicion Description",
                            "Token Age",
                            "Token Root Source",
                            "Role Name",
                            "Role Session Name",
                            "Permissions Summary",
                            "Token TTL",
                            "Event Time",
                            "Expiration Time",
                            "Event Name",
                            "Aws Region",
                            "Source Ip Address",
                            "User Agent",
                            "Event Type",
                            "Event Source",
                            "Request Id",
                            "Event Id",
                            "Role Arn",
                            "Detailed Role Permissions"
]

AKIA_SHEET_COLUMNS = [
                        "User",
                        "Akia Token",
                        "Suspicion Description"
]

class ExportStsHistoryHandler(object):
    def __init__(self, sts_history_object):
        self.__sts_history_object = sts_history_object
        self.worksheets_columns_max_size = {}
        self.__inserted_index = 1

    def write_row(self, worksheet, row_index, col_index, data):
        if worksheet.name not in self.worksheets_columns_max_size.keys():
            self.worksheets_columns_max_size[worksheet.name] = {}
        if col_index not in self.worksheets_columns_max_size[worksheet.name].keys() or\
                self.worksheets_columns_max_size[worksheet.name][col_index] < len(str(data)):
            self.worksheets_columns_max_size[worksheet.name][col_index] = len(str(data))
        worksheet.write(row_index, col_index, data)

    def set_columns_headers(self, worksheet, columns):
        for column_index, column_name in enumerate(columns, start=0):
            self.write_row(worksheet, 0, column_index, column_name)

    def __add_token_to_tokens_sheet(self, row_index, token, tokens_sheet):
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Token"), token.token)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Suspected Key"), token.is_suspicious_token())
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Suspicion Description"), token.suspicious_reason)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Token Age"), token.get_living_days())
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Token Root Source"), token.get_token_source_string())
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Role Name"), token.role_name)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Role Session Name"), token.role_session_name)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Permissions Summary"), token.get_token_privileged_information())
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Token TTL"), "{0} minutes".format((token.expiration_time - datetime.utcnow()).seconds // 60))
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Event Time"), token.event_time.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Expiration Time"), token.expiration_time.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Event Name"), token.event_name)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Aws Region"), token.aws_region)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Source Ip Address"), token.source_ip_address)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("User Agent"), token.user_agent)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Event Type"), token.event_type)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Event Source"), token.event_source)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Request Id"), token.request_id)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Event Id"), token.event_id)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Role Arn"), token.role_arn)
        self.write_row(tokens_sheet, row_index, TOKENS_SHEET_COLUMNS.index("Detailed Role Permissions"), token.get_token_privileged_information(detailed=True))

    def export_results(self):
        config_handler = ConfigHandler.get_instance()
        config = config_handler.config
        project_path = get_project_root()
        excel_output_file_location = os.path.join(project_path, config["output"]["excel_output_file"].format(trail=self.__sts_history_object.cloudwatch_trail_object.trail_name, account_id=config["account"]["account_id"], date=config["run_timestamp"]))
        summary_file_location = os.path.join(project_path, config["output"]["summary_output_file"].format(
            trail=self.__sts_history_object.cloudwatch_trail_object.trail_name,
            account_id=config["account"]["account_id"], date=config["run_timestamp"]))
        self.export_data_to_excel(excel_output_file_location)
        self.create_summary_file(summary_file_location)

    def create_summary_file(self, summary_file_location):
        summary_data_file = SKYWRAPPER_INTRO
        summary_data_file += "\nSkyWrapper run summary:\n"
        data_template = "\t{data}\n"

        privileged_tokens = []
        live_ec2_tokens = []
        live_lambda_tokens = []
        live_manual_tokens = []
        live_other_tokens = []
        oldest_token = None

        for live_token in self.__sts_history_object.live_temporary_tokens:
            if oldest_token is None or oldest_token.living_days < live_token.living_days:
                oldest_token = live_token
            token_privileges = live_token.get_token_privileged_information()

            if token_privileges != "":
                privileged_tokens.append(live_token)
            if EC2_TOKEN_SOURCE is live_token.token_source:
                live_ec2_tokens.append(live_token)
            elif LAMBDA_TOKEN_SOURCE is live_token.token_source:
                live_lambda_tokens.append(live_token)
            elif MANUAL_TOKEN_SOURCE is live_token.token_source:
                live_manual_tokens.append(live_token)
            else:
                live_other_tokens.append(live_token)

        if oldest_token is None:
            oldest_token_living_days = 0
        else:
            oldest_token_living_days = oldest_token.living_days

        privileged_roles_handler = PrivilegedRolesScanHandler()
        privileged_roles_handler.scan_for_privileged_roles()

        with open(summary_file_location, "w") as output_file:
            summary_data_file += data_template.format(data="Live temporary tokens found: " + str(len(self.__sts_history_object.live_temporary_tokens)))
            summary_data_file += data_template.format(
                data="The number of privileged tokens: " + str(len(privileged_tokens)))
            summary_data_file += data_template.format(data="The oldest token is live for {days_number} days".format(days_number=oldest_token_living_days))
            summary_data_file += data_template.format(data="The number of suspicious live temporary tokens discovered: " + str(len(self.__sts_history_object.suspicious_tokens)))
            summary_data_file += data_template.format(
                data="The number of live ec2 tokens: " + str(len(live_ec2_tokens)))
            summary_data_file += data_template.format(
                data="The number of live lambda tokens: " + str(len(live_lambda_tokens)))
            summary_data_file += data_template.format(
                data="The number of live manual tokens: " + str(len(live_manual_tokens)))
            summary_data_file += data_template.format(
                data="The number of other live tokens: " + str(len(live_other_tokens)))
            if len(privileged_tokens) > 0:
                summary_data_file += data_template.format(
                    data="")
                summary_data_file += data_template.format(
                    data="List of the found privileges tokens:")
                for privilege_token in privileged_tokens:
                    summary_data_file += data_template.format(
                        data="Privileged token: {token_key_id} | Privileges: {privileges} | Token source: {token_source}".format(token_key_id=privilege_token.token, privileges=privilege_token.get_token_privileged_information(), token_source=privilege_token.token_source))
            if len(privileged_roles_handler.privileged_roles) > 0:
                summary_data_file += data_template.format(
                    data="")
                summary_data_file += data_template.format(
                    data="List of the privilege roles:")
                for role in privileged_roles_handler.privileged_roles:
                    summary_data_file += data_template.format(
                        data="Role name: {role_name} | Role ARN: {role_arn}".format(
                            role_name=role["RoleName"],
                            role_arn=role["Arn"]))
            if len(privileged_roles_handler.refresh_privileged_roles) > 0:
                summary_data_file += data_template.format(
                    data="")
                summary_data_file += data_template.format(
                    data="List of the roles can be use for refreshing tokens:")
                for role in privileged_roles_handler.refresh_privileged_roles:
                    summary_data_file += data_template.format(
                        data="Role name: {role_name} | Role ARN: {role_arn}".format(
                            role_name=role["RoleName"],
                            role_arn=role["Arn"]))

            output_file.write(summary_data_file)

    def export_data_to_excel(self, excel_output_file_location):
        wb = xlsxwriter.Workbook(excel_output_file_location)
        live_temporary_tokens_sheet = wb.add_worksheet('Live temporary tokens')
        flagged_temporary_tokens_sheet = wb.add_worksheet('Suspected live temporary tokens')
        refresh_tokens_akia_sheet = wb.add_worksheet('Suspected permanent tokens')
        # Live temporary Tokens Sheet Columns
        self.set_columns_headers(live_temporary_tokens_sheet, TOKENS_SHEET_COLUMNS)

        # Flagged temporary Tokens Sheet Columns
        self.set_columns_headers(flagged_temporary_tokens_sheet, TOKENS_SHEET_COLUMNS)

        # User and Akia Tokens Sheet Columns q
        self.set_columns_headers(refresh_tokens_akia_sheet, AKIA_SHEET_COLUMNS)

        flagged_tokens_counter = 0

        live_temporary_tokens = sorted(self.__sts_history_object.live_temporary_tokens, key=methodcaller('number_of_suspicious_reasons'), reverse=True)
        live_temporary_tokens = sorted(live_temporary_tokens,key=attrgetter('living_days'), reverse=True)
        live_temporary_tokens = sorted(live_temporary_tokens,
                                       key=methodcaller('rate_of_privilege_token'), reverse=True)
        live_temporary_tokens = sorted(live_temporary_tokens, key=methodcaller('is_suspicious_token'), reverse=True)

        for row_index, live_token in enumerate(live_temporary_tokens, start=1):
            if live_token.is_suspicious_token():
                self.__add_token_to_tokens_sheet(flagged_tokens_counter + 1, live_token, flagged_temporary_tokens_sheet)
                flagged_tokens_counter += 1
            self.__add_token_to_tokens_sheet(row_index, live_token, live_temporary_tokens_sheet)

        flagged_temporary_tokens_sheet.autofilter(
            "A1:W{amount_of_tokens}".format(amount_of_tokens=len(live_temporary_tokens)))
        live_temporary_tokens_sheet.autofilter(
            "A1:W{amount_of_tokens}".format(amount_of_tokens=len(live_temporary_tokens)))

        akia_tokens = {}
        for persistence_token in self.__sts_history_object.root_temporary_tokens:
            akia_owner_user = self.__sts_history_object.root_temporary_tokens[persistence_token].user
            akia_key = self.__sts_history_object.root_temporary_tokens[persistence_token].parent_access_key_id
            count_results = count_node_children_and_live_nodes(
                self.__sts_history_object.root_temporary_tokens[persistence_token])

            if akia_key in akia_tokens:
                akia_tokens[akia_key]["number_of_child_tokens"] += count_results[0]
                akia_tokens[akia_key]["live_created_tokens"] += count_results[1]
                if self.__sts_history_object.root_temporary_tokens[persistence_token].role_arn is not None:
                    akia_tokens[akia_key]["role_arn_token"].add(
                        self.__sts_history_object.root_temporary_tokens[persistence_token].role_arn)
            else:
                roles_arn_set = set()
                if self.__sts_history_object.root_temporary_tokens[persistence_token].role_arn is not None:
                    roles_arn_set.add(self.__sts_history_object.root_temporary_tokens[persistence_token].role_arn)
                akia_tokens[akia_key] = {
                    "akia_owner_user": akia_owner_user,
                    "number_of_child_tokens": count_results[0],
                    "live_created_tokens": count_results[1],
                    "role_arn_token": roles_arn_set
                }

        for row_index, akia_key in enumerate(akia_tokens, start=1):
            self.write_row(refresh_tokens_akia_sheet, row_index, 0, akia_tokens[akia_key]["akia_owner_user"])
            self.write_row(refresh_tokens_akia_sheet, row_index, 1, akia_key)
            suspicion_reason = """This token created {number_of_child_tokens} tokens. \r\n{live_created_tokens} are live tokens. \r\nThe roles arn of the created tokens: \n{roles_arn}
                                """.format(number_of_child_tokens=akia_tokens[akia_key]["number_of_child_tokens"],
                                           live_created_tokens=akia_tokens[akia_key]["live_created_tokens"],
                                           roles_arn="\n".join(akia_tokens[akia_key]["role_arn_token"]))
            self.write_row(refresh_tokens_akia_sheet, row_index, 2, suspicion_reason)

        set_sheet_columns_sizes(live_temporary_tokens_sheet, self.worksheets_columns_max_size)
        set_sheet_columns_sizes(flagged_temporary_tokens_sheet, self.worksheets_columns_max_size)
        set_sheet_columns_sizes(refresh_tokens_akia_sheet, self.worksheets_columns_max_size)

        wb.close()

