from utilities.Boto3Utilities import client_session_creator
import time
from structures.AthenaTrailRow import AthenaTrailRow
from exceptions.AthenaBadQueryException import AthenaBadQueryException
import logging
from handlers.ConfigHandler import ConfigHandler

# Query Result Fields
DATA_VALUE_TYPE = "VarCharValue"

class AthenaHandler(object):
    def __init__(self, athena_bucket_region):
        self.__config = ConfigHandler.get_instance().get_config()
        self.athena_client = client_session_creator('athena', region_name=athena_bucket_region)
        self.__logger = logging.getLogger(__name__)


    def run_query(self, query_string, database_name, output_location):
        # Code inspired by https://gist.github.com/schledererj/b2e2a800998d61af2bbdd1cd50e08b76
        if database_name is not None:
            query_id = self.athena_client.start_query_execution(
                QueryString=query_string,
                QueryExecutionContext={'Database': database_name},
                ResultConfiguration={'OutputLocation': output_location}
            )['QueryExecutionId']
        else:
            query_id = self.athena_client.start_query_execution(
                QueryString=query_string,
                ResultConfiguration={'OutputLocation': output_location}
            )['QueryExecutionId']

        self.__logger.debug("Running the following SQL query: {0}".format(query_string))
        self.__logger.info("Athena is running a query, it might take a while")

        query_status = None
        while query_status == 'QUEUED' or query_status == 'RUNNING' or query_status is None:
            query_status_data = self.athena_client.get_query_execution(QueryExecutionId=query_id)
            query_status = query_status_data['QueryExecution']['Status']['State']
            if query_status == 'FAILED' or query_status == 'CANCELLED':
                raise AthenaBadQueryException(
                    'Athena query with the string "{}" failed or was cancelled.\nReason: {}'.format(query_string,
                                                                                                    query_status_data[
                                                                                                        'QueryExecution'][
                                                                                                        'Status'][
                                                                                                        'StateChangeReason']))
            # In order to prevent spamming the athena's servers,
            # we create a time gap between each status request
            time.sleep(2)

        return query_id

    def fetchall_athena(self, query_string, database_name, output_location):
        # Code inspired by https://gist.github.com/schledererj/b2e2a800998d61af2bbdd1cd50e08b76
        query_id = self.run_query(query_string, database_name, output_location)
        self.__logger.info("Fetching the query result")

        results_paginator = self.athena_client.get_paginator('get_query_results')
        results_iter = results_paginator.paginate(
            QueryExecutionId=query_id,
            PaginationConfig={'PageSize': 1000}

        )
        results = []
        data_list = []
        for results_page in results_iter:
            for row in results_page['ResultSet']['Rows']:
                data_list.append(row['Data'])
        object_fields_descriptor = data_list[0]
        for datum in data_list[1:]:
            row = {}
            for column_id, column_data in enumerate(datum):
                column_name = object_fields_descriptor[column_id][DATA_VALUE_TYPE]
                if DATA_VALUE_TYPE in column_data:
                    row[column_name] = column_data[DATA_VALUE_TYPE]
                else:
                    row[column_name] = None
            results.append(AthenaTrailRow(row))

        self.__logger.info("Fetched {0} rows".format(len(results)))
        return results