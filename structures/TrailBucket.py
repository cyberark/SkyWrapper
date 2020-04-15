class TrailBucket(object):
    def __init__(self, trail_name,
                 include_global_service_events,
                 is_organization_trail,
                 trail_arn,
                 log_file_validation_enabled,
                 is_multi_region_trail,
                 has_custom_events_selectors,
                 s3_bucket_name,
                 home_region
                 ):
        self.trail_name = trail_name
        self.include_global_service_events = include_global_service_events
        self.is_organization_trail = is_organization_trail
        self.trail_arn = trail_arn
        self.log_file_validation_enabled = log_file_validation_enabled
        self.is_multi_region_trail = is_multi_region_trail
        self.has_custom_events_selectors = has_custom_events_selectors
        self.s3_bucket_name = s3_bucket_name
        self.home_region = home_region

    def get_converted_s3_bucket_name_to_table_name(self):
        return self.s3_bucket_name.replace("-", "_").replace(".", "")

    def get_athena_result_bucket(self):
        account_id = self.__config["account_id"]
        return "s3://aws-athena-query-results-{account_id}-{region}/".format(account_id=account_id, region=self.home_region)

    def get_bucket_url(self):
        return "s3://{s3_bucket_name}/".format(s3_bucket_name=self.s3_bucket_name)


