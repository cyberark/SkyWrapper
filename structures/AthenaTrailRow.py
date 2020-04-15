from structures.UserIdentity import UserIdentity
import json

COLUMN_PARSERS = {"useridentity": UserIdentity}

class AthenaTrailRow(object):
    def __init__(self, raw_row):
        self.raw_row = raw_row
        self.data = {}
        self.__parse_raw_row()

    def __parse_raw_row(self):
        for column_name in self.raw_row:
            column_data = self.raw_row[column_name]
            if column_name in COLUMN_PARSERS:
                column_data = COLUMN_PARSERS[column_name](column_data)
            else:
                try:
                    column_data = json.loads(column_data)
                except ValueError:
                    pass
                except TypeError:
                    pass
            self.data[column_name] = column_data

    def __repr__(self):
        return str(self.data)


