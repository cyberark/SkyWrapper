# Constants for user identity filed parsing
OBJECT_START = '{'
OBJECT_END = '}'
FILED_DELIMITER = ','
FILED_VALUE_NAME = ','

def parse_user_identity_filed(user_identity):
    return __parse_user_identity_filed(user_identity, 0, {})[0]

def __parse_user_identity_filed(user_identity, index, result_object):
    filed_name = ""
    value_filed = ""
    if user_identity[index] == OBJECT_START:
        index += 1
        while user_identity[index] != OBJECT_END:
            filed_name = ""
            value_filed = ""
            while user_identity[index] != "=":
                filed_name += user_identity[index]
                index += 1
            # Skip the "=" sign to get to the value
            index += 1
            while user_identity[index] != "," and user_identity[index] != OBJECT_END:
                if user_identity[index] == OBJECT_START:
                    value_filed, index = __parse_user_identity_filed(user_identity, index, {})
                    break
                value_filed += user_identity[index]
                if user_identity[index] != OBJECT_END:
                    index += 1
            result_object[filed_name] = value_filed
            if user_identity[index] == ",":
                # Skip to the next key-value element
                index += 2
    return result_object, index