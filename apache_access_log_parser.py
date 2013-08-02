import shlex

access_log_field_names = [
    "client-ip",
    "ident",
    "username",
    "time",
    "request-line",
    "status-code",
    "size",
    "referrer",
    "agent"
]

def tokenize(access_log_data):
    'Returns a list of strings for each access log entry'
    cleaned_access_log_data = access_log_data.replace('[', '"').replace(']', '"')
    return [ shlex.split(entry) for entry in cleaned_access_log_data.splitlines() ]

def get_tree(log_entry_list):
    """
    Returns a list of dictionaries each representing individual log entries
    """
    log_entry_dict_list = [dict(zip(access_log_field_names, entry)) for entry in log_entry_list]
    log_entry_dict_list.sort(lambda x, y: cmp(x['client-ip'], y['client-ip']))
    return log_entry_dict_list

def parse(access_log_data):
    """
    Returns a list of dictionaries each representing individual log entries
    given the contents of an access log.
    """
    return get_tree(tokenize(access_log_data))

def filter_by_property_value(access_log_data, access_log_property, value):
    """
    Returns a list of dictionaries each representing individual log entries
    filtered by the value of a given property.
    
    Possible properties are:
    
    "client-ip", "ident", username", "time", "request-line", "status-code",
    "size", "referrer" and "agent"

    """
    return [entry for entry in parse(access_log_data) if entry[access_log_property] == value]

def filter_by_client_ip(access_log_data, client_ip):
    return filter_by_property_value(access_log_data, 'client-ip', client_ip)

def get_all_property_values(access_log_data, property_key):
    """
    Get all values of a given property of log entries given the property key.
    """
    return [entry[property_key] for entry in parse(access_log_data)]
