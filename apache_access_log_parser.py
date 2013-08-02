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

