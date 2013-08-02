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
    cleaned_access_log_data = access_log_data.replace('[', '"').replace(']', '"')
    return [ shlex.split(entry) for entry in cleaned_access_log_data.splitlines() ]

def get_tree(log_entry_list):
    log_entry_dict_list = [dict(zip(access_log_field_names, entry)) for entry in log_entry_list]
    log_entry_dict_list.sort(lambda x, y: cmp(x['client-ip'], y['client-ip']))
    return log_entry_dict_list

def parse(access_log_data):
    return get_tree(tokenize(access_log_data))

def filter_by_property_value(log_entry_dict_list, property_key, property_value):
    return [entry for entry in log_entry_dict_list if entry[property_key] == property_value]

def filter_by_client_IP(log_entry_dict_list, client_IP):
    return filter_by_property_value(log_entry_dict_list, 'client-ip', client_IP)

def filter_by_GET_URL(log_entry_dict_list, url):
    request_line = 'GET %s HTTP/1.1' % url
    return filter_by_property_value(log_entry_dict_list, 'request-line', request_line)

def get_all_property_values(log_entry_dict_list, property_key):
    return [entry[property_key] for entry in log_entry_dict_list]

def get_all_property_values_with_count(log_entry_dict_list, property_key):
    property_value_list = get_all_property_values(log_entry_dict_list, property_key)
    property_value_set = set(property_value_list)
    property_value_list_with_count = []
    for value in property_value_set:
        property_value_list_with_count.append((value, property_value_list.count(value)))
    property_value_list_with_count.sort(lambda x, y: cmp(x[1], y[1]))
    return property_value_list_with_count

def get_all_client_IPs_with_count(log_entry_dict_list):
    return get_all_property_values_with_count(log_entry_dict_list, 'client-ip')

