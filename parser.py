import shlex

def tokenize(file_name):
    access_log = open(file_name)
    log_entries = tuple(access_log.read().splitlines())
    print "%d log entries" % len(log_entries)
    v2_download_log_entries = [entry for entry in log_entries if "GET /downloads/" in entry]
    print "%d version 2 download log entries" % len(v2_download_log_entries)
