Apache Access Log Parser
------------------------


## Intro

This library parses apache access log data, returning it as a list of
dictionaries for each entry.

## Usage

```python
import apache_log_parser

access_log_data = open('access.log')
print apache_log_parser.parse(access_log_data)[0]
```

## License

MIT License
&copy; Okal Otieno 2013
