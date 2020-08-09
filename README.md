# CrowdClient

CrowdClient is a Python library for interacting with CrowdStrike Falcon's REST API.

## Installation
```python
pip install crowdclient
```

## Usage

### General Use
```python
from CrowdClient.crowdclient import CrowdClient

# Instantiate your client
falcon_client = CrowdClient(<client_id>, <client_secret>)

# Authenticate to retrieve and store an authentication token for subsequent requests
falcon_client.authenticate()

# Get current detections (defaults to new detections only of all severities sorted newest -> oldest)
# Returns a list of all ID's matching above criteria
detections = falcon_client.get_detections()

# Get the number of hosts in your environment exhibiting activity related to a specified indicator
host_count = falcon_client.indicator_host_count('8.8.8.8', 'ipv4')
```
### Real-Time Response
```python
from CrowdClient.crowdclient import RTRClient

# Instantiate your client and authenticate in one line - Also works for the CrowdClient class
rtr_client = RTRClient(<client_id>, <client_secret>).authenticate()

# Initiate a batch session for multiple hosts
batch_id = rtr_client.batch_init(['hostid1', 'hostid2', 'hostid3'])

# Issue an RTR Admin command using the established session - Exclude a host if you'd like
rtr_client.batch_admin_cmd(batch_id, command='ls', command_string='ls C:\Users\', optional_hosts=['hostid3'])

# View the script ID's available for the user to use with the 'runscript' command
script_ids = rtr_client.get_scripts()

# Get the details for said scripts
script_details = rtr_client.script_details(script_ids)
```


## License
[Gnu GPLv3](https://choosealicense.com/licenses/gpl-3.0/)
