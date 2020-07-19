# CrowdClient

CrowdClient is a Python library for interacting with CrowdStrike Falcon's REST API.

## Usage

```python
from crowdclient import CrowdClient

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

## License
[Gnu GPLv3](https://choosealicense.com/licenses/gpl-3.0/)