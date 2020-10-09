import requests
from requests.auth import HTTPBasicAuth
from requests_toolbelt import MultipartEncoder
from .helpers import *
from typing import Union, List


class CrowdClient:

    def __init__(self, client_id: str,
                 client_secret: str,
                 base_url: str = 'https://api.crowdstrike.com',
                 verify_cert: bool = True):

        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = requests.session()
        self.session.verify = verify_cert

    def authenticate(self):
        """
        Authenticate to CrowdStrike API using id and secret supplied on instantiation
        :return:
        """

        payload = {'client_id': self.client_id,
                   'client_secret': self.client_secret}

        response = self.session.post(self.base_url + '/oauth2/token', data=payload)

        if response.status_code == 201:
            headers = {'Authorization': f'Bearer {response.json()["access_token"]}',
                       'token_type': 'bearer',
                       'Content-Type': 'application/json'}

            self.session.headers = headers

            return self

        else:
            print("Authentication failed - Check ID and Secret and try again.")

    def revoke(self) -> bool:
        """
        Revoke an issued Bearer token.
        :return:
        """

        token = self.session.headers['Authorization'].split()[-1]  # Split out the token from our headers

        payload = {'token': token}

        response = self.session.post(self.base_url + '/oauth2/revoke', data=payload,
                                     auth=HTTPBasicAuth(self.client_id, self.client_secret))

        return response.status_code == 200

    def get_detections(self, limit: int = 9999, offset: int = 0, sort: str = 'last_behavior|desc',
                       status: str = 'new', severity: str = 'All') -> List:
        """
        Get a list of detection ID's based on the parameters supplied.
        :param limit: Defaults to 9999 detections.
        :param offset: First detection to return (0 is the latest detection).
        :param sort: Defaults to last behavior associated with the detection in descending order.
        :param status: Defaults to new detections - Can be new, in_progress, true_positive, false_positive, or ignored.
        :param severity: Specify Critical, High, Medium, Low, or Info - Defaults to all of the above.
        :return:
        """

        params = {'limit': limit, 'offset': offset, 'sort': sort}

        if severity != 'All':
            params['filter'] = f"status:'{status}'+max_severity_displayname:['{severity}']"
        else:
            params['filter'] = f"status:'{status}'+" \
                               f"max_severity_displayname:['Critical', 'High', 'Medium', 'Low', 'Info']"

        response = self.session.get(self.base_url + '/detects/queries/detects/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def get_detection_details(self, detection_ids: List, detailed: bool = False) -> List:
        """
        Retrieves details for a list of supplied detection ID's (IE, from the get_detections method).
        :param detection_ids: Supply a list of detection ID's - Or even just one, as long as it's in list format.
        :param detailed: Formatted a bit more nicely - Off by default.
        :return:
        """

        payload = {'ids': detection_ids}

        response = self.session.post(self.base_url + '/detects/entities/summaries/GET/v1', json=payload)

        if response.status_code == 200:
            detections = response.json()['resources']
        else:
            return []

        if detailed:
            detection_details = {}

            for detection in detections:
                timestamp = detection['behaviors'][0]['timestamp']
                behaviors = detection['behaviors'][0]

                detection_details[f"{timestamp} - {detection['max_severity_displayname']}: "
                                  f"{behaviors['tactic']} - {behaviors['technique']} - "
                                  f"{detection['device']['hostname']}"] = detection
            return [detection_details]

        else:
            return detections

    def update_detection(self, detection_id: str, status: str = '', assignment: str = '', comment: str = '') -> bool:
        """
        Modify the state, assignee, and/or visibility of a detection.
        :param detection_id: Supply a detection ID in the form of a string.
        :param status: Can be new, in_progress, true_positive, false_positive, or ignored.
        :param assignment: Must be a user ID (UUID) for a user in your CrowdStrike account.
        :param comment: Can add a comment to a detection in the form of a string.
        :return:
        """
        payload = {'ids': [detection_id]}

        if status:
            payload['status'] = status
        if assignment:
            payload['assigned_to_uuid'] = assignment
        if comment:
            payload['comment'] = comment

        response = self.session.patch(self.base_url + '/detects/entities/detects/v2', json=payload)

        return response.status_code == 200

    def get_incidents(self, sort: str = 'modified_timestamp.desc', status: str = 'new', fine_score: str = '10') -> List:
        """
        Retrieve a list of incidents in your environment based on supplied criteria.
        :param sort: Defaults to descending order based on last modified.
        :param status: Can be 'new', 'in_progress', 'closed', or 'reopened'.
        :param fine_score: Severity (>=) can be anywhere from 0-100 (100 would have a severity of 10.0).
        :return:
        """

        status_dict = {
            'new': '20',
            'in_progress': '30',
            'closed': '40',
            'reopened': '25'
        }

        params = {'sort': sort,
                  'filter': f'status:{status_dict[status.lower()]}+fine_score:>={fine_score}'}

        response = self.session.get(self.base_url + '/incidents/queries/incidents/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def get_incident_details(self, incident_ids: List, detailed: bool = False) -> Union[Union[list, dict]]:
        """
        Get details for one or more incidents by supplying their ID's.
        :param incident_ids: Incident ID's in the form of a list - Can get these with get_incidents().
        :param detailed: Optional... Retrieve these details in the form of a detailed dict.
        :return:
        """
        payload = {'ids': incident_ids}

        response = self.session.post(self.base_url + '/incidents/entities/incidents/GET/v1', json=payload)

        if response.status_code == 200:
            incidents = response.json()['resources']
        else:
            return []

        if detailed:
            incident_details = {}

            for incident in incidents:
                if 'name' in incident.keys():
                    incident_details[incident['name']] = incident
                else:
                    incident_details[incident['incident_id']] = incident

            return incident_details

        else:
            return incidents

    def update_incident(self, incident_ids: List, status: str = '', tags: str = '') -> bool:
        """
        Update one or more incidents by supplying their ID's.
        :param incident_ids: Specify which incidents you'd like to modify in the form of a list.
        :param status: Can be 'New', 'In Progress', 'Closed', or 'Reopened'.
        :param tags: Specify which tags you'd like to apply to the specified incident(s).
        :return:
        """

        status_dict = {'New': '20',
                       'In Progress': '30',
                       'Closed': '40',
                       'Reopened': '25'}

        action_parameters = []

        if status:
            action_parameters.append({'name': 'update_status',
                                      'value': status_dict[status]})
        if tags:
            action_parameters.append({'name': 'add_tag',
                                      'value': tags})

        payload = {'action_parameters': action_parameters,
                   'ids': incident_ids}

        response = self.session.post(self.base_url + '/incidents/entities/incident-actions/v1', json=payload)

        return response.status_code == 200

    def get_behaviors(self, criteria: str, criteria_type: str, limit: int = 500) -> dict:
        """
        Get a list of behavior ID's based on supplied criteria.
        :param criteria_type: IE, local_ip, hostname, etc.
        :param criteria: Largely dependent on 'criteria_type' (IE, local_ip:'192.168.0.3')
        :param limit: Defaults to 500 to capture as many records as possible.
        :return:
        """

        params = {
            'filter': f"{criteria_type}:'{criteria}'",
            'limit': limit
        }

        response = self.session.get(self.base_url + '/incidents/queries/behaviors/v1', jparams=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def get_behavior_details(self, behavior_ids: List) -> dict:
        """
        Supply a list of behavior ID's to retrieve details on each.
        :param behavior_ids: List of behavior ID's - Can be retrieved with the get_behaviors method.
        :return:
        """

        payload = {'ids': behavior_ids}

        response = self.session.post(self.base_url + '/incidents/entities/behaviors/GET/v1', json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def indicator_upload(self, indicator_list: List, indicator_type: str, description: str = '') -> Union[str, List]:
        """
        Create a new indicator/series of indicators in your account.
        :param indicator_list: Should all be of the same category (IE, ipv4, domain, md5, etc)
        :param indicator_type: Valid types include ipv4, ipv6, domain, md5, or sha256
        :param description: Optionally supply your own description in the form of a string.
        :return:
        """

        payload = payload_assemble(indicator_list, description, indicator_type)

        for item in chunker(payload):
            response = self.session.post(self.base_url + '/indicators/entities/iocs/v1', json=item)

            if response.status_code == 200:
                if not response.json()['errors']:
                    return "[*] Indicators successfully uploaded to CrowdStrike!\n"
                else:
                    return response.json()['errors']

    def indicator_info(self, indicator: str, indicator_type: str, policy: str = 'detect') -> List:
        """
        View information related to a specific indicator.
        :param indicator: Specify an indicator for which you'd like details.
        :param indicator_type: May be ipv4, ipv6, domain, md5, or sha256.
        :param policy: May be 'detect' or 'none'.
        :return:
        """

        params = {'type': indicator_type,
                  'value': indicator}

        if policy:
            params['policy'] = policy

        response = self.session.get(self.base_url + '/indicators/entities/iocs/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def indicator_host_search(self, indicator: str, indicator_type: str) -> dict:
        """
        Search for hosts that have displayed some activity related to a specified indicator.
        :param indicator: String representation of the indicator.
        :param indicator_type: May be ipv4, ipv6, domain, md5, or sha256.
        :return:
        """

        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.get(self.base_url + '/indicators/queries/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()

    def indicator_host_count(self, indicator: str, indicator_type: str) -> int:
        """
        View the # of hosts that have exhibited some activity with regard to a specific IOC.
        :param indicator: String representation fo the indicator.
        :param indicator_type: May be ipv4, ipv6, domain, md5, or sha256.
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.get(self.base_url + '/indicators/aggregates/devices-count/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources'][0]['device_count']

    def indicator_remove(self, indicator: str, indicator_type) -> bool:
        """
        Delete an IOC from your customer account by specifying the indicator and its type.
        :param indicator: String representation fo the indicator.
        :param indicator_type: May be ipv4, ipv6, domain, md5, or sha256.
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.delete(self.base_url + '/indicators/entities/iocs/v1', params=params)

        return response.status_code == 200

    def indicator_list(self, indicator_type: str):
        """
        View custom IOC's in your customer account by specifying the type you'd like listed.
        :param indicator_type: May be ipv4, ipv6, domain, md5, or sha256.
        :return:
        """

        params = {'types': indicator_type}

        response = self.session.get(self.base_url + '/indicators/queries/iocs/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_search(self, criteria: str = None, criteria_type: str = None,
                    raw_filter: str = None, limit: int = 5000) -> List:
        """
        Search for hosts in your environment - Returns a list of agent ID's.
        :param criteria_type: IE, local_ip, hostname, etc.
        :param criteria: Largely dependent on 'criteria_type' (IE, local_ip:'192.168.0.3')
        :param raw_filter: Optional - Supply your own pre-built filter. If blank, defaults to criteria/criteria_type.
        :param limit: Defaults to 5000 to capture as many records as possible.
        :return:
        """

        if criteria and criteria_type:
            params = {'filter': f"{criteria_type}:'{criteria}'"}
        elif raw_filter:
            params = {'filter': raw_filter}
        else:
            params = {}

        if limit:
            params['limit'] = limit

        response = self.session.get(self.base_url + '/devices/queries/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_details(self, host_ids: List) -> List:
        """
        Retrieve host details using a list of agent ID's (can be retrieved with host_search method).
        :param host_ids: IE, ['123456789aeiou', '987654321uoiea'] - Can be retrieved with host_search.
        :return:
        """
        params = {'ids': host_ids}

        response = self.session.get(self.base_url + '/devices/entities/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_action(self, host_ids: List, action: str) -> bool:
        """
        Contain, lift containment, delete, or restore a host using supplied host ID's.
        :param host_ids: IE, ['123456789aeiou', '987654321uoiea'] - Can be retrieved with host_search.
        :param action: Action to take - May be contain, lift_containment, hide_host, or unhide_host.
        :return:
        """
        payload = {'ids': host_ids}
        params = {'action_name': action}

        response = self.session.post(self.base_url + '/devices/entities/devices-actions/v2',
                                     json=payload, params=params)

        return response.status_code == 202


class RTRClient:

    def __init__(self, client_id: str,
                 client_secret: str,
                 base_url: str = 'https://api.crowdstrike.com',
                 verify_cert: bool = True):

        self.auth_url = base_url
        self.base_url = base_url + '/real-time-response'
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = requests.session()
        self.session.verify = verify_cert

    def authenticate(self):
        """
        Authenticate to CrowdStrike API using id and secret supplied on instantiation.
        :return:
        """
        payload = {'client_id': self.client_id,
                   'client_secret': self.client_secret}

        response = self.session.post(self.auth_url + '/oauth2/token', data=payload)

        if response.status_code == 201:
            headers = {'Authorization': f'Bearer {response.json()["access_token"]}',
                       'token_type': 'bearer',
                       'Content-Type': 'application/json'}

            self.session.headers = headers

            return self

    def revoke(self) -> bool:
        """
        Revoke an issued Bearer token.
        :return:
        """

        token = self.session.headers['Authorization'].split()[-1]  # Split out the token from our headers

        payload = {'token': token}

        response = self.session.post(self.auth_url + '/oauth2/revoke', data=payload,
                                     auth=HTTPBasicAuth(self.client_id, self.client_secret))

        return response.status_code == 200

    def host_search(self, criteria: str = None, criteria_type: str = None,
                    raw_filter: str = None, limit: int = 5000) -> List:
        """
        Search for hosts in your environment - Returns a list of agent ID's.
        :param criteria_type: IE, local_ip, hostname, etc.
        :param criteria: Largely dependent on 'criteria_type' (IE, local_ip:'192.168.0.3')
        :param raw_filter: Optional - Supply your own pre-built filter. If blank, defaults to criteria/criteria_type.
        :param limit: Defaults to 5000 to capture as many records as possible.
        :return:
        """

        if criteria and criteria_type:
            params = {'filter': f"{criteria_type}:'{criteria}'"}
        elif raw_filter:
            params = {'filter': raw_filter}
        else:
            params = {}

        if limit:
            params['limit'] = limit

        response = self.session.get(self.auth_url + '/devices/queries/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def batch_init(self, host_ids: List, timeout: str = '30', timeout_duration: str = '30s') -> str:
        """
        Initialize an RTR session across multiple hosts.
        :param host_ids: List of agent ID's belonging to one or more hosts.
        :param timeout: Timeout in seconds - Default is 30 seconds, maximum is 600 (10 minutes).
        :param timeout_duration: How long to wait for request to complete - Valid units: ns, us, ms, s, m, h - Max 10m.
        :return:
        """

        params = {'timeout': timeout,
                  'timeout_duration': timeout_duration}

        payload = {'host_ids': host_ids}

        response = self.session.post(self.base_url + '/combined/batch-init-session/v1',
                                     params=params, json=payload)

        if response.status_code == 201:
            return response.json()['batch_id']
        else:
            return f'Error:\n{response.text}'

    def batch_refresh(self, batch_id: str, hosts_to_remove: List = None) -> bool:
        """
        Refresh an active batch session - Batch sessions expire after 10 minutes unless refresh.
        :param batch_id: Batch ID belonging to the session you'd like to refresh.
        :param hosts_to_remove: Optional - Specify which hosts you'd like to remove from the current session.
        :return:
        """
        payload = {
            'batch_id': batch_id
        }

        if hosts_to_remove:
            payload['hosts_to_remove'] = hosts_to_remove

        response = self.session.post(self.base_url + '/combined/batch-refresh-session/v1', json=payload)

        return response.status_code == 201

    def batch_cmd(self, batch_id: str, command: str, command_string: str, timeout: int = 30,
                  timeout_duration: str = '10m', optional_hosts: List = None) -> bool:
        """
        Executes an RTR read-only command across all hosts mapped to a batch ID.
        :param batch_id: Batch ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, env, eventlog, filehash, getsid, help, history, ipconfig, ls,
                        mount, netstat, ps, reg query.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :param timeout: How long to wait for the request in seconds - Default is 30, max is 10 minutes (600).
        :param timeout_duration: How long to wait for the request in duration syntax. Valid units: ns, us, ms, s, m, h.
        :param optional_hosts: List of a subset of hosts to run a command on.
        :return:
        """

        payload = {
            'base_command': command,
            'batch_id': batch_id,
            'command_string': command_string
        }

        if optional_hosts:
            payload['optional_hosts'] = optional_hosts

        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }

        response = self.session.post(self.base_url + '/combined/batch-command/v1', json=payload, params=params)

        return response.status_code == 201

    def batch_active_cmd(self, batch_id: str, command: str, command_string: str, timeout: int = 30,
                         timeout_duration: str = '10m', optional_hosts: List = None) -> bool:
        """
        Executes an RTR active-responder command across all hosts mapped to a batch ID.
        :param batch_id: Batch ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, cp, encrypt, env, eventlog, filehash, get, getsid, help,
                        history, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg query, reg set,
                        reg delete, reg load, reg unload, restart, rm, runscript, shutdown, unmap, xmemdump, zip.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :param timeout: How long to wait for the request in seconds - Default is 30, max is 10 minutes (600).
        :param timeout_duration: How long to wait for the request in duration syntax. Valid units: ns, us, ms, s, m, h.
        :param optional_hosts: List of a subset of hosts to run a command on.
        :return:
        """

        payload = {
            'base_command': command,
            'batch_id': batch_id,
            'command_string': command_string
        }

        if optional_hosts:
            payload['optional_hosts'] = optional_hosts

        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }

        response = self.session.post(self.base_url + '/combined/batch-active-responder-command/v1',
                                     json=payload, params=params)

        return response.status_code == 201

    def batch_admin_cmd(self, batch_id: str, command: str, command_string: str, timeout: int = 30,
                        timeout_duration: str = '10m', optional_hosts: List = None) -> bool:
        """
        Executes an RTR admin command across all hosts mapped to a batch ID.
        :param batch_id: Batch ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, cp, encrypt, env, eventlog, filehash, get, getsid, help,
                        history, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg query,
                        reg set, reg delete, reg load, reg unload, restart, rm, run, runscript, shutdown, unmap,
                        xmemdump, zip.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :param timeout: How long to wait for the request in seconds - Default is 30, max is 10 minutes (600).
        :param timeout_duration: How long to wait for the request in duration syntax. Valid units: ns, us, ms, s, m, h.
        :param optional_hosts: List of a subset of hosts to run a command on.
        :return:
        """

        payload = {
            'base_command': command,
            'batch_id': batch_id,
            'command_string': command_string
        }

        if optional_hosts:
            payload['optional_hosts'] = optional_hosts

        params = {
            'timeout': timeout,
            'timeout_duration': timeout_duration
        }

        response = self.session.post(self.base_url + '/combined/batch-admin-command/v1', json=payload, params=params)

        return response.status_code == 201

    def session_init(self, host_id: str, origin: str) -> str:
        """
        Initialize an RTR session on a single host.
        :param host_id: Agent ID on which the session will be initiated.
        :param origin:
        :return:
        """

        payload = {
            'device_id': host_id,
            'origin': origin,
        }

        response = self.session.post(self.base_url + '/entities/sessions/v1', json=payload)

        if response.status_code == 201:
            return response.json()['resources'][0]['session_id']
        else:
            return response.text

    def session_refresh(self, host_id: str) -> bool:
        """
        Refresh an active single-host session by specifying its host ID.
        :param host_id: Specify which host by supplying its agent ID as a string.
        :return:
        """
        payload = {
            'device_id': host_id
        }

        response = self.sesion.post(self.base_url + '/entities/refresh-session/v1', json=payload)

        return response.status_code == 201

    def delete_session(self, session_id: str) -> bool:
        """
        Delete an existing single-host session.
        :param session_id: Session ID supplied as a string.
        :return:
        """
        params = {'session_Id': session_id}

        response = self.session.delete(self.base_url + '/entities/sessions/v1', params=params)

        return response.status_code == 204

    def session_list(self) -> dict:
        """
        View session ID's currently initiated in your customer account.
        :return:
        """

        response = self.session.get(self.base_url + '/queries/sessions/v1')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error': response.text}

    def session_meta(self, session_ids: List) -> dict:
        """
        Retrieve metadata related to established sessions.
        :param session_ids: Specify sessions on which you'd like info in the form of a list of strings.
        :return:
        """

        payload = {'ids': session_ids}

        response = self.session.post(self.base_url + '/entities/sessions/GET/v1', json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def session_cmd(self, session_id: str, command: str, command_string: str) -> bool:
        """
        Executes an RTR read-only command across all hosts mapped to a batch ID.
        :param session_id: Session ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, env, eventlog, filehash, getsid, help, history, ipconfig, ls,
                        mount, netstat, ps, reg query.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :return:
        """

        payload = {
            'base_command': command,
            'command_string': command_string,
            'id': session_id
        }

        response = self.session.post(self.base_url + '/entities/command/v1', json=payload)

        return response.status_code == 201

    def session_active_cmd(self, session_id: str, command: str, command_string: str) -> bool:
        """
        Executes an RTR active-responder command across all hosts mapped to a batch ID.
        :param session_id: Session ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, cp, encrypt, env, eventlog, filehash, get, getsid, help,
                        history, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, reg query, reg set,
                        reg delete, reg load, reg unload, restart, rm, runscript, shutdown, unmap, xmemdump, zip.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :return:
        """

        payload = {
            'base_command': command,
            'session_id': session_id,
            'command_string': command_string
        }

        response = self.session.post(self.base_url + '/entities/active-responder-command/v1', json=payload)

        return response.status_code == 201

    def session_admin_cmd(self, session_id: str, command: str, command_string: str) -> bool:
        """
        Executes an RTR read-only command across all hosts mapped to a batch ID.
        :param session_id: Session ID retrieved from the batch_init() method.
        :param command: Valid commands: cat, cd, clear, cp, encrypt, env, eventlog, filehash, get, getsid, help,
                        history, ipconfig, kill, ls, map, memdump, mkdir, mount, mv, netstat, ps, put, reg query,
                        reg set, reg delete, reg load, reg unload, restart, rm, run, runscript, shutdown, unmap,
                        xmemdump, zip.
        :param command_string: Full command string for the command - IE, 'cd C:\\some_directory'.
        :return:
        """

        payload = {
            'base_command': command,
            'session_id': session_id,
            'command_string': command_string
        }

        response = self.session.post(self.base_url + '/entities/admin-command/v1', json=payload)

        return response.status_code == 201

    def session_runscript(self, session_id: str, script_name: str = None, raw_cmd: str = None) -> bool:
        """
        Execute either a pre-staged PowerShell script or supply a raw PowerShell command. Added this specifically
        because the format for the runscript command can be tricky and is a pain to debug.
        :param session_id: Session ID retrieved from the batch_init() method.
        :param script_name: Name of a pre-staged script.
        :param raw_cmd: Valid PowerShell command to execute across hosts in batch session.
        :return:
        """

        if script_name:
            cmd_string = f'runscript -CloudFile="{script_name}"'
        elif raw_cmd:
            cmd_string = f'runscript -Raw=```{raw_cmd}```'
        else:
            print("Error! Must supply either a valid script name or a raw PowerShell command to execute.")
            return False

        payload = {
            'base_command': 'runscript',
            'session_id': session_id,
            'command_string': cmd_string
        }

        response = self.session.post(self.base_url + '/entities/admin-command/v1', json=payload)

        return response.status_code == 201

    def session_file_list(self, session_id: str) -> dict:
        """
        Get a list of files for the specified session.
        :param session_id: Supply the session ID as a string.
        :return:
        """

        params = {
            'session_id': session_id
        }

        response = self.session.get(self.base_url + '/entities/file/v1', params=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def session_file_contents(self, session_id: str, sha256: str, filename: str = None) -> dict:
        """
        Get RTR extracted file contents for the specified session and SHA256
        :param session_id: Supply the desired session ID as a string.
        :param sha256: The extracted sha256 for which to retrieve information.
        :param filename: Optional - Filename to use for the archive name.
        :return:
        """

        params = {
            'session_id': session_id,
            'sha256': sha256
        }

        if filename:
            params['filename'] = filename

        response = self.session.get(self.base_url + '/entities/extracted-file-contents/v1', params=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def session_file_del(self, file_id: str, session_id: str) -> bool:
        """
        Delete an RTR session file.
        :param file_id: File ID belonging to the file to be deleted.
        :param session_id: Pertinent session ID (supplied as a string).
        :return:
        """

        params = {
            'ids': file_id,
            'session_id': session_id
        }

        response = self.session.delete(self.base_url + '/entities/file/v1', params=params)

        return response.status_code == 204

    def get_scripts(self) -> List:
        """
        Get a list of custom-script ID's available for the user for the 'runscript' command.
        :return:
        """

        response = self.session.get(self.base_url + '/queries/scripts/v1')

        if response.status_code == 200:
            return response.json()['resources']

    def script_details(self, script_ids: List) -> dict:
        """
        Get the details for custom-scripts based on the ID's provided.
        :param script_ids: Supply a list of strings corresponding to existing script ID's.
        :return:
        """

        params = {'ids': script_ids}

        response = self.session.get(self.base_url + '/entities/scripts/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text, 'Full Response': response}

    def script_upload(self, script_path: str, script_name: str, description: str,
                      permission_type: str, platform: str = 'Windows') -> bool:
        """
        Upload a new custom-script to use for the RTR 'runscript' command'.
        :param script_path: Custom-script file to upload (Should be a .ps1).
        :param script_name: Filename to use for the uploaded script.
        :param description: Description to use for the uploaded file.
        :param permission_type: Can be one of three values:
                                - private: usable by only the user who uploaded the script.
                                - group: usable by all RTR Admins.
                                - public: usable by all active-responders and RTR admins.
        :param platform: Platforms for the file - Currently supports windows, mac.
        :return:
        """

        payload = MultipartEncoder(
            fields={'file': (script_name, open(script_path, 'rb')),
                    'description': description,
                    'permission_type': permission_type,
                    'platform': platform}
        )

        self.session.headers['Content-Type'] = payload.content_type

        response = self.session.post(self.base_url + '/entities/scripts/v1', data=payload)

        return response.status_code == 200

    def script_replace(self, script_id: str, script_path: str, script_name: str, description: str,
                       permission_type: str, platform: List = None) -> bool:
        """
        Upload a new custom-script to use for the RTR 'runscript' command'.
        :param script_id: Script ID to update.
        :param script_path: Custom-script file to upload (Should be a .ps1).
        :param script_name: Filename to use for the uploaded script.
        :param description: Description to use for the uploaded file.
        :param permission_type: Can be one of three values:
                                - private: usable by only the user who uploaded the script.
                                - group: usable by all RTR Admins.
                                - public: usable by all active-responders and RTR admins.
        :param platform: Platforms for the file - Currently supports windows, mac.
        :return:
        """

        payload = MultipartEncoder(
            fields={'file': (script_name, open(script_path, 'rb')),
                    'id': script_id,
                    'description': description,
                    'permission_type': permission_type,
                    'platform': platform}
        )

        self.session.headers['Content-Type'] = payload.content_type

        response = self.session.patch(self.base_url + '/entities/scripts/v1', data=payload)

        return response.status_code == 200

    def script_delete(self, script_id) -> bool:
        """
        Delete a custom-script based on the ID given.
        :param script_id: Supply script ID as a string.
        :return:
        """
        params = {'ids': script_id}

        response = self.session.delete(self.base_url + '/entities/scripts/v1', params=params)

        return response.status_code == 200

    def batch_runscript(self, batch_id: str, script_name: str = None, raw_cmd: str = None,
                        optional_hosts: List = None) -> bool:
        """
        Execute either a pre-staged PowerShell script or supply a raw PowerShell command. Added this specifically
        because the format for the runscript command can be tricky and is a pain to debug.
        :param batch_id: Batch ID retrieved from the batch_init() method.
        :param script_name: Name of a pre-staged script.
        :param raw_cmd: Valid PowerShell command to execute across hosts in batch session.
        :param optional_hosts: Any hosts you'd like excluded from command execution.
        :return:
        """
        true = True

        if script_name:
            cmd_string = f'runscript -CloudFile="{script_name}"'
        elif raw_cmd:
            cmd_string = f'runscript -Raw=```{raw_cmd}```'
        else:
            print("Error! Must supply either a valid script name or a raw PowerShell command to execute.")
            return False

        payload = {
            'base_command': 'runscript',
            'batch_id': batch_id,
            'command_string': cmd_string,
            'persist_all': true
        }

        if optional_hosts:
            payload['optional_hosts'] = optional_hosts

        response = self.session.post(self.base_url + '/combined/batch-admin-command/v1', json=payload)

        return response.status_code == 201

    def file_list(self) -> dict:
        """
        Get a list of put-file ID's that are available to the user for the 'put' command.
        :return:
        """

        response = self.session.get(self.base_url + '/queries/put-files/v1')

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def file_details(self, file_ids: List) -> dict:
        """
        Get details on put-files based on the ID's provided.
        :param file_ids: List of file ID's on which to get details (list of strings).
        :return:
        """

        params = {'ids': file_ids}

        response = self.session.get(self.base_url + '/entities/put-files/v1', params=params)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def file_upload(self, filename: str, file_path: str, description: str, comment: str = '') -> bool:
        """
        Upload a new put-file to use for the RTR 'put' command.
        :param filename: Filename by which the file will be identified.
        :param file_path: Put-file to upload.
        :param description: Description for the file.
        :param comment: Optional - Supply a comment for the audit log.
        :return:
        """

        payload = MultipartEncoder(
            fields={'file': (filename, open(file_path, 'rb')),
                    'description': description,
                    'comment': comment}
        )

        self.session.headers['Content-Type'] = payload.content_type

        response = self.session.post(self.base_url + '/entities/put-files/v1', data=payload)

        return response.status_code == 200

    def file_delete(self, file_id: str) -> bool:
        """
        File ID for the file to be deleted.
        :param file_id: File ID as a string.
        :return:
        """

        params = {'ids': file_id}

        response = self.session.delete(self.base_url + '/entities/put-files/v1', params=params)

        return response.status_code == 200
