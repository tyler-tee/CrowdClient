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

    def authenticate(self) -> bool:
        """
        Authenticate to CrowdStrike API using id and secret supplied on instantiation
        :return:
        """
        payload = {'client_id': self.client_id,
                   'client_secret': self.client_secret}

        response = self.session.post(self.base_url + '/oauth2/token',
                                     data=payload)

        if response.status_code == 201:
            headers = {'Authorization': f'Bearer {response.json()["access_token"]}',
                       'token_type': 'bearer',
                       'Content-Type': 'application/json'}

            self.session.headers = headers

        return response.status_code == 201

    def revoke(self) -> bool:
        """
        Revoke an issued Bearer token.
        :return:
        """
        payload = {'token': self.session.headers['Authorization']}

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

    def get_incidents(self, sort: str = 'modified_timestamp.desc', status: str = '20', fine_score: str = '10') -> List:
        """
        Retrieve a list of incidents in your environment based on supplied criteria.
        :param sort: Defaults to descending order based on last modified.
        :param status: Can be 'New', 'In Progress', 'Closed', or 'Reopened'.
        :param fine_score: Severity (>=) can be anywhere from 0-100 (100 would have a severity of 10.0).
        :return:
        """

        status_dict = {
            'New': '20',
            'In Progress': '30',
            'Closed': '40',
            'Reopened': '25'
        }

        params = {'sort': sort,
                  'filter': f'status:{status_dict[status]}+fine_score:>={fine_score}'}

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

    def indicator_host_search(self, indicator: str, indicator_type: str) -> List:
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

    def host_search(self, criteria: str, criteria_type: str, limit: int = 5000) -> List:
        """
        Search for hosts in your environment - Returns a list of agent ID's.
        :param criteria_type: IE, local_ip, hostname, etc.
        :param criteria: Largely dependent on 'criteria_type' (IE, local_ip:'192.168.0.3')
        :param limit: Defaults to 5000 to capture as many records as possible.
        :return:
        """

        params = {'filter': f"{criteria_type}:'{criteria}'"}

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

    def rtr_get_scripts(self):
        response = self.session.get(self.base_url + '/real-time-response/queries/scripts/v1')

        if response.status_code == 200:
            return response.json()['resources']

    def rtr_script_details(self, script_ids: List):
        params = {'ids': script_ids}

        response = self.session.get(self.base_url + '/real-time-response/entities/scripts/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']
        else:
            return response

    def rtr_upload_script(self, script_path: str, script_name: str, description: str,
                          permission_type: str, platform: str):

        payload = MultipartEncoder(
            fields={'file': (script_name, open(script_path, 'rb')),
                    'description': description,
                    'permission_type': permission_type,
                    'platform': platform}
        )

        self.session.headers['Content-Type'] = payload.content_type

        response = self.session.post(self.base_url + '/real-time-response/entities/scripts/v1', data=payload)

        return response.status_code == 200

    def rtr_delete_script(self, script_id):
        params = {'ids': script_id}

        response = self.session.delete(self.base_url + '/real-time-response/entities/scripts/v1', params=params)

        return response.status_code == 200

    def rtr_batch_init(self, host_ids: List, timeout: str = '30', timeout_duration: str = '30s'):
        params = {'timeout': timeout,
                  'timeout_duration': timeout_duration}

        payload = {'host_ids': host_ids}

        response = self.session.post(self.base_url + '/real-time-response/combined/batch-init-session/v1',
                                     params=params, json=payload)

        if response.status_code == 201:
            return response.json()['batch_id']
        else:
            return f'Error:\n{response.text}'


