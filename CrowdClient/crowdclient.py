import requests
from requests.auth import HTTPBasicAuth
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

    def get_incidents(self, sort: str = 'modified_timestamp.desc', status: str = '20',
                      fine_score: str = '10') -> List:
        """

        :param sort:
        :param status:
        :param fine_score:
        :return:
        """
        params = {'sort': sort,
                  'filter': f'status:{status}+fine_score:>={fine_score}'}

        response = self.session.get(self.base_url + '/incidents/queries/incidents/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def get_incident_details(self, incident_ids: List, detailed: bool = True) -> Union[Union[list, dict]]:
        """

        :param incident_ids:
        :param detailed:
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

        :param incident_ids:
        :param status:
        :param tags:
        :return:
        """
        action_parameters = []

        if status:
            action_parameters.append({'name': 'update_status',
                                      'value': status})
        if tags:
            action_parameters.append({'name': 'add_tag',
                                      'value': tags})

        payload = {'action_parameters': action_parameters,
                   'ids': incident_ids}

        response = self.session.post(self.base_url + '/incidents/entities/incident-actions/v1', json=payload)

        return response.status_code == 200

    def get_behavior_details(self, behavior_ids: List) -> dict:
        payload = {'ids': behavior_ids}

        response = self.session.post(self.base_url + '/incidents/entities/behaviors/GET/v1', json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            return {'Error Code': response.status_code, 'Error Details': response.text}

    def indicator_upload(self, indicator_list: List, description: str, category: str) -> Union[str, List]:
        """

        :param indicator_list:
        :param description:
        :param category:
        :return:
        """

        payload = payload_assemble(indicator_list, description, category)

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
        :param indicator:
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
