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
                       status: str = 'new') -> List:
        """

        :param limit:
        :param offset:
        :param sort:
        :param status:
        :return:
        """
        params = {'limit': limit, 'offset': offset, 'sort': sort,
                  'filter': f"status:'{status}'+max_severity_displayname:['Critical', 'High', 'Medium', 'Low']"}

        response = self.session.get(self.base_url + '/detects/queries/detects/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def get_detection_details(self, detection_ids: List, detailed: bool = True) -> List:
        """

        :param detection_ids:
        :param detailed:
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

        :param detection_id:
        :param status:
        :param assignment:
        :param comment:
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

    def indicator_info(self, indicator: str, indicator_type: str) -> List:
        """

        :param indicator:
        :param indicator_type:
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.get(self.base_url + '/indicators/entities/iocs/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def indicator_host_search(self, indicator: str, indicator_type: str) -> List:
        """

        :param indicator:
        :param indicator_type:
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.get(self.base_url + '/indicators/queries/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()

    def indicator_host_count(self, indicator: str, indicator_type: str) -> int:
        """

        :param indicator:
        :param indicator_type:
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.get(self.base_url + '/indicators/aggregates/devices-count/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources'][0]['device_count']

    def indicator_remove(self, indicator: str, indicator_type):
        """

        :param indicator:
        :param indicator_type:
        :return:
        """
        params = {'type': indicator_type,
                  'value': indicator}

        response = self.session.delete(self.base_url + '/indicators/entities/iocs/v1', params=params)

        if response.status_code == 200:
            return f"Indicator {indicator} Removed!"
        else:
            return f"Failed removal of indicator {indicator}."

    def indicator_list(self, indicator_type: str):
        """

        :param indicator_type:
        :return:
        """
        params = {'types': indicator_type}

        response = self.session.get(self.base_url + '/indicators/queries/iocs/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_search(self, criteria: str, criteria_type: str) -> List:
        """

        :param criteria:
        :param criteria_type:
        :return:
        """
        params = {'filter': f"{criteria_type}:'{criteria}'"}

        response = self.session.get(self.base_url + '/devices/queries/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_details(self, host_ids: List) -> List:
        """

        :param host_ids:
        :return:
        """
        params = {'ids': host_ids}

        response = self.session.get(self.base_url + '/devices/entities/devices/v1', params=params)

        if response.status_code == 200:
            return response.json()['resources']

    def host_action(self, host_ids: List, action: str) -> bool:
        payload = {'ids': host_ids}
        params = {'action_name': action}

        response = self.session.post(self.base_url + '/devices/entities/devices-actions/v2',
                                     json=payload, params=params)

        return response.status_code == 202
