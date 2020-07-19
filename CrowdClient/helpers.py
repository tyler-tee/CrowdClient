import typing


def chunker(indicator_list) -> typing.List:
    for i in range(0, len(indicator_list), 200):
        yield indicator_list[i:i + 1]


def payload_assemble(indicator_list, description, category):
    payload = []

    for indicator in indicator_list:
        payload_specs = {
            "description": description,
            "share_level": "red",
            "type": category,
            "value": indicator,
            "policy": "detect"
        }

        if category in ['domain', 'ipv4', 'ipv6']:
            payload_specs['expiration_days'] = 365

        payload.append(payload_specs)

    return payload
