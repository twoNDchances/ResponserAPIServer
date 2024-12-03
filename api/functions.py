from ansible_runner import run
import re
import uuid
from .storage import ANSIBLE_DATA_DIR, ANSIBLE_INVENTORY, ANSIBLE_MODSEC_CONAME, ANSIBLE_FIREWALL_USERNAME, ANSIBLE_FIREWALL_PASSWORD, ANSIBLE_CRS_PATH_DIR


def parse_path(path: str) -> list[str] | str | None:
    if path.startswith("[") and path.endswith("]"):
        paths = re.split(r',\s*', path[1:-1].strip())
        if all(re.match(r'^[\w\.-]+$', p) for p in paths):
            return paths
        else:
            return None
    elif re.match(r'^[\w\.-]+$', path):
        return path
    else:
        return None


def get_value_from_json(data, path: str):
    keys = re.split(r'\.(?![^\[]*\])', path)
    for key in keys:
        match = re.match(r'([\w\-]+)(\[(\d+)\])?', key)
        if not match:
            return None
        key, _, index = match.groups()
        if isinstance(data, dict):
            data = data.get(key)
            if data is None:
                return None
        else:
            return None
        if index is not None:
            try:
                index = int(index)
                data = data[index]
            except:
                return None
    return data


def parse_multipart_form_data(raw_data: str):
    first_line_end = raw_data.find("\r\n")
    if first_line_end == -1:
        raise ValueError("Invalid format: Cannot find boundary")
    boundary = raw_data[:first_line_end]
    parts = raw_data.split(boundary)
    result = {}

    for part in parts:
        if not part.strip() or part.strip() == "--":
            continue
        header_end = part.find("\r\n\r\n")
        if header_end == -1:
            continue
        headers = part[:header_end]
        body = part[header_end + 4:].strip("\r\n")
        name_start = headers.find('name="')
        if name_start == -1:
            continue
        name_start += len('name="')
        name_end = headers.find('"', name_start)
        if name_end == -1:
            continue
        field_name = headers[name_start:name_end]
        result[field_name] = body
    return result


def hex_escape_to_char(string):
    hex_pattern = r"\\x([0-9A-Fa-f]{2})"
    def hex_to_char(match):
        hex_value = match.group(1)
        if hex_value == '22':
            return '"'
        elif hex_value == '0D':
            return '\r'
        elif hex_value == '0A':
            return '\n'
        else:
            return '\\x' + hex_value
    return re.sub(hex_pattern, hex_to_char, string)


def generate_full_regex(text, sub_regex):
    text_escaped = re.escape(text)
    modifier_match = re.match(r"^\(\?[a-zA-Z]+\)", sub_regex)
    modifier = modifier_match.group(0) if modifier_match else ""
    if modifier:
        sub_regex = sub_regex[len(modifier):]
    try:
        matches = list(re.finditer(sub_regex, text, flags=re.IGNORECASE if "(?i)" in modifier else 0))
    except re.error as e:
        raise ValueError(f"Error in sub_regex: {e}")
    if not matches:
        return f"{modifier}{text_escaped}"    
    full_regex = ""
    last_index = 0
    for match in matches:
        full_regex += re.sub(r'\b(\w+)\b', r"[\\w\\s!@#$%^&*()-_=+\[\]{}'\\\"|;:,\.<\\\>?/]+", re.escape(text[last_index:match.start()]))
        full_regex += f"({sub_regex})"
        last_index = match.end()
    full_regex += re.sub(r'\b(\w+)\b', r"[\\w\\s!@#$%^&*()-_=+\[\]{}'\\\"|;:,\.<\\\>?/]+", re.escape(text[last_index:]))
    return f"{modifier}{full_regex}"


# def delete_secrule_file(extra_vars: dict):
#     runner = run(
#         private_data_dir=ANSIBLE_DATA_DIR,
#         playbook='../api/modsecurity/playbooks/ansible_apply_only_ip_payload_modsecurity.yaml',
#         inventory=ANSIBLE_INVENTORY,
#         extravars={
#             'username_firewall_node': ANSIBLE_FIREWALL_USERNAME,
#             'password_firewall_node': ANSIBLE_FIREWALL_PASSWORD,
#             'secrule_anomaly_score': ip_address.get('anomaly_score'),
#             'secrule_paranoia_level': ip_address.get('paranoia_level'),
#             'secrule_payload': root_cause_value.replace('\"', '\\\"'),
#             'secrule_id_ip': id_for_secrule_ip,
#             'secrule_id_chain': id_for_secrule_chain,
#             'secrule_ip': ip_source_value,
#             'secrule_file': f'{ANSIBLE_CRS_PATH_DIR}/REQUEST-{id_for_secrule_ip}-{id_for_secrule_chain}-{unique_id_onlyIPAndPayload_forever}',
#             'modsec_container_name': ANSIBLE_MODSEC_CONAME
#         },
#         host_pattern='firewall',
#         json_mode=True,
#         quiet=True,
#         ident=uuid.uuid4()
#     )
#     return True
