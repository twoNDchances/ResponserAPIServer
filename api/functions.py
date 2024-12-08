from ansible_runner import run
import re


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


def find_missing_or_next(numbers: list) -> list[int] | int:
    full_range = range(1, numbers[-1] + 1)
    missing_numbers = list(set(full_range) - set(numbers))
    if missing_numbers:
        if missing_numbers.__len__() == 1:
            return missing_numbers + [numbers[-1] + 1]
        return missing_numbers
    else:
        next_number = max(numbers) + 1
        return next_number


def replace_important_chars(string: str):
    return string.replace('\\\\"', '@dbquote@').replace('"', '@dbquote@').replace('\\b', '@backspace@').replace('`', '@backquote@').replace(';', '@semicolon@').replace("'", '@sgquote@').replace('$', '@dollar@')

