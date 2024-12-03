# # # import re

# # # def decode_hex_escaped_string(input_string):
# # #     def replace_match(match):
# # #         return bytes.fromhex(match.group(1)).decode('latin1')
# # #     decoded_string = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_match, input_string)
# # #     return decoded_string

# # # # print(decode_hex_escaped_string(input_string='0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e'))


# # # rules = [
# # #     re.compile(r'0x[0-9A-Fa-f]+')
# # # ]

# # # for rule in rules:
# # #     if rule.search('0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e'):
# # #         print(rule)


# # import re

# # # Chuỗi chứa biểu thức chính quy và các tùy chọn
# # pattern_str = r"re.compile('(?i)\\\\b(EXEC\\\\s*\\\\(\\\\s*(@\\\\w+|[\\'\"].*[\\'\"])\\\\s*\\\\);|EXEC?\\\\s+\\\\w+\\\\s+@\\\\w+\\\\s*=\\\\s*|EXECUTE\\\\s+\\\\w+\\\\s*;|EXECUTE\\\\s*(\\\\w+|[\\'\"].*[\\'\"]);)', re.IGNORECASE)"

# # # Tách regex chính và các tùy chọn
# # regex_part = re.search(r"re\.compile\('([^']*)'", pattern_str).group(1)
# # flags_part = re.search(r",\s*(re\.\w+)", pattern_str)

# # # Xử lý regex thoát ký tự (\\ -> \)
# # regex = "(?i)<.*?script.*?>.*?(</script>)?"

# # # Xử lý các tùy chọn (nếu có)
# # flags = 0
# # if flags_part:
# #     flag_name = flags_part.group(1)
# #     flags = eval(flag_name)  # Biến chuỗi flag thành giá trị thực

# # # Biên dịch lại regex
# # print([regex])
# # compiled_pattern = re.compile(regex)

# # # Kiểm tra biểu thức regex
# # test_str = "</script>"
# # match = compiled_pattern.search(test_str)
# # if match:
# #     print("Khớp:", match.group())
# # else:
# #     print("Không khớp")

import re

def generate_full_regex(text, sub_regex):
    """
    Generate a full regex pattern that matches exactly the given text,
    ensuring that inline modifiers like (?i) are correctly applied.
    
    Parameters:
        text (str): The input text to match.
        sub_regex (str): A sub-regex pattern that appears within the text.
        
    Returns:
        str: A regex pattern that matches the entire text.
    """
    text_escaped = re.escape(text)
    # Kiểm tra và tách các global flags ở đầu regex (e.g., (?i))
    modifier_match = re.match(r"^\(\?[a-zA-Z]+\)", sub_regex)
    modifier = modifier_match.group(0) if modifier_match else ""
    if modifier:
        sub_regex = sub_regex[len(modifier):]  # Bỏ modifier khỏi sub-regex để xử lý
    # Xác định vị trí khớp sub_regex trong text
    try:
        matches = list(re.finditer(sub_regex, text, flags=re.IGNORECASE if "(?i)" in modifier else 0))
    except re.error as e:
        raise ValueError(f"Error in sub_regex: {e}")

    # Nếu không có khớp, trả về regex cho toàn bộ chuỗi tĩnh
    if not matches:
        return f"{modifier}{text_escaped}"
    
    # Xây dựng regex từ các phần khớp
    full_regex = ""
    last_index = 0
    for match in matches:
        # Thêm phần trước đoạn khớp
        full_regex += re.sub(r'\b(\w+)\b', r'\\w+', re.escape(text[last_index:match.start()]))
        # Thêm sub_regex vào regex đầy đủ
        full_regex += f"({sub_regex})"
        # Cập nhật vị trí cuối
        last_index = match.end()

    # Thêm phần còn lại của chuỗi
    full_regex += re.sub(r'\b(\w+)\b', r'\\w+', re.escape(text[last_index:]))
    # full_regex += re.escape(text[last_index:])
    # Đặt modifier ở đầu toàn bộ regex
    return f"{modifier}{full_regex}"

# Ví dụ
text = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, 1 like 1 Chrome/131.0.0.0 Safari/537.36"
sub_regex = "(?i).+\\s*R?LIKE\\s*(['\"].*['\"]|\\((\\w*|.*)\\))|.*(\\s*['\"]|\\s+\\d+)\\s*R?LIKE\\s+\\d+\\s*"
# Tạo regex toàn bộ chuỗi
full_regex = generate_full_regex(text, sub_regex)
full_regex = re.sub(r'\\\s+', r'\\s*', full_regex)
print(f"Regex toàn bộ chuỗi: {full_regex}")

# Kiểm tra
if re.fullmatch(full_regex, text):
    print("Chuỗi khớp với regex.")
else:
    print("Chuỗi không khớp với regex.")

# print([line.replace('\n', '') for line in file.readlines()])