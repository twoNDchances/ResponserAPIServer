import re

regex = re.sub(r'\b(\w+)\b', r'[\\w\\s]+', 'aaaaa')

print(re.compile(regex).search('aaaa13r902 8sss/da\\sda'))

print([regex])