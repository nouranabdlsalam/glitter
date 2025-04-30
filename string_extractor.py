import re


def extract_strings(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()

    pattern = rb'[\x20-\x7E]{6,}'
    file_strings = re.findall(pattern, content)

    decoded_strings = []

    for string in file_strings:
        decoded_strings.append(string.decode('utf-8', errors='ignore'))

    return decoded_strings
