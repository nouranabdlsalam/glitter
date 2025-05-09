import re


def extract_iocs(strings):
    ip_pattern = (r"(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]?|[1-9][0-9]|[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]?|["
                  r"1-9][0-9]|[0-9])\.(?:25[0-5]|2[0-4][0-9]|[1][0-9][0-9]?|[1-9][0-9]|[0-9])\.(?:25[0-5]|2[0-4]["
                  r"0-9]|[1][0-9][0-9]?|[1-9][0-9]|[0-9])")

    url_pattern = r'(?i)\b(?:https?|ftp):\/\/(?:[\w-]+\.)+[a-zA-Z0-9]{2,}(?:\/[^\s]*)?\b'

    ip_iocs = [ioc for string in strings for ioc in re.findall(ip_pattern, string)]
    url_iocs = [ioc for string in strings for ioc in re.findall(url_pattern, string)]

    unique_ip_iocs = []
    unique_url_iocs = []

    [unique_ip_iocs.append(ip) for ip in ip_iocs if ip not in unique_ip_iocs]
    [unique_url_iocs.append(url) for url in url_iocs if url not in unique_url_iocs]

    return unique_ip_iocs, unique_url_iocs
