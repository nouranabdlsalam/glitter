import os
import re
from pathlib import Path
import colorama


def write_rule(iocs, file_name, ioc_type):
    ioc_singular = ioc_type[:-1].lower()
    rule = f'''
rule detect_malicious_{ioc_type.lower()}{{
    meta:
        author = "Glitter"
        description = "Detects known malicious {ioc_type} found in {file_name}."
    strings:
'''
    for i, item in enumerate(iocs, 1):
        rule += f'        $malicious_{ioc_singular}_{i} = "{item["ioc"]}"\n'

    rule += "    condition:\n        any of them\n}\n"
    return rule



def generate_yara_rules(result, file_path, output_dir, verbose):
    file_name = os.path.basename(file_path)
    rules = ""

    if result["malicious_ips"]:
        rules += write_rule(result["malicious_ips"], file_name, "IPs")

    if result["malicious_urls"]:
        rules += write_rule(result["malicious_urls"], file_name, "URLs")

    if not rules.strip():
        print(colorama.Fore.LIGHTMAGENTA_EX + f"[+] No YARA rules to write for {file_name}." + colorama.Fore.RESET)
        return

    parts = re.split(r"\.", file_name)
    file_name = parts[0]

    output_path = Path(output_dir) / "glitter_yara_rules" / f"{file_name}_rules.yara"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as yara_file:
        yara_file.write(rules)

    print(colorama.Fore.LIGHTMAGENTA_EX + f"[+] YARA rules written to {output_path}" + colorama.Fore.RESET)
    if verbose:
        print(colorama.Fore.LIGHTYELLOW_EX + f"[.] Use 'yara {output_path} {file_path}' to try them out." + colorama.Fore.RESET)

    return output_path
