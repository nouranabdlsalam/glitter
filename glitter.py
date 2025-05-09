import argparse
import os
from pathlib import Path
import colorama


from banner import print_banner
from string_extractor import extract_strings
from ioc_extractor import extract_iocs
from ioc_validator import validate_iocs
from yara_generator import generate_yara_rules
from report_generator import generate_html_report


def main():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description="Glitter - Automated IOC Extractor and Validator")
    parser.add_argument('-p', '--path', required=True, nargs='+', help='Path(s) to file(s) or directory to scan')
    parser.add_argument('-o', '--output', default=f'{os.path.join(script_dir, "outputs/")}', help='Output folder')
    parser.add_argument('--no-yara', action='store_true', help='Disable YARA rule generation')
    parser.add_argument('-q', '--quiet-mode', action='store_true', help='Launch Glitter without printing the banner')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan subdirectories')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show scanning details')
    args = parser.parse_args()

    print(colorama.Fore.LIGHTMAGENTA_EX + "\n \n Glitter - Automated IOC Extractor and Validator" + colorama.Fore.RESET)

    if not args.quiet_mode:
        print_banner()

    report_data = []
    scanned_files_count = 0

    paths_to_scan = []

    for p in args.path:
        if os.path.isfile(p):
            paths_to_scan.append(Path(p))
        elif os.path.isdir(p):
            dir_path = Path(p)
            if args.recursive:
                paths_to_scan.extend([f for f in dir_path.rglob('*') if f.is_file()])
            else:
                paths_to_scan.extend([f for f in dir_path.iterdir() if f.is_file()])
        else:
            print(colorama.Fore.RED + f"[!] Invalid path: {p}" + colorama.Fore.RESET)

    if paths_to_scan:
        for file_path in paths_to_scan:
            result = scan_file(file_path, args)
            scanned_files_count += 1
            if result:
                report_data.append(result)
    else:
        print(colorama.Fore.LIGHTRED_EX + "[-] No files to scan in " + args.output + colorama.Fore.RESET)

    if report_data:
        generate_html_report(report_data, scanned_files_count, args.output)


def scan_file(file_path, args):
    print()
    print(colorama.Fore.LIGHTMAGENTA_EX + "[+] Scanning " + str(file_path) + colorama.Fore.RESET)
    strings = extract_strings(file_path)

    if args.verbose:
        print(colorama.Fore.LIGHTYELLOW_EX + "[+] Extracted " + str(len(strings)) + " strings from " + str(
            file_path) + colorama.Fore.RESET)

    ip_iocs, url_iocs = extract_iocs(strings)

    if args.verbose:
        print(colorama.Fore.LIGHTYELLOW_EX + "[+] Found " + str(
            len(ip_iocs)) + " IPs and " + str(len(url_iocs)) + " URLs in " + str(file_path) + colorama.Fore.RESET)

    results = validate_iocs(ip_iocs, url_iocs, args.verbose)

    yara_rules_path = ""
    if not args.no_yara:
        yara_rules_path = generate_yara_rules(results, str(file_path), args.output, args.verbose)

    return {"file_path": file_path, "scan_results": results, "yara_rules_path": yara_rules_path,
            "number_of_extracted_ip_iocs": len(ip_iocs), "number_of_extracted_url_iocs": len(url_iocs)}


if __name__ == "__main__":
    main()
