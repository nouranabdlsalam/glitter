import os

import requests
import json
import sys
import base64
import colorama


def scan_ioc(ioc_type, ioc, url, headers, thresholds, verbose):
    response = requests.get(url, headers=headers)
    if verbose:
        print(colorama.Fore.LIGHTYELLOW_EX + f"[+] Scanned {ioc}" + colorama.Fore.RESET)
    data = response.json()

    if "error" in data:
        code = data["error"].get("code", "")
        if code == "NotFoundError":
            print(colorama.Fore.LIGHTRED_EX + f"[-] No VT data for {ioc} — marking as unknown." + colorama.Fore.RESET)
            return None
        elif code == "QuotaExceededError":
            print(colorama.Fore.LIGHTRED_EX + f"[-] Quota exceeded. Skipping {ioc}." + colorama.Fore.RESET)
            return None
        else:
            print(
                colorama.Fore.LIGHTRED_EX + f"[-] VT error for {ioc}: {data['error'].get('message', 'Unknown error')}" + colorama.Fore.RESET)
            return None

    attributes = data["data"]["attributes"]

    reputation = attributes.get("reputation", 0)
    engines = attributes.get("last_analysis_results", {})

    malicious_detections = sum(1 for r in engines.values() if r["category"] == "malicious")
    suspicious_detections = sum(1 for r in engines.values() if r["category"] == "suspicious")

    total_engines = len(engines)
    malicious_ratio = malicious_detections / total_engines if total_engines else 0

    if (
            reputation < thresholds["reputation"] or
            malicious_ratio > thresholds["malicious_ratio"] or
            malicious_detections >= thresholds["malicious_detections"] or
            (suspicious_detections >= thresholds["suspicious_detections"] and reputation < 0)
    ):
        return (
            {"type": ioc_type, "ioc": ioc, "malicious_detections": malicious_detections,
             "suspicious_detections": suspicious_detections,
             "reputation": reputation, "total_engines": len(engines), "malicious_ratio": malicious_ratio})
    else:
        return {}


def scan_ips(ip_iocs, api_key, thresholds, verbose):
    malicious_ips = []
    unknown_ips = []

    for ip in ip_iocs:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = make_headers(api_key)
        scan_result = scan_ioc("ip", ip, url, headers, thresholds, verbose)
        if scan_result is None:
            unknown_ips.append(ip)
        elif scan_result:
            malicious_ips.append(scan_result)

    return malicious_ips, unknown_ips


def scan_urls(url_iocs, api_key, thresholds, verbose):
    malicious_urls = []
    unknown_urls = []

    for url_ioc in url_iocs:
        url_id = base64.urlsafe_b64encode(url_ioc.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = make_headers(api_key)

        scan_result = scan_ioc("url", url_ioc, vt_url, headers, thresholds, verbose)

        if scan_result is None:
            unknown_urls.append(url_ioc)
        elif scan_result:
            malicious_urls.append(scan_result)

    return malicious_urls, unknown_urls


def make_headers(api_key):
    return {
        "accept": "application/json",
        "x-apikey": api_key
    }


def validate_iocs(ip_iocs, url_iocs, verbose):
    malicious_ips = []
    malicious_urls = []
    unknown_ips = []
    unknown_urls = []

    try:
        script_dir = os.path.dirname(os.path.realpath(__file__))
        config_path = os.path.join(script_dir, "conf.json")
        with open(config_path, "r") as file:
            config = json.load(file)

        api_key = config["api-key"]
        thresholds = config["thresholds"]

        if not api_key:
            sys.exit(colorama.Fore.LIGHTRED_EX + "[-] 'api-key' is missing in conf.json." + colorama.Fore.RESET)

        required_keys = ["reputation", "malicious_ratio", "malicious_detections", "suspicious_detections"]
        for key in required_keys:
            if key not in thresholds:
                sys.exit(colorama.Fore.LIGHTRED_EX + f"[-] Threshold key '{key}' is missing. Please copy conf.example.json to conf.json." + colorama.Fore.RESET)

        if ip_iocs:
            malicious_ips, unknown_ips = scan_ips(ip_iocs, api_key, thresholds, verbose)

        if url_iocs:
            malicious_urls, unknown_urls = scan_urls(url_iocs, api_key, thresholds, verbose)

        return {
            "malicious_ips": malicious_ips,
            "malicious_urls": malicious_urls,
            "unknown_ips": unknown_ips,
            "unknown_urls": unknown_urls
        }

    except FileNotFoundError:
        sys.exit(colorama.Fore.LIGHTRED_EX + "[-] config file 'conf.json' not found." + colorama.Fore.RESET)
    except json.JSONDecodeError:
        sys.exit(colorama.Fore.LIGHTRED_EX + "[-] conf.json is not valid JSON." + colorama.Fore.RESET)
    except Exception as e:
        sys.exit(colorama.Fore.LIGHTRED_EX + f"[-] Unexpected error: {str(e)}" + colorama.Fore.RESET)
