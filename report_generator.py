import json
import os
from datetime import datetime
from pathlib import Path
import colorama


def generate_table(malicious_iocs):
    table = f'''
    <table>
        <tr>
            <th> {malicious_iocs[0].get("type").upper()} </th>
            <th> Malicious Detections </th>
            <th> Suspicious Detections </th>
            <th> Reputation </th>
            <th> Total AV Engines </th>
            <th> Malicious Detections Ratio </th>
        </tr>
    '''

    for malicious_ioc in malicious_iocs:
        ioc = malicious_ioc.get("ioc")
        malicious_detections = malicious_ioc.get("malicious_detections")
        suspicious_detections = malicious_ioc.get("suspicious_detections")
        reputation = malicious_ioc.get("reputation")
        total_engines = malicious_ioc.get("total_engines")
        malicious_ratio = malicious_ioc.get("malicious_ratio")
        table += f'''
        <tr>
            <td> {ioc} </td>
            <td> {malicious_detections} </td>
            <td> {suspicious_detections} </td>
            <td> {reputation} </td>
            <td> {total_engines} </td>
            <td> {malicious_ratio} </td>
        </tr>
        '''

    table += "</table>"
    return table


def generate_list(unknown_iocs):
    list = "\n <ul> \n"
    for unknown_ioc in unknown_iocs:
        list += f"<li> {unknown_ioc} </li> \n"

    list += "</ul> \n"
    return list


def update_scanned_files(file_name, yara_rules_path, number_of_extracted_ips, number_of_extracted_urls, scan_results):
    malicious_ips = scan_results.get("malicious_ips")
    malicious_urls = scan_results.get("malicious_urls")
    unknown_ips = scan_results.get("unknown_ips")
    unknown_urls = scan_results.get("unknown_urls")

    scanned_file = f'''
    <section>
    <h2> {file_name} </h2>
    <p> <strong> Number of Extracted IOCs: </strong> {(number_of_extracted_ips + number_of_extracted_urls)} </p>
    <p> <strong> Number of Malicious IOCs: </strong> {(len(malicious_ips) + len(malicious_urls))} </p>
    '''

    if malicious_ips or malicious_urls:
        scanned_file += f'''
        <p> <strong> Path to YARA Rules: </strong> {yara_rules_path} </p>
        '''

    if malicious_ips:
        scanned_file += "<h3> Malicious IPs </h3>"
        scanned_file += generate_table(malicious_ips)

    if malicious_urls:
        scanned_file += "<h3> Malicious URLs </h3>"
        scanned_file += generate_table(malicious_urls)

    if unknown_ips:
        scanned_file += "<h3> Unknown IPs </h3>"
        scanned_file += generate_list(unknown_ips)

    if unknown_urls:
        scanned_file += "<h3> Unknown URLs </h3>"
        scanned_file += generate_list(unknown_urls)

    scanned_file += "\n </section> \n"

    return scanned_file, len(malicious_ips), len(malicious_urls)


def generate_html_report(report_data, scanned_files_count, output_dir):
    total_extracted_iocs = total_extracted_ips = total_extracted_urls = 0
    total_malicious_iocs = total_malicious_ips = total_malicious_urls = 0
    scanned_files = ""
    for file in report_data:
        file_path = file.get("file_path")
        scan_results = file.get("scan_results")
        yara_rules_path = file.get("yara_rules_path")
        number_of_extracted_ips = file.get("number_of_extracted_ip_iocs")
        number_of_extracted_urls = file.get("number_of_extracted_url_iocs")

        file_name = os.path.basename(file_path)
        total_extracted_iocs += (number_of_extracted_ips + number_of_extracted_urls)
        total_extracted_ips += number_of_extracted_ips
        total_extracted_urls += number_of_extracted_urls

        code, malicious_ips, malicious_urls = update_scanned_files(file_name, yara_rules_path, number_of_extracted_ips,
                                                                   number_of_extracted_urls, scan_results)

        total_malicious_iocs += (malicious_ips + malicious_urls)
        total_malicious_ips += malicious_ips
        total_malicious_urls += malicious_urls

        scanned_files += code

    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
        <title>Glitter IOC Report</title>
        <style>
            body {{
              font-family: 'Poppins', sans-serif;
              background: #f8f5ff;
              color: #2f2a4a;
              margin: 0;
              padding: 2rem;
            }}

            header {{
              background: linear-gradient(to right, #f4d3ff, #f4f0ff);
              border-bottom: 2px solid #d19dd6;
              padding: 1.5rem;
              text-align: center;
              position: relative;
            }}

            header h1 {{
              margin: 0;
              font-size: 2rem;
              font-weight: 600;
              color: #9b30b1;
            }}

            header p {{
              font-size: 1rem;
              color: #4f3b78;
            }}

            section {{
              margin-top: 2rem;
            }}

            h2 {{
              font-size: 1.25rem;
              border-bottom: 1px solid #d19dd6;
              padding-bottom: 0.5rem;
              color: #9b30b1;
            }}

            h3 {{
              margin-top: 1.5rem;
            }}

            table {{
              width: 100%;
              border-collapse: collapse;
              margin-top: 1rem;
            }}

            th, td {{
              border: 1px solid #d9b3eb;
              padding: 0.75rem;
              text-align: left;
            }}

            th {{
              background-color: #eed2f9;
              color: #842c96;
            }}

            td {{
              background-color: #fdfbff;
            }}
        
            ul {{
              padding-left: 1.2em;
            }}

            li {{
              color: #9b30b1;
              margin: 4px 0;
            }}
        
            footer {{
              margin-top: 4rem;
              text-align: center;
              font-size: 0.9rem;
              color: #7a6b94;
            }}
            @media print {{
            button, header p {{
              display: none;
            }}
            }}
            .button-container {{
              text-align: center;
              margin-top: 2rem;
            }}
            .download-btn {{
              background-color: #9b30b1;
              color: white;
              padding: 0.6rem 1.4rem;
              border: none;
              border-radius: 6px;
              font-weight: bold;
              font-size: 1rem;
              cursor: pointer;
              transition: background-color 0.3s ease;
            }}
            .download-btn:hover {{
              background-color: #842c96;
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>Glitter IOC Report</h1>
            <p>IOC Scanning Made Fabulous</p>
        </header>
        <section>
            <h2> Scan Summary </h2>
            <table>
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Scan Date</td><td>{datetime.now().strftime("%d-%m-%Y %H:%M:%S")}</td></tr>
                <tr><td>Total Scanned Files</td><td>{scanned_files_count}</td></tr>
                <tr><td>Total Extracted IOCs</td><td>{total_extracted_iocs}</td></tr>
                <tr><td>Total Malicious IOCs</td><td>{total_malicious_iocs}</td></tr>
                <tr><td>Total Extracted IPs</td><td>{total_extracted_ips}</td></tr>
                <tr><td>Total Malicious IPs</td><td>{total_malicious_ips}</td></tr>
                <tr><td>Total Extracted URLs</td><td>{total_extracted_urls}</td></tr>
                <tr><td>Total Malicious URLs</td><td>{total_malicious_urls}</td></tr>
            </table>
        </section>    
    '''

    html += scanned_files
    html += '''
    <div class="button-container">
        <button onclick="window.print()" class="download-btn">Download as PDF</button>
    </div>
    <footer>
        Report generated by Glitter ✨
    </footer>
    </body>
    </html>
    '''

    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, "conf.json")

    with open(config_path, "r") as file:
        config = json.load(file)

    scan_count = config.get("scan_count", 1)

    # Construct output path
    output_path = Path(output_dir) / "glitter_reports" / f"glitter_report_{scan_count}.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the report
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Increment and save scan_count
    config["scan_count"] = scan_count + 1
    with open(config_path, "w") as file:
        json.dump(config, file, indent=2)

    print()
    print(colorama.Fore.LIGHTMAGENTA_EX + f"[+] IOC Report Generated at {output_path}" + colorama.Fore.RESET)
