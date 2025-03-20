import requests
import zipfile
import os
import json
from datetime import datetime
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet

NVD_API_KEY = "your-nvd-api-key-here"  # Replace with your NVD API key or leave empty
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def read_jar_list(sheet_path):
    jar_files = []
    with open(sheet_path, 'r') as file:
        for line in file:
            jar_path = line.strip()
            if jar_path.endswith('.jar'):
                jar_files.append(jar_path)
    return jar_files

def extract_jar_metadata(jar_path):
    try:
        with zipfile.ZipFile(jar_path, 'r') as jar:
            if 'META-INF/MANIFEST.MF' in jar.namelist():
                with jar.open('META-INF/MANIFEST.MF') as manifest:
                    manifest_data = manifest.read().decode('utf-8')
                    metadata = {}
                    for line in manifest_data.splitlines():
                        if ':' in line:
                            key, value = line.split(':', 1)
                            metadata[key.strip()] = value.strip()
                    return metadata.get('Implementation-Title', 'Unknown'), metadata.get('Implementation-Version', 'Unknown')
    except Exception as e:
        print(f"Error reading {jar_path}: {e}")
    return "Unknown", "Unknown"

def fetch_cve_data(library_name, version):
    headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        'keywordSearch': f"{library_name} {version}",
        'resultsPerPage': 50
    }
    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get('vulnerabilities', [])
        else:
            print(f"Error fetching CVE for {library_name} {version}: {response.status_code}")
            return []
    except Exception as e:
        print(f"Exception fetching CVE: {e}")
        return []

def save_to_csv(report, output_file):
    data = []
    for result in report["results"]:
        for cve in result["cve_details"]:
            data.append({
                "JAR Path": result["jar_path"],
                "Library Name": result["library_name"],
                "Version": result["version"],
                "CVE ID": cve["cve_id"],
                "Description": cve["description"]
            })
        if not result["cve_details"]:
            data.append({
                "JAR Path": result["jar_path"],
                "Library Name": result["library_name"],
                "Version": result["version"],
                "CVE ID": "None",
                "Description": "No vulnerabilities found"
            })
    df = pd.DataFrame(data)
    df.to_csv(output_file, index=False)
    print(f"CSV report saved to {output_file}")

def save_to_pdf(report, output_file):
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph(f"Jar CVE Scan Report - {report['timestamp']}", styles['Title']))
    elements.append(Spacer(1, 12))
    table_data = [["JAR Path", "Library Name", "Version", "CVE ID", "Description"]]
    for result in report["results"]:
        for cve in result["cve_details"]:
            table_data.append([
                result["jar_path"],
                result["library_name"],
                result["version"],
                cve["cve_id"],
                Paragraph(cve["description"], styles['BodyText'])
            ])
        if not result["cve_details"]:
            table_data.append([
                result["jar_path"],
                result["library_name"],
                result["version"],
                "None",
                Paragraph("No vulnerabilities found", styles['BodyText'])
            ])
    table = Table(table_data, colWidths=[100, 80, 50, 80, 200])
    table.setStyle([('GRID', (0, 0), (-1, -1), 1, 'black')])
    elements.append(table)
    doc.build(elements)
    print(f"PDF report saved to {output_file}")

def scan_jars(jar_list, output_format="csv"):
    report = {"timestamp": str(datetime.now()), "results": []}
    for jar_path in jar_list:
        library_name, version = extract_jar_metadata(jar_path)
        print(f"Scanning {jar_path} - Library: {library_name}, Version: {version}")
        cve_data = fetch_cve_data(library_name, version)
        result = {
            "jar_path": jar_path,
            "library_name": library_name,
            "version": version,
            "cve_count": len(cve_data),
            "cve_details": [{"cve_id": cve['cve']['id'], "description": cve['cve']['descriptions'][0]['value']} for cve in cve_data]
        }
        report["results"].append(result)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if output_format.lower() == "csv":
        output_file = f"scan_report_{timestamp}.csv"
        save_to_csv(report, output_file)
    elif output_format.lower() == "pdf":
        output_file = f"scan_report_{timestamp}.pdf"
        save_to_pdf(report, output_file)
    else:
        output_file = f"scan_report_{timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"JSON report saved to {output_file}")

if __name__ == "__main__":
    sheet_path = "jars.txt"
    jar_list = read_jar_list(sheet_path)
    scan_jars(jar_list, output_format="csv")  # Change to "pdf" for PDF output
