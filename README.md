# JarCVEScanner 🛡️

**Scan your Java JAR libraries for vulnerabilities with ease!**

JarCVEScanner is a powerful, open-source Python tool designed to identify vulnerabilities in Java JAR files by fetching CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD). Whether you're a developer, security researcher, or DevOps engineer, this tool helps you ensure your third-party libraries are secure. Output your scan results in **CSV** or **PDF** format—your choice!

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg) ![License](https://img.shields.io/badge/License-MIT-green.svg) ![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)

---

## ✨ Features
- **CVE Lookup**: Fetches real-time vulnerability data from NVD (`nvd.nist.gov`).
- **JAR Metadata Extraction**: Automatically pulls library names and versions from `MANIFEST.MF`.
- **Flexible Output**: Generate reports in **CSV** (spreadsheet-friendly) or **PDF** (professionally formatted).
- **Scalable**: Add new JARs to your list and rescan anytime.
- **Cross-Platform**: Works seamlessly on **Ubuntu** and **Windows**.
- **Interactive**: Simple setup with clear terminal feedback.

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.6+** installed.
- An internet connection to query the NVD API.
- A list of JAR files to scan (in a `jars.txt` file).

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/JarCVEScanner.git
   cd JarCVEScanner
Install Dependencies:
bash
pip install requests pandas reportlab
Prepare Your JAR List:
Create a jars.txt file in the project directory.
Add full paths to your JAR files, one per line:
text


/path/to/commons-collections-3.2.1.jar
/path/to/log4j-1.2.17.jar
Run the Scanner:
For CSV output:
bash


python JarCVEScanner.py
For PDF output, edit the last line in JarCVEScanner.py to scan_jars(jar_list, output_format="pdf") and run:
bash


python JarCVEScanner.py
📋 Example Output
CSV Report
File: scan_report_20250320_160022.csv

csv


JAR Path,Library Name,Version,CVE ID,Description
/path/to/commons-collections-3.2.1.jar,Commons Collections,3.2.1,CVE-2015-7501,"Deserialization of untrusted data allows remote code execution."
/path/to/log4j-1.2.17.jar,log4j,1.2.17,CVE-2021-44228,"Log4Shell: Remote code execution via JNDI lookups."
PDF Report
File: scan_report_20250320_160033.pdf

A neatly formatted table with JAR details and CVE descriptions in a professional document.
🛠️ How It Works
Reads JAR List: Parses jars.txt for JAR file paths.
Extracts Metadata: Dives into each JAR’s MANIFEST.MF to grab library name and version.
Fetches CVE Data: Queries the NVD API for vulnerabilities matching the library and version.
Generates Report: Saves results in your chosen format (CSV or PDF).
🔧 Configuration
NVD API Key (Optional):
Get a key from NVD API Registration to avoid rate limits.
Replace NVD_API_KEY = "your-nvd-api-key-here" in JarCVEScanner.py with your key.
Output Format: Change output_format in the last line of the script:
"csv" for CSV (default).
"pdf" for PDF.
📦 Code Snippet
Here’s the core of the tool:


Copy
def scan_jars(jar_list, output_format="csv"):
    report = {"timestamp": str(datetime.now()), "results": []}
    for jar_path in jar_list:
        library_name, version = extract_jar_metadata(jar_path)
        cve_data = fetch_cve_data(library_name, version)
        report["results"].append({
            "jar_path": jar_path,
            "library_name": library_name,
            "version": version,
            "cve_count": len(cve_data),
            "cve_details": [{"cve_id": cve['cve']['id'], "description": cve['cve']['descriptions'][0]['value']} for cve in cve_data]
        })
    # Save as CSV or PDF based on output_format
Full code is in JarCVEScanner.py.

⚠️ Troubleshooting
"Module not found": Run pip install requests pandas reportlab.
"File not found": Ensure jars.txt exists with valid JAR paths.
Rate Limit Errors: Add time.sleep(12) in fetch_cve_data or use an NVD API key.
🌟 Why Use JarCVEScanner?
Open-Source: Free and customizable.
User-Friendly: No complex setup—just list your JARs and run!
Professional Output: Shareable CSV or PDF reports for teams or audits.
Future-Ready: Easily scan new libraries as your project grows.
🤝 Contributing
Love this tool? Want to make it better?

Fork the repo.
Submit a pull request with your enhancements.
Report issues or suggest features in the Issues tab.
📜 License
This project is licensed under the MIT License - see the LICENSE file for details.

🙌 Acknowledgments
Built with ❤️ by Ramjee P.
Powered by NVD for CVE data.
Special thanks to the Python community!
Ready to secure your Java projects? Star this repo and start scanning today! ⭐

text
