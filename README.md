# EYES-WITHOUT-COMPROMISE
EYES WITHOUT COMPROMISE is a cybersecurity project built for advanced threat detection and real-time monitoring. It provides deep visibility into systems without sacrificing speed or privacy, empowering ethical hackers and security teams with reliable, uncompromised protection.

Features
IP and Domain Scanning: Scan single or multiple targets (comma-separated) at once. The application automatically resolves domain names to their corresponding IP addresses.
Detailed Host Information: Gathers comprehensive data for each target, including:
Open ports and running services.
Organization and ISP details.
Associated hostnames.
Geographical location (City, Country).
Vulnerability Detection:
Flags services that might be using weak or default passwords.
Detects signs of brute-force activity on open ports.
Whois Lookup: For domain inputs, it performs a Whois query to fetch registrar, creation date, and expiration date.
Interactive Map: Plots the geographical location of all scanned IPs on an interactive Folium map (ip_map.html), which is automatically generated and opened.
Data Export: Allows you to export the scan results into a CSV file (scan_results.csv) for further analysis.
Simple Login: Features a basic login window for access control.

Prerequisites
Python 3.x
A Shodan API Key

Installation
Clone the repository or download the source code.
Install the required Python libraries:

pip install -r requirements.txt

You will need to create a requirements.txt file with the following content:customtkinter

shodan
Pillow
folium
python-whois

Set up your Shodan API Key:
Create a file named api_key.txt in the same directory as main.py.
Paste your Shodan API key into this file and save it.
Place assets:
Create an assets folder in the root directory.
Place your application logo named logo.png inside this folder.

How to Run
Execute the main.py script from your terminal:
python main.py

You will be prompted with a login window. Use the following credentials:
Username: admin
Password: @dminAfter 
successful login, the main application window will appear.

UsageEnter Targets: In the input field, type the IP addresses or domain names you want to scan. For multiple targets, separate them with a comma (e.g., 8.8.8.8, example.com, 9.9.9.9).
Start Scan: Click the "Scan" button to begin. The application will display real-time status and results in the textbox.
View Results:
Scan details will appear in the main text area.
An interactive map showing the location of the scanned IPs will be automatically created, saved as results/ip_map.html, and opened in your default web browser.
Export Data: Click the "Export to CSV" button to save the collected port and service information to results/scan_results.csv.
File Structure.
├── assets/
│   └── logo.png
├── results/
│   ├── ip_map.html       (Generated after scan)
│   └── scan_results.csv  (Generated after export)
├── api_key.txt
├── main.py
└── requirements.txt
