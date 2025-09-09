<img width="120" height="120" alt="logo" src="https://github.com/user-attachments/assets/00b92550-69ba-4cfa-a3df-afe20eb3aa24" /> 
 **EYES WITHOUT COMPROMISE** is a cybersecurity project built for **advanced threat detection and real-time monitoring**. It provides deep visibility into systems **without sacrificing speed or privacy**, empowering ethical hackers and security teams with reliable, uncompromised protection.

---

## ✨ Features

* **IP and Domain Scanning**: Scan single or multiple targets (comma-separated). Domains are automatically resolved to their corresponding IPs.
* **Detailed Host Information**: For each target, gathers:

  * Open ports and running services
  * Organization and ISP details
  * Associated hostnames
  * Geographical location (City, Country)
* **Vulnerability Detection**:

  * Flags services with weak or default passwords
  * Detects brute-force activity on open ports
* **Whois Lookup**: Fetch registrar, creation date, and expiration date for domain inputs.
* **Interactive Map**: Plots scanned IPs on an interactive Folium map (`ip_map.html`) that opens automatically.
* **Data Export**: Export scan results to CSV (`scan_results.csv`) for further analysis.
* **Simple Login**: Basic login window for access control.

---

## ⚙️ Prerequisites

* Python 3.x
* Shodan API Key

---

## 📦 Installation

1. Clone the repository or download the source code.

```bash
git clone https://github.com/YOUR-USERNAME/EYES-WITHOUT-COMPROMISE.git
cd EYES-WITHOUT-COMPROMISE
```

2. Install required Python libraries:

```bash
pip install -r requirements.txt
```

**requirements.txt** content:

```
customtkinter
shodan
Pillow
folium
python-whois
```

3. Set up your Shodan API Key:

   * Create a file named `api_key.txt` in the project directory.
   * Paste your Shodan API key into it.

4. Place assets:

   * Create an `assets/` folder.
   * Place your logo as `logo.png` inside it.

---

## ▶️ How to Run

```bash
python main.py
```

Login credentials:

* **Username:** admin
* **Password:** @dmin

After successful login, the main application window will appear.

---

## 🚀 Usage

1. **Enter Targets**: Type IPs or domains (comma-separated, e.g., `8.8.8.8, example.com, 9.9.9.9`).
2. **Start Scan**: Click **Scan** to begin. Results appear in real-time in the main text area.
3. **View Results**:

   * Scan details in the text area
   * Interactive map automatically generated at `results/ip_map.html` and opens in browser
4. **Export Data**: Click **Export to CSV** to save scan results at `results/scan_results.csv`.

---

## 📂 File Structure

```
├── assets/
│   └── logo.png
├── results/
│   ├── ip_map.html       (Generated after scan)
│   └── scan_results.csv  (Generated after export)
├── api_key.txt
├── main.py
├── requirements.txt
└── README.md
```

---

## ⚠️ Disclaimer

This tool is for **educational and ethical testing purposes only**. Use responsibly and **only on systems you own or have permission to test**.


if you want, i can **also add some badges** (like Python version, license, GitHub stars) at the top to make it look **even more pro**. do you want me to do that?
