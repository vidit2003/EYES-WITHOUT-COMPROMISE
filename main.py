from PIL import Image
from customtkinter import CTkImage
import customtkinter as ctk
import shodan
import csv
import re
import folium
import webbrowser
import os
import socket
import whois

# UI Theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

API_KEY = open("api_key.txt").read().strip()
ALLOWED_IPS = None  # All IPs allowed

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    return False

def resolve_domain(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        registrar = info.registrar or "N/A"
        creation = info.creation_date or "N/A"
        expiration = info.expiration_date or "N/A"
        updated = info.updated_date or "N/A"
        return f"Registrar: {registrar}\nCreated On: {creation}\nExpires On: {expiration}\nUpdated On: {updated}"
    except:
        return "Whois: Not Available"

class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Login")
        self.geometry("300x200")

        self.label_user = ctk.CTkLabel(self, text="Username")
        self.label_user.pack(pady=(20, 5))
        self.entry_user = ctk.CTkEntry(self)
        self.entry_user.pack(pady=5)

        self.label_pass = ctk.CTkLabel(self, text="Password")
        self.label_pass.pack(pady=5)
        self.entry_pass = ctk.CTkEntry(self, show="*")
        self.entry_pass.pack(pady=5)

        self.login_btn = ctk.CTkButton(self, text="Login", command=self.verify)
        self.login_btn.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.pack()

    def verify(self):
        username = self.entry_user.get()
        password = self.entry_pass.get()
        if username == "admin" and password == "@dmin":
            self.destroy()
            app = ShodanScannerApp()
            app.mainloop()
        else:
            self.status_label.configure(text="Invalid credentials!", text_color="red")

class ShodanScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Eye Without Compromise")
        self.geometry("900x700")

        img = Image.open("assets/logo.png")
        ctk_img = CTkImage(light_image=img, dark_image=img, size=(80, 80))
        self.logo = ctk.CTkLabel(self, image=ctk_img, text="")
        self.logo.pack(pady=(10, 0))

        self.label = ctk.CTkLabel(self, text="Enter IP(s) or Domain(s) (comma-separated):", font=ctk.CTkFont(size=18))
        self.label.pack(pady=10)

        self.mode_label = ctk.CTkLabel(self, text="Mode: IP/Domain Scan (Multi Supported)", font=ctk.CTkFont(size=14))
        self.mode_label.pack(pady=5)

        self.entry = ctk.CTkEntry(self, width=600, placeholder_text="e.g., 8.8.8.8, example.com")
        self.entry.pack(pady=10)

        self.button = ctk.CTkButton(self, text="Scan", command=self.run_scan)
        self.button.pack(pady=10)

        self.status = ctk.CTkLabel(self, text="Status: Ready", font=ctk.CTkFont(size=12))
        self.status.pack(pady=(0, 5))

        self.textbox = ctk.CTkTextbox(self, width=850, height=400)
        self.textbox.pack(pady=10)

        self.export_btn = ctk.CTkButton(self, text="Export to CSV", command=self.export_results)
        self.export_btn.pack(pady=5)

        self.results = []

    def run_scan(self):
        self.textbox.delete("1.0", ctk.END)
        user_inputs = self.entry.get().strip().split(',')
        user_inputs = [ip.strip() for ip in user_inputs if ip.strip()]
        self.results = []

        api = shodan.Shodan(API_KEY)
        map_obj = folium.Map(location=[20, 0], zoom_start=2)

        for user_input in user_inputs:
            ip_address = user_input if is_valid_ip(user_input) else resolve_domain(user_input)

            if not ip_address:
                self.textbox.insert(ctk.END, f"[!] Could not resolve: {user_input}\n")
                continue

            self.textbox.insert(ctk.END, f"\n--- Scanning {user_input} ({ip_address}) ---\n")
            self.status.configure(text=f"Status: Scanning {user_input}...")

            if not is_valid_ip(user_input):
                whois_info = get_whois_info(user_input)
                self.textbox.insert(ctk.END, f"[Whois Info]\n{whois_info}\n")

            try:
                host = api.host(ip_address)
                ip = host['ip_str']
                org = host.get('org', 'N/A')
                isp = host.get('isp', 'N/A')
                hostnames = ", ".join(host.get('hostnames', [])) or "N/A"
                city = host.get('city', 'N/A')
                country = host.get('country_name', 'N/A')
                latitude = host.get('latitude', 0)
                longitude = host.get('longitude', 0)

                folium.Marker(location=[latitude, longitude], popup=f"{ip} ({city}, {country})").add_to(map_obj)

                self.textbox.insert(
                    ctk.END,
                    f"IP: {ip}\nOrg: {org}\nISP: {isp}\nHostnames: {hostnames}\nLocation: {city}, {country}\nOpen Ports:\n"
                )

                weak_password_detected = False
                brute_force_detected = False
                weak_keywords = ['default', 'admin', '1234', 'password', 'test', 'guest', 'root', 'changeme', 'none']

                for item in host['data']:
                    port = item.get('port', 'N/A')
                    product = item.get('product', 'N/A')
                    banner = item.get('data', '').lower()

                    if any(keyword in banner for keyword in weak_keywords):
                        weak_password_detected = True
                        line = f" → Port: {port} | Service: {product} ⚠️ WEAK PASSWORD"
                    elif 'too many login attempts' in banner or 'brute force' in banner:
                        brute_force_detected = True
                        line = f" → Port: {port} | Service: {product} 🚨 BRUTE FORCE DETECTED"
                    else:
                        line = f" → Port: {port} | Service: {product}"

                    self.textbox.insert(ctk.END, line + "\n")
                    self.results.append([ip, port, product, org])

                if weak_password_detected:
                    self.textbox.insert(ctk.END, "[!] ⚠️ Weak passwords detected.\n")
                if brute_force_detected:
                    self.textbox.insert(ctk.END, "[!] 🚨 Brute-force activity suspected.\n")

                self.textbox.insert(ctk.END, "------------------------------\n")

            except Exception as e:
                self.status.configure(text=f"Status: ❌ Error with {user_input}")
                self.textbox.insert(ctk.END, f"[!] Error with {user_input}: {e}\n")

        self.status.configure(text="Status: ✅ Scan Complete")

        os.makedirs("results", exist_ok=True)
        map_path = os.path.abspath("results/ip_map.html")
        map_obj.save(map_path)
        self.textbox.insert(ctk.END, f"\n[+] Map saved to: {map_path}\n")
        webbrowser.open(f"file://{map_path}")

    def export_results(self):
        try:
            os.makedirs("results", exist_ok=True)
            with open("results/scan_results.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Port", "Service", "Org"])
                writer.writerows(self.results)
            self.status.configure(text="Status: ✅ Exported to scan_results.csv")
            self.textbox.insert(ctk.END, "\n[+] Results exported to 'results/scan_results.csv'.")
        except Exception as e:
            self.status.configure(text="Status: ❌ Export Error")
            self.textbox.insert(ctk.END, f"\n[!] Failed to export: {e}")

if __name__ == "__main__":
    login = LoginWindow()
    login.mainloop()
