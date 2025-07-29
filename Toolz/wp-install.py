import requests
import os
import random
from platform import system
from multiprocessing import Pool
from requests.exceptions import RequestException, Timeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from colorama import Fore, Style, init

# Disable warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize colorama for color support in Windows terminals
init(autoreset=True)

# List of paths to scan
memek = ["wordpress/wp-admin/setup-config.php?step=1", "back/wp-admin/setup-config.php?step=1", "blog/wp-admin/setup-config.php?step=1", "home/wp-admin/setup-config.php?step=1", 
         "web/wp-admin/setup-config.php?step=1", "wp/wp-admin/setup-config.php?step=1", "site/wp-admin/setup-config.php?step=1", "html/wp-admin/setup-config.php?step=1", 
         "cms/wp-admin/setup-config.php?step=1", "public/wp-admin/setup-config.php?step=1", "new/wp-admin/setup-config.php?step=1", "old/wp-admin/setup-config.php?step=1", 
         "backup/wp-admin/setup-config.php?step=1", "oldweb/wp-admin/setup-config.php?step=1", "lama/wp-admin/setup-config.php?step=1", "v1/wp-admin/setup-config.php?step=1", 
         "v2/wp-admin/setup-config.php?step=1", "v3/wp-admin/setup-config.php?step=1", "new/wp-admin/setup-config.php?step=1", "old_website/wp-admin/setup-config.php?step=1", 
         "old_site/wp-admin/setup-config.php?step=1", "wp-admin/setup-config.php?step=1", "wp/wp-admin/setup-config.php?step=1", "wordpress/wp-admin/setup-config.php?step=1", 
         "wordpress/setup-config.php?step=1", "wp-admin/wp-content/setup-config.php?step=1", "wp-content/wp-admin/setup-config.php?step=1", "blog/wordpress/setup-config.php?step=1", 
         "blog/wp-admin/setup-config.php?step=1", "blog/wp/wp-admin/setup-config.php?step=1", "blog/wordpress/wp-admin/setup-config.php?step=1", "web/wp-admin/setup-config.php?step=1", 
         "web/wp/wp-admin/setup-config.php?step=1", "web/wordpress/wp-admin/setup-config.php?step=1", "public/wp-admin/setup-config.php?step=1", "public/wp/wp-admin/setup-config.php?step=1", 
         "public/wordpress/wp-admin/setup-config.php?step=1", "users/wp-admin/setup-config.php?step=1", "users/wordpress/wp-admin/setup-config.php?step=1", 
         "users/wp/wp-admin/setup-config.php?step=1", "data/wp-admin/setup-config.php?step=1", "data/wp/wp-admin/setup-config.php?step=1", "data/wordpress/wp-admin/setup-config.php?step=1", 
         "assets/wp-admin/setup-config.php?step=1", "assets/wp/wp-admin/setup-config.php?step=1", "assets/wordpress/wp-admin/setup-config.php?step=1", "asset/wp-admin/setup-config.php?step=1", 
         "asset/wp/wp-admin/setup-config.php?step=1", "asset/wordpress/wp-admin/setup-config.php?step=1", "wp/setup-config.php?step=1", "cms/wp-admin/setup-config.php?step=1", 
         "cms/wp/wp-admin/setup-config.php?step=1", "cms/wordpress/wp-admin/setup-config.php?step=1", "cms/wordpress/setup-config.php?step=1"]

# Load User-Agents from file
try:
    with open('user-agents.txt', 'r') as f:
        user_agents = [line.strip() for line in f.readlines() if line.strip()]
except FileNotFoundError:
    print(f'{Fore.RED}File not found: user-agents.txt{Fore.WHITE}')
    exit(1)

def clear():
    if system() in ["Linux", "Darwin"]:
        os.system("clear")
    else:
        os.system("cls")

def banner():
    print(f"""{Fore.RESET}
 _       ______     __           __        ____
| |     / / __ \   / /___  _____/ /_____ _/ / /
| | /| / / /_/ /  / / __ \/ ___/ __/ __ `/ / / 
| |/ |/ / ____/  /_/ / / (__  ) /_/ /_/ / / /  
|__/|__/_/      (_)_/ /_/____/\__/\__,_/_/_/   
""")

def main(url):
    s = requests.Session()

    for i in memek:
        ua = random.choice(user_agents)
        try:
            headerx = {
                'User-Agent': ua
            }
            r = s.get(f'http://{url}/{i}', timeout=7, verify=False, headers=headerx)
            status_code = r.status_code
            if 'label for="dbname"' in r.text and 'label for="dbhost"' in r.text:
                print(f'{Fore.GREEN}[{status_code}] {url}/{i}{Fore.WHITE} {ua}')
                with open('result_wpinstall.txt', 'a+') as f:
                    f.write(f'http://{url}/{i}\n')
            else:
                print(f'{Fore.RED}[{status_code}] {url}/{i}{Fore.WHITE} {ua}')
        except (RequestException, Timeout):
            pass  # Handle errors silently and continue

if __name__ == "__main__":
    clear()
    banner()
    memekjembut = input("Website list (Without http[s]): ")
    try:
        urls = open(memekjembut).read().splitlines()
    except FileNotFoundError:
        print(f'{Fore.RED}File not found: {memekjembut}{Fore.WHITE}')
        exit(1)
    
    p = Pool(25)
    p.map(main, urls)