import requests
import json
import base64
import datetime
import random
import time

# === KONFIGURASI ===
API_KEY = "4a6f496c962a6f3aac7ca0a22f8ba09514d4b450360a99212a5d90eaa66928bb"
BASE_URL = "https://api.hunter.how/search"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) Firefox/68.0",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/108.0.5359.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) Safari/604.1"
]

def build_url(query, start_time, end_time, page):
    encoded_query = base64.b64encode(query.encode()).decode()
    return f"{BASE_URL}?api-key={API_KEY}&query={encoded_query}&start_time={start_time}&end_time={end_time}&page={page}"

def fetch_page(query, start_str, end_str, page):
    url = build_url(query, start_str, end_str, page)
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    print(f"[+] Mengambil page {page}...")

    try:
        response = requests.get(url, headers=headers, timeout=30)
        data = response.json()
    except Exception as e:
        print(f"[!] Error page {page}: {e}")
        return []

    if data.get("code") != 200:
        print(f"[!] API error page {page}: {data.get('message', 'Unknown error')}")
        return []

    result_list = data.get("data", {}).get("list", [])
    result = []
    for item in result_list:
        ip = item.get("ip")
        port = item.get("port")
        if ip and port:
            result.append(f"{ip}:{port}")

    return result

def grab_all(query, start_str, end_str, max_page):
    all_results = []
    seen_ips = set()

    for page in range(1, max_page + 1):
        result = fetch_page(query, start_str, end_str, page)
        for entry in result:
            ip = entry.split(":")[0]
            if ip not in seen_ips:
                seen_ips.add(ip)
                all_results.append(entry)
        time.sleep(1)  # Delay untuk hindari "too frequent requests"

    return all_results

def main():
    query = input("Masukkan query pencarian: ").strip()
    start_input = input("Dari tanggal (YYYY-MM-DD) [kosongkan untuk default 7 hari]: ").strip()
    end_input = input("Sampai tanggal (YYYY-MM-DD) [kosongkan untuk hari ini]: ").strip()
    try:
        max_page = int(input("Ambil sampai page ke berapa? [default 10]: ").strip() or 10)
    except:
        print("[!] Jumlah page harus berupa angka.")
        return

    try:
        end_time = datetime.datetime.strptime(end_input, "%Y-%m-%d") if end_input else datetime.datetime.utcnow()
        start_time = datetime.datetime.strptime(start_input, "%Y-%m-%d") if start_input else end_time - datetime.timedelta(days=7)
    except ValueError:
        print("[!] Format tanggal salah. Gunakan YYYY-MM-DD.")
        return

    start_str = start_time.strftime("%Y-%m-%d")
    end_str = end_time.strftime("%Y-%m-%d")

    hasil = grab_all(query, start_str, end_str, max_page)

    if hasil:
        try:
            with open("Result/hunter.txt", "w") as f:
                for entry in hasil:
                    f.write(entry + "\n")
            print(f"[✓] Disimpan ke Result/hunter.txt — {len(hasil)} IP unik dari {max_page} page.")
        except Exception as e:
            print(f"[!] Gagal menyimpan file: {e}")
    else:
        print("[!] Tidak ada data disimpan.")

if __name__ == "__main__":
    main()