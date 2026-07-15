import subprocess
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

BANNER = r"""
  _   _       _    __ _           _ 
 | | | | __ _| |_ / _(_)_ __   __| |
 | |_| |/ _` | __| |_| | '_ \ / _` |
 |  _  | (_| | |_|  _| | | | | (_| |
 |_| |_|\__,_|\__|_| |_|_| |_|\__,_|
"""
print("\033[96m" + BANNER + "\033[0m")
print("\033[92m[*] Advanced Reconnaissance Tool\033[0m")
print("-" * 40)

while True:
    user_input = input("\033[93mEnter domain (or '-h' for help, 'q' to quit):\033[0m ").strip()
    
    if user_input.lower() == 'q':
        print("\033[91mExiting Hatfind...\033[0m")
        sys.exit(0)
    elif user_input.lower() == '-h' or user_input.lower() == 'help':
        print("\n\033[96m[?] Hatfind Help\033[0m")
        print("Hatfind is an automated reconnaissance pipeline that:")
        print("  - Finds subdomains using subfinder")
        print("  - Checks alive domains, grabs screenshots, and detects tech using httpx")
        print("  - Crawls for active and historical endpoints using katana and gau")
        print("  - Scans alive targets for open ports using nmap")
        print("  - Exports all findings into a centralized 'results.json' file\n")
        continue
    elif not user_input:
        continue
    else:
        domain = user_input.replace("https://", "").replace("http://", "").split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        break

results = {
    "domain": domain,
    "subdomains": {}
}

# 1. Get subdomains
print(f"[+] Finding subdomains for {domain}......")
with open("subdomains.txt", "w") as f:
    subprocess.run(["subfinder", "-d", domain], stdout=f)
print("[+] Subdomains saved to subdomains.txt")

# 2. Httpx (Alive, titles, tech, headers)
print("[+] Checking alive domains, taking screenshots, detecting tech, and collecting headers...")
httpx_cmd = [
    "httpx", "-l", "subdomains.txt", "-silent", 
    "-screenshot", "-title", "-tech-detect", 
    "-server", "-web-server", "-status-code", "-json"
]

httpx_result = subprocess.run(httpx_cmd, capture_output=True, text=True)

# Handle Windows Defender blocking leakless.exe (used by httpx for screenshots)
if httpx_result.returncode != 0:
    print("\033[93m[!] Error running httpx with screenshots (likely Windows Defender blocking headless chromium). Retrying without screenshots...\033[0m")
    httpx_cmd.remove("-screenshot")
    httpx_result = subprocess.run(httpx_cmd, capture_output=True, text=True)

for line in httpx_result.stdout.splitlines():
    if not line.strip(): continue
    try:
        data = json.loads(line)
        sub = data.get("host", "")
        if not sub: continue
        
        # Ensure we can safely parse headers (httpx may use 'header' or 'headers')
        header_raw = data.get("headers", data.get("header", {}))
        headers = {str(k).lower(): v for k, v in header_raw.items()} if isinstance(header_raw, dict) else {}
        
        results["subdomains"][sub] = {
            "url": data.get("url"),
            "ip": data.get("a", [""])[0] if data.get("a") else "",
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "web_server": data.get("webserver"),
            "technologies": data.get("tech", []),
            "csp": headers.get("content-security-policy", ""),
            "hsts": headers.get("strict-transport-security", ""),
            "x_frame_options": headers.get("x-frame-options", ""),
            "urls": [],
            "js_files": [],
            "nmap_scan": ""
        }
        
        # Fallback for IP if not returned by httpx
        if not results["subdomains"][sub]["ip"]:
            try:
                results["subdomains"][sub]["ip"] = socket.gethostbyname(sub)
            except Exception:
                pass
                
    except json.JSONDecodeError:
        pass

print(f"[+] Processed {len(results['subdomains'])} alive domains")

# 3. Analyze each alive subdomain (Nmap, Gau, Katana)
alive_subs = list(results["subdomains"].keys())

def analyze_subdomain(sub):
    info = results["subdomains"][sub]
    url = info.get("url", f"https://{sub}")
    
    urls = []
    
    # Katana for crawling
    try:
        print(f"[+] Crawling {url} with Katana")
        katana_res = subprocess.run(
            ["katana", "-u", url, "-silent"], 
            capture_output=True, text=True, timeout=120
        )
        urls.extend(katana_res.stdout.splitlines())
    except Exception:
        pass
        
    # Gau for historical URLs
    try:
        print(f"[+] Gathering history for {sub} with Gau")
        gau_res = subprocess.run(
            ["gau", sub], 
            capture_output=True, text=True, timeout=120
        )
        urls.extend(gau_res.stdout.splitlines())
    except Exception:
        pass
        
    # Deduplicate URLs
    urls = sorted(list(set([u for u in urls if u.strip()])))
    info["urls"] = urls
    
    # Filter for JS files
    info["js_files"] = [u for u in urls if ".js" in u]
    
    # Nmap scan
    try:
        print(f"[+] Scanning {sub} with Nmap")
        nmap_res = subprocess.run(
            ["nmap", "-sV", "-T4", sub],
            capture_output=True,
            text=True,
            timeout=120
        )
        info["nmap_scan"] = nmap_res.stdout.strip()
    except Exception as e:
        info["nmap_scan"] = f"FAILED: {e}"

with ThreadPoolExecutor(max_workers=5) as executor:
    list(executor.map(analyze_subdomain, alive_subs))

# 4. Export everything to JSON
with open("results.json", "w") as f:
    json.dump(results, f, indent=4)

print("[+] Done! All results saved in results.json")