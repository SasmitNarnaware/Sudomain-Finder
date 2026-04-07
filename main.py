import subprocess

domain = input("Enter domain: ").replace("https://", "").replace("http://", "").split("/")[0]

#Get subdomains

print("Finding subdomains......")
with open("subdomains.txt", "w") as f:
     subprocess.run(["subfinder","-d",domain], stdout=f)

print(f"Subdomain Saved to subdomain.txt")

#Read subdomains

print("[+] Checking alive domains...")

with open("alive.txt", "w") as alive:
    subprocess.run(
        ["httpx", "-l", "subdomains.txt", "-silent"],
        stdout=alive
    )

print("[+] Alive domains saved")

with open("alive.txt","r") as f:
     subdomains = f.read().splitlines()

#Scan with Nmap

from concurrent.futures import ThreadPoolExecutor

def scan(sub):
    print(f"[+] Scanning {sub}")
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-T4", sub],
            capture_output=True,
            text=True,
            timeout=60
        )
        return f"\n===== {sub} =====\n{result.stdout}"
    except Exception as e:
        return f"\n===== {sub} FAILED =====\n{e}\n"
               

print("Done! Results saved in Scan_results.txt")