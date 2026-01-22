############STILL UPDATED##############

# cloudfree-ip
This tool was design to automated finding the true real ip of a cloudflare website
# 1. Install dependencies
sudo apt update && sudo apt install -y subfinder amass httpx gowitness masscan nmap dnsutils wkhtmltopdf cutycapt

# 2. Python deps
pip3 install requests colorame
# 3. Now just download the script and run it 


# 4. How it works?
1. Capture CDN response fingerprint (MD5 hash)
2. Collect 100+ historical IPs from CRT.sh + subdomains  
3. Test EACH IP with Host:domain header
4. Match HTTP response = TRUE ORIGIN ✅
5. 95%+ bypass success rate

