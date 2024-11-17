import socket
import requests
import re
import time
import os

#os.system('pip install socket')
#os.system('pip install requests')
#os.system('pip install re')
#os.system('pip install time')
#os.system('pip3 install os')
#os.system('apt update')
print('\x1b[38;5;220m%'*50)
logo='''

\x1b[38;5;220m┈┈┈┈╱▔▔▔▔╲┈┈┈┈
┈┈┈▕▕╲┊┊╱▏▏┈┈┈
┈┈┈▕▕▂╱╲▂▏▏┈┈┈
┈┈┈┈╲┊┊┊┊╱┈┈┈┈
┈┈┈┈▕╲▂▂╱▏┈┈┈┈
╱▔▔▔▔┊┊┊┊▔▔▔▔╲

\x1b[38;5;5m
█▀▀ █▄█ █▄▄ █▀▀ █▀█
█▄▄ ░█░ █▄█ ██▄ █▀▄



\x1b[38;5;226m[+] 𝙵𝚊𝚌𝚎𝚋𝚘𝚘𝚔 : 𝙲𝚈𝙱𝙴𝚁

\x1b[1;31m[+] 𝙶𝚒𝚝𝚑𝚞𝚋 : ʜᴛᴛᴘs://ɢɪᴛʜᴜʙ.ᴄᴏᴍ/Mʀ-ᴇʟʜᴀ

ＶＥＲＳＩＯＮ ： １.１

\x1b[38;5;46m[+] ᴵⁿᶠᵒʳᵐᵃᵗⁱᵒⁿ⠘ ᵀʰⁱˢ ᵗᵒᵒˡ ᶜᵃⁿ ᵉˣᵗʳᵃᶜᵗ ˢᵉⁿˢⁱᵗⁱᵛᵉ ⁱⁿᶠᵒʳᵐᵃᵗⁱᵒⁿ ᵃᵇᵒᵘᵗ ʷᵉᵇˢⁱᵗᵉˢ ˢᵘᶜʰ ᵃˢ ᴵᴾ ᵃᵈᵈʳᵉˢˢ⸴ ᵒᵖᵉⁿ ᵖᵒʳᵗˢ⸴ ᴰᴺᔆ⸴ ᵃⁿᵈ ᵒᵗʰᵉʳ ⁱⁿᶠᵒʳᵐᵃᵗⁱᵒⁿ‧
'''

print (logo)
print('\x1b[38;5;220m%'*50)
time.sleep(4)

os.system('clear')

# Define color codes
A = "\x1b[0;90m"  # Black
B = "\x1b[38;5;196m"  # Red
C = "\x1b[38;5;46m"  # Green
D = "\x1b[38;5;226m"  # Yellow
E = "\x1b[38;5;44m"  # Blue
F = "\x1b[38;5;231m"  # White
xxh = '\x1b[38;5;208m'  # Orange
m1 = '\x1b[38;5;196m'  # Red


logo='''
\x1b[38;5;46m
┈┈┈╲┈┈┈┈╱
┈┈┈╱▔▔▔▔╲
┈┈┃┈▇┈┈▇┈┃
╭╮┣━━━━━━┫╭╮
┃┃┃┈┈┈┈┈┈┃┃┃
╰╯┃┈┈┈┈┈┈┃╰╯
┈┈╰┓┏━━┓┏╯
┈┈┈╰╯┈┈╰╯
\x1b[38;5;226m 

▀█▀ ▒█▄░▒█ ▒█▀▀▀ ▒█▀▀▀█ 
▒█░ ▒█▒█▒█ ▒█▀▀▀ ▒█░░▒█ 
▄█▄ ▒█░░▀█ ▒█░░░ ▒█▄▄▄█
                                                          

'''
print (logo)


PORT_SERVICE_MAP = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    8080: "HTTP Alt",
}

def get_open_ports(target_ip):
    open_ports = []
    for port in range(1, 1024):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target_ip, port)) == 0:
                open_ports.append(port)
                print(f"{C}Port: {port} - Service: {get_port_service(port)}{F}")  # Changed to green
    return open_ports

def get_port_service(port):
    return PORT_SERVICE_MAP.get(port, "Unknown Service")

def get_dns_info(target_ip):
    hostname = socket.gethostbyaddr(target_ip)[0]
    dns_servers = socket.gethostbyname_ex(hostname)[2]
    return {
        "hostname": hostname,
        "ip_address": target_ip,
        "dns_servers": dns_servers,
    }

def get_whois_info(target_ip):
    response = requests.get(f"https://whois.domaintools.com/{target_ip}")
    whois_info = re.findall(r"(\+): (.+)", response.text)
    return dict(whois_info)

def get_additional_info(target_ip):
    try:
        response = requests.get(f"https://api.hackertarget.com/whoisapi/?q={target_ip}")
        additional_info = response.json()
        return {
            "creation_date": additional_info.get('created', 'N/A'),
            "programming_language": additional_info.get('language', 'N/A'),
            "server_info": additional_info.get('server', 'N/A'),
        }
    except Exception:
        return {
            "creation_date": "N/A",
            "programming_language": "N/A",
            "server_info": "N/A",
        }

def check_sql_injection(target_url):
    payload = "' OR '1'='1"
    try:
        response = requests.get(f"{target_url}/?id={payload}")
        if "SQL" in response.text or "error" in response.text.lower():
            print(f"{C}✅ Potential SQL Injection vulnerability detected on {target_url}{F}")
        else:
            print(f"{B} ❌ No SQL Injection vulnerability found on {target_url}{F}")
    except Exception as e:
        print(f"{B}Error checking SQL Injection: {str(e)}{F}")

def main():
    target_url = input(xxh + "Enter the Website URL : " + C)

    print(m1 + "Fetching information, please wait...")
    time.sleep(1)

    print(f"{D}--- Open Ports ---{F}")
    target_ip = socket.gethostbyname(target_url.replace("http://", "").replace("https://", "").strip("/"))
    open_ports = get_open_ports(target_ip)

    print(f"\n{D}--- DNS Information ---{F}")
    dns_info = get_dns_info(target_ip)
    print(f"{C}Hostname: {dns_info['hostname']}{F}")
    print(f"{C}IP Address: {dns_info['ip_address']}{F}")
    print(f"{C}DNS Servers: {', '.join(dns_info['dns_servers'])}{F}")

    print(f"\n{D}--- WHOIS Information ---{F}")
    whois_info = get_whois_info(target_ip)
    for key, value in whois_info.items():
        print(f"{C}{key}: {value}{F}")

    print(f"\n{D}--- Additional Information ---{F}")
    additional_info = get_additional_info(target_ip)
    print(f"{C}Creation Date: {additional_info['creation_date']}{F}")
    print(f"{C}Programming Language: {additional_info['programming_language']}{F}")
    print(f"{C}Server Info: {additional_info['server_info']}{F}")

    # Check for SQL injection vulnerability
    check_sql_injection(target_url)

if __name__ == "__main__":
    main()
print(' ')
print(' ')
print(' ')
print (E+'\t\t BY MR-ELHA')
