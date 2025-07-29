#!/usr/bin/env python3
import os
import sys
import socket
import requests
import json
import time
import re
import threading
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

CYBER_ASCII = f"""{Fore.MAGENTA}
   ██████╗ ██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
  ██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
  ██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██╔██╗ ██║█████╔╝ 
  ██║▄▄ ██║██║   ██║██╔══██╗██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║╚██╗██║██╔═██╗ 
  ╚██████╔╝╚██████╔╝██║  ██║███████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║██║  ██╗
   ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
         {Style.RESET_ALL}
"""

def cyber_print(text, color=Fore.CYAN, delay=0.01):
    for char in text:
        print(color + char, end='', flush=True)
        time.sleep(delay)
    print(Style.RESET_ALL, end='')

def menu():
    os.system('clear')
    print(CYBER_ASCII)
    print(Fore.GREEN + "[1] OSINT Scan")
    print("[2] Port Scan (TCP/UDP, MagicNmap+)")
    print("[3] HTTP Header Analysis")
    print("[4] Banner Grab")
    print("[5] Generate Report")
    print("[6] Geolocalizzazione IP")
    print("[7] Check IPv6")
    print("[8] Server/Device Fingerprint (SSD)")
    print("[9] Magic Automazione (Auto Recon)")
    print("[10] Traceroute Magico")
    print("[0] Exit" + Style.RESET_ALL)
    cyber_print("\nSelect an option: ", Fore.YELLOW, 0.01)
    return input().strip()

def whois_lookup(target):
    cyber_print(f"\n[+] WHOIS for {target}...\n", Fore.MAGENTA)
    try:
        import whois
        w = whois.whois(target)
        return str(w)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def dns_info(target):
    cyber_print(f"\n[+] DNS Info for {target}...\n", Fore.MAGENTA)
    try:
        import dns.resolver
        answers = dns.resolver.resolve(target, 'A')
        records = [r.address for r in answers]
        return f"A records: {records}"
    except Exception as e:
        return f"DNS lookup failed: {e}"

def subdomain_scan(target):
    cyber_print(f"\n[+] Subdomain scan for {target} (quick)...\n", Fore.MAGENTA)
    common = ["www", "mail", "ftp", "dev", "test", "api", "blog"]
    found = []
    for sub in common:
        host = f"{sub}.{target}"
        try:
            socket.gethostbyname(host)
            found.append(host)
        except:
            pass
    return f"Subdomains found: {found}" if found else "No common subdomains found."

def osint_scan(target):
    result = {}
    result["whois"] = whois_lookup(target)
    result["dns"] = dns_info(target)
    result["subs"] = subdomain_scan(target)
    return result

def port_scan_tcp(target, ports, timeout=0.3, bannergrab=False):
    open_ports = []
    banners = {}
    def scan(port):
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((target, port))
            open_ports.append(port)
            if bannergrab:
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banners[port] = s.recv(1024).decode(errors='ignore')
                except:
                    banners[port] = ''
            s.close()
        except:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports, banners

def port_scan_udp(target, ports, timeout=1.0):
    import random
    open_ports = []
    def scan(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"CyberPunkScanner", (target, port))
            s.recvfrom(1024)
            open_ports.append(port)
            s.close()
        except:
            # If ICMP Port Unreachable not received, port could be open/filtered
            pass
    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports

def magic_nmap(target, auto=False):
    cyber_print(f"\n[+] MagicNmap+ Scan on {target} (TCP/UDP, banner, heuristics)...\n", Fore.MAGENTA)
    report = {}
    # TCP scan common + top ports
    tcp_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
    tcp_ports += list(range(1, 1025)) if not auto else []
    open_tcp, banners = port_scan_tcp(target, tcp_ports, bannergrab=True)
    report["open_tcp"] = open_tcp
    report["tcp_banners"] = {str(p): b for p, b in banners.items() if b}
    # UDP scan on some well-known ports
    udp_ports = [53,67,68,69,123,137,138,161,162,500,514,520]
    open_udp = port_scan_udp(target, udp_ports)
    report["open_udp"] = open_udp
    # Service guessing
    services = {}
    for p in open_tcp:
        if p == 22:
            services[p] = "SSH"
        elif p == 80 or p == 8080 or p == 8443:
            services[p] = "HTTP(S)"
        elif p == 21:
            services[p] = "FTP"
        elif p == 3389:
            services[p] = "RDP"
        elif p == 445:
            services[p] = "SMB"
        elif p == 25:
            services[p] = "SMTP"
        elif p == 110 or p == 995:
            services[p] = "POP3"
        elif p == 143 or p == 993:
            services[p] = "IMAP"
        else:
            services[p] = "Unknown"
    report["services_guess"] = services
    # Magic: Highlight risks
    risky_ports = [21,23,445,3389,5900]
    magic_hints = []
    for p in open_tcp:
        if p in risky_ports:
            magic_hints.append(f"⚠️  Port {p} ({services.get(p,'Unknown')}) è molto rischioso e spesso usato per exploit!")
    if 80 in open_tcp and 443 not in open_tcp:
        magic_hints.append("⚡ HTTP senza HTTPS, attenzione a dati in chiaro!")
    if not magic_hints:
        magic_hints.append("✅ Nessuna porta ad alto rischio tra le rilevate.")
    report["magic_hints"] = magic_hints
    return report

def http_header_analysis(target):
    url = f"http://{target}"
    cyber_print(f"\n[+] HTTP headers for {url}...\n", Fore.MAGENTA)
    try:
        r = requests.get(url, timeout=4)
        return json.dumps(dict(r.headers), indent=2)
    except Exception as e:
        return f"HTTP request failed: {e}"

def banner_grab(target):
    cyber_print(f"\n[+] Banner grab on {target}:80 ...\n", Fore.MAGENTA)
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((target, 80))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore')
        s.close()
        return f"Banner:\n{banner}"
    except Exception as e:
        return f"Banner grab failed: {e}"

def generate_report(report, fmt="txt"):
    cyber_print(f"\n[+] Generating {fmt.upper()} report...\n", Fore.MAGENTA)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        fname = f"cyberpunk_report_{ts}.json"
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
    else:
        fname = f"cyberpunk_report_{ts}.txt"
        with open(fname, "w") as f:
            for k, v in report.items():
                f.write(f"== {k.upper()} ==\n{v}\n\n")
    cyber_print(f"Report saved as {fname}\n", Fore.GREEN, 0.01)

def geolocate_ip(ip):
    cyber_print(f"\n[+] Geolocalizzazione per {ip}...\n", Fore.MAGENTA)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,org,as,query"
        r = requests.get(url, timeout=4)
        data = r.json()
        if data.get("status") == "success":
            return f"{data['country']}, {data['regionName']}, {data['city']} | Org: {data['org']} | ASN: {data['as']} | Lat: {data['lat']} | Lon: {data['lon']}"
        else:
            return f"Geoloc fallita: {data.get('message','-')}"
    except Exception as e:
        return f"Geoloc error: {e}"

def ipv6_check(target):
    cyber_print(f"\n[+] Test IPv6 per {target}...\n", Fore.MAGENTA)
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET6)
        return f"IPv6 trovato: {infos[0][4][0]}"
    except:
        return "IPv6 non trovato o non raggiungibile."

def server_fingerprint(target):
    cyber_print(f"\n[+] Server/Device fingerprinting su {target}...\n", Fore.MAGENTA)
    banner = banner_grab(target)
    headers = http_header_analysis(target)
    ssd_info = []
    if "nginx" in banner.lower() or "nginx" in headers.lower():
        ssd_info.append("Webserver: nginx")
    if "apache" in banner.lower() or "apache" in headers.lower():
        ssd_info.append("Webserver: Apache")
    if "windows" in banner.lower() or "iis" in headers.lower():
        ssd_info.append("OS: Windows/IIS")
    if "ubuntu" in banner.lower() or "debian" in banner.lower():
        ssd_info.append("OS: Linux (Ubuntu/Debian)")
    match = re.search(r"Server: ([^\r\n]+)", headers)
    if match:
        ssd_info.append(f"Header server: {match.group(1)}")
    return "\n".join(ssd_info) if ssd_info else "Nessun device/server identificato."

def traceroute_magic(target):
    cyber_print(f"\n[+] Magic Traceroute per {target}...\n", Fore.MAGENTA)
    hops = []
    max_hops = 20
    port = 33434
    ttl = 1
    try:
        dst_addr = socket.gethostbyname(target)
    except:
        return "Impossibile risolvere il target."
    while ttl <= max_hops:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        recv_socket.settimeout(2)
        recv_socket.bind(("", port))
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        send_socket.sendto(b"", (target, port))
        curr_addr = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.error:
            curr_addr = "*"
        finally:
            send_socket.close()
            recv_socket.close()
        hops.append(f"{ttl}: {curr_addr}")
        if curr_addr == dst_addr:
            break
        ttl += 1
    return "\n".join(hops)

def magic_auto_recon(target):
    cyber_print("\n✨ [MAGIC AUTO RECON] ✨\n", Fore.LIGHTMAGENTA_EX, 0.02)
    cyber_print("Avvio OSINT...\n", Fore.LIGHTCYAN_EX)
    osint = osint_scan(target)
    cyber_print("Avvio MagicNmap+ (TCP/UDP, banner)...\n", Fore.LIGHTCYAN_EX)
    magic_nmap_report = magic_nmap(target, auto=True)
    cyber_print("Analizzo header HTTP...\n", Fore.LIGHTCYAN_EX)
    headers = http_header_analysis(target)
    cyber_print("Analizzo fingerprint server/device...\n", Fore.LIGHTCYAN_EX)
    ssd = server_fingerprint(target)
    cyber_print("Geolocalizzo...\n", Fore.LIGHTCYAN_EX)
    try:
        ip = socket.gethostbyname(target)
    except:
        ip = target
    geo = geolocate_ip(ip)
    cyber_print("Check IPv6...\n", Fore.LIGHTCYAN_EX)
    ipv6 = ipv6_check(target)
    cyber_print("Traceroute magico...\n", Fore.LIGHTCYAN_EX)
    trace = traceroute_magic(target)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    big_report = {
        f"OSINT ({now})": osint,
        f"MagicNmap+ ({now})": magic_nmap_report,
        f"HTTP_HEADERS ({now})": headers,
        f"SSD-FP ({now})": ssd,
        f"GEOLOC ({now})": geo,
        f"IPV6 ({now})": ipv6,
        f"TRACEROUTE ({now})": trace
    }
    cyber_print("\n✨ Tutto fatto! Vuoi salvare il report? [y/n]: ", Fore.LIGHTMAGENTA_EX)
    ans = input().strip().lower()
    if ans == "y":
        cyber_print("Formato: [1] TXT [2] JSON: ", Fore.YELLOW)
        fmt = input().strip()
        fmt = "json" if fmt == "2" else "txt"
        generate_report(big_report, fmt)
    else:
        cyber_print("Report non salvato.\n", Fore.LIGHTMAGENTA_EX)
    cyber_print("\n✨ Fine auto-magic recon! ✨\n", Fore.LIGHTMAGENTA_EX, 0.01)

def main():
    report = {}
    cyber_print("Welcome to CYBERPUNKSCANNER\n", Fore.CYAN, 0.02)
    cyber_print("Enter target domain or IP: ", Fore.YELLOW, 0.01)
    target = input().strip()
    ip = None
    try:
        ip = socket.gethostbyname(target)
    except:
        ip = target  # maybe already an IP/IPv6
    while True:
        choice = menu()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if choice == "1":
            res = osint_scan(target)
            report[f"OSINT ({now})"] = res
            cyber_print(json.dumps(res, indent=2), Fore.CYAN, 0.003)
        elif choice == "2":
            cyber_print("\nPort scan - [1] MagicNmap+ (consigliato) [2] Personalizzato: ", Fore.YELLOW)
            sub = input().strip()
            if sub == "2":
                cyber_print("TCP/UDP? [1] TCP [2] UDP: ", Fore.YELLOW)
                proto = input().strip()
                cyber_print("Inserisci porta iniziale: ", Fore.YELLOW)
                p_start = int(input().strip())
                cyber_print("Inserisci porta finale: ", Fore.YELLOW)
                p_end = int(input().strip())
                ports = list(range(p_start, p_end+1))
                if proto == "2":
                    res = port_scan_udp(target, ports)
                    report[f"UDP_SCAN ({now})"] = res
                    cyber_print(f"Open UDP ports: {res}", Fore.LIGHTCYAN_EX, 0.003)
                else:
                    cyber_print("Banner grab? [y/n]: ", Fore.YELLOW)
                    bg = input().strip().lower() == "y"
                    openp, banners = port_scan_tcp(target, ports, bannergrab=bg)
                    report[f"TCP_SCAN ({now})"] = openp
                    if bg:
                        report[f"TCP_BANNERS ({now})"] = banners
                    cyber_print(f"Open TCP ports: {openp}", Fore.LIGHTCYAN_EX, 0.003)
                    if bg:
                        for p, b in banners.items():
                            cyber_print(f"\nPort {p}: {b}", Fore.LIGHTCYAN_EX, 0.002)
            else:
                res = magic_nmap(target)
                report[f"MagicNmap+ ({now})"] = res
                cyber_print(json.dumps(res, indent=2), Fore.LIGHTCYAN_EX, 0.003)
        elif choice == "3":
            res = http_header_analysis(target)
            report[f"HTTP_HEADERS ({now})"] = res
            cyber_print(res, Fore.CYAN, 0.003)
        elif choice == "4":
            res = banner_grab(target)
            report[f"BANNER ({now})"] = res
            cyber_print(res, Fore.CYAN, 0.003)
        elif choice == "5":
            cyber_print("Choose format: [1] TXT [2] JSON: ", Fore.YELLOW, 0.01)
            fmt = input().strip()
            fmt = "json" if fmt == "2" else "txt"
            generate_report(report, fmt)
        elif choice == "6":
            res = geolocate_ip(ip)
            report[f"GEOLOC ({now})"] = res
            cyber_print(res, Fore.CYAN, 0.003)
        elif choice == "7":
            res = ipv6_check(target)
            report[f"IPV6 ({now})"] = res
            cyber_print(res, Fore.CYAN, 0.003)
        elif choice == "8":
            res = server_fingerprint(target)
            report[f"SSD-FP ({now})"] = res
            cyber_print(res, Fore.CYAN, 0.003)
        elif choice == "9":
            magic_auto_recon(target)
        elif choice == "10":
            res = traceroute_magic(target)
            report[f"TRACEROUTE ({now})"] = res
            cyber_print(res, Fore.LIGHTCYAN_EX, 0.003)
        elif choice == "0":
            cyber_print("Bye!\n", Fore.MAGENTA, 0.01)
            break
        else:
            cyber_print("Invalid option\n", Fore.RED, 0.01)
        input(Fore.YELLOW + "\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cyber_print("\n[!] Interrupted by user.\n", Fore.RED)
        sys.exit(0)
