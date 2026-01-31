import socket
import ssl
import ipaddress
import concurrent.futures
import time
import os
import ctypes
import threading
import sys
import re
from colorama import init, Fore, Style

init(autoreset=True)
PRINT_LOCK = threading.Lock()

CF_IP_LIST = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "1.1.1.0/24", "1.0.0.0/24"
]
CF_NETWORKS = [ipaddress.ip_network(net) for net in CF_IP_LIST]

def is_upstream(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in CF_NETWORKS:
            if ip_obj in network: return "PUBLIC"
        return "UPSTREAM"
    except: return "UNKNOWN"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def set_title(title):
    if os.name == 'nt': ctypes.windll.kernel32.SetConsoleTitleW(title)

def check_logic(ip, port, sni, host):
    try:
        start_time = time.perf_counter()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                ssock.sendall(request.encode())
                response = ssock.recv(1024).decode(errors='ignore')
                latency = int((time.perf_counter() - start_time) * 1000)
                ws_status = "WS:OK" if ("101" in response or "Switching Protocols" in response) else "WS:NO"
        return True, latency, f"TLS:OK | {ws_status}"
    except: return False, None, None

def generate_configs(found_ips, template):
    configs = []
    try:
        part_before_at = template.split('@')[0] + '@'
        remaining = template.split('@')[1]
        part_after_addr = ':' + ':'.join(remaining.split(':')[1:])
        for h in found_ips:
            ip = h['ip']
            new_link = part_before_at + ip + part_after_addr
            if "#" in new_link:
                base = new_link.split("#")[0]
                new_link = f"{base}#{ip}_V3R"
            else:
                new_link += f"#{ip}_V3R"
            configs.append(new_link)
    except: raise Exception("INVALID CONFIG FORMAT")
    return configs

def main():
    try:
        clear_screen()
        set_title("VIP3R & NIMA - CF AND GENR")
        print(Fore.MAGENTA + Style.BRIGHT + r"""
        __      _______ _____ ____  _____     _____  _____ 
        \ \    / /_   _|  __ \___ \|  __ \   / ____|/ ____|
         \ \  / /  | | | |__) |__) | |__) | | (___ | |     
          \ \/ /   | | |  ___/|__ <|  _  /   \___ \| |     
           \  /   _| |_| |    ___) | | \ \   ____) | |____ 
            \/   |_____|_|   |____/|_|  \_\ |_____/ \_____|
        """)
        print(Fore.CYAN + "       GITHUB.COM/CY33R | VIP3R & NIMA CONFIG CF AND GENR")
        print(Fore.WHITE + "    ===================================================")

        user_range = input(Fore.YELLOW + " > IP RANGE: ").strip()
        try:
            network = ipaddress.ip_network(user_range, False)
            ips = [str(ip) for ip in network]
            print(Fore.CYAN + f" [!] THIS RANGE CONTAINS {len(ips)} IPS.")
        except: return print(Fore.RED + "[!] INVALID RANGE")

        limit_input = input(Fore.YELLOW + f" > HOW MANY IPS TO SCAN? (MAX {len(ips)} / ENTER FOR ALL): ").strip()
        limit = int(limit_input) if limit_input.isdigit() else len(ips)
        scan_list = ips[:limit]

        target_sni = input(Fore.YELLOW + " > SNI (DEFAULT: WWW.SPEEDTEST.NET): ").strip() or "www.speedtest.net"
        target_host = input(Fore.YELLOW + " > HOST (DEFAULT: WWW.SPEEDTEST.NET): ").strip() or "www.speedtest.net"
        port_input = input(Fore.YELLOW + " > PORT (DEFAULT 443): ").strip()
        target_port = int(port_input) if port_input.isdigit() else 443

        print(f"\n{Fore.MAGENTA}[+] STARTING SCAN | TARGET: {len(scan_list)} | PORT: {target_port}")
        head = f"{'IP ADDRESS':<18} | {'LATENCY':<8} | {'TYPE':<10} | {'STATUS'}"
        print(Fore.YELLOW + "=" * 70)
        print(Fore.YELLOW + head)
        print(Fore.YELLOW + "-" * 70)

        found_list = []
        processed = 0
        
        def worker(ip):
            nonlocal processed
            success, ping, status = check_logic(ip, target_port, target_sni, target_host)
            with PRINT_LOCK:
                processed += 1
                set_title(f"VIP3R | {processed}/{len(scan_list)} | HITS: {len(found_list)}")
                if success:
                    ip_type = is_upstream(ip)
                    found_list.append({'ip': ip, 'ping': ping, 'type': ip_type, 'status': status})
                    p_str = f"{ping}MS"
                    p_color = Fore.GREEN if ping < 250 else (Fore.YELLOW if ping < 600 else Fore.RED)
                    t_color = Fore.CYAN if ip_type == "UPSTREAM" else Fore.WHITE
                    sys.stdout.write(f"{Fore.GREEN}[HIT] {Fore.WHITE}{ip:<12} | "
                                     f"{p_color}{p_str:>8}{Fore.WHITE} | "
                                     f"{t_color}{ip_type:<10}{Fore.WHITE} | "
                                     f"{Fore.GREEN}{status.upper()}\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(worker, scan_list)

        if found_list:
            sorted_hits = sorted(found_list, key=lambda x: x['ping'])
            print(Fore.GREEN + f"\n [✔] SCAN FINISHED. {len(found_list)} HITS FOUND.")
            
            # STEP 1: ASKING TO SAVE SCAN RESULTS
            print(Fore.CYAN + " > DO YOU WANT TO SAVE SCAN RESULTS TO FILE? (Y/N)")
            save_choice = sys.stdin.readline().strip().upper()
            if save_choice == 'Y':
                with open("found_upstreams.txt", "w", encoding="utf-8") as f:
                    f.write(f"GITHUB.COM/CY33R | VIP3R & NIMA SCANNER\n")
                    for h in sorted_hits:
                        f.write(f"{h['ip']:<18} | {h['ping']:>5}MS | {h['type']:<10} | {h['status'].upper()}\n")
                print(Fore.GREEN + " [✔] RESULTS SAVED IN 'found_upstreams.txt'")

            # STEP 2: GENERATING V2RAY CONFIGS
            print(Fore.CYAN + "\n > DO YOU WANT TO GENERATE V2RAY CONFIGS? (Y/N)")
            if sys.stdin.readline().strip().upper() == 'Y':
                print(Fore.YELLOW + " [!] PASTE YOUR SAMPLE CONFIG AND PRESS ENTER:")
                user_template = sys.stdin.readline().strip()
                if user_template:
                    try:
                        final_configs = generate_configs(sorted_hits, user_template)
                        with open("V2RAY_CONFIGS.txt", "w", encoding="utf-8") as cf:
                            cf.write("\n".join(final_configs))
                        print(Fore.GREEN + f" [✔] {len(final_configs)} CONFIGS SAVED IN 'V2RAY_CONFIGS.TXT'")
                    except Exception as e: print(Fore.RED + f" [!] ERROR: {e}")

        print(Fore.WHITE + "\n ALL TASKS COMPLETED.")
        input(" PRESS ENTER TO EXIT...")
    except KeyboardInterrupt: sys.exit()

if __name__ == "__main__":
    main()
