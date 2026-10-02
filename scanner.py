import socket
import ipaddress
import subprocess
import csv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os


PORTS_TO_SCAN = [
    22,
    53,
    80,
    443,
    445,
    3389
]

MAX_THREADS = 50
TIMEOUT = 0.5


def get_local_ip():
    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
        return local_ip

    except socket.error:
        return None


def get_network():
    local_ip = get_local_ip()

    if local_ip is None:
        return None

    network = ipaddress.ip_network(
        local_ip + "/24",
        strict=False
    )

    return network


def is_host_alive(ip):
    command = [
        "ping",
        "-n",
        "1",
        "-w",
        "500",
        str(ip)
    ]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if result.returncode == 0:
            return str(ip)

        return None

    except Exception:
        return None


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname

    except socket.herror:
        return "Unknown"


def scan_port(ip, port):
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(TIMEOUT)

    try:
        result = sock.connect_ex(
            (ip, port)
        )

        if result == 0:
            return True

        return False

    except socket.error:
        return False

    finally:
        sock.close()


def scan_host_ports(ip):
    open_ports = []

    for port in PORTS_TO_SCAN:
        if scan_port(ip, port):
            open_ports.append(port)

    return open_ports


def scan_host(ip):
    print(f"[+] Analyse de {ip}...")

    hostname = get_hostname(ip)
    open_ports = scan_host_ports(ip)

    result = {
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports
    }

    return result


def save_report(results):
    os.makedirs(
        "reports",
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    filename = f"reports/scan_{timestamp}.csv"

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP",
            "Hostname",
            "Open Ports"
        ])

        for result in results:

            ports = ", ".join(
                str(port)
                for port in result["open_ports"]
            )

            writer.writerow([
                result["ip"],
                result["hostname"],
                ports
            ])

    print()
    print(f"[+] Rapport créé : {filename}")


def main():

    print("=" * 60)
    print("             NETWORK SCANNER")
    print("=" * 60)
    print()

    network = get_network()

    if network is None:
        print("[-] Impossible de déterminer le réseau.")
        return

    print(f"[*] Réseau détecté : {network}")
    print()

    print("[*] Recherche des machines actives...")
    print()

    active_hosts = []

    with ThreadPoolExecutor(
        max_workers=MAX_THREADS
    ) as executor:

        results = executor.map(
            is_host_alive,
            network.hosts()
        )

        for result in results:

            if result is not None:

                active_hosts.append(result)

                print(
                    f"[+] Machine active : {result}"
                )

    print()

    print(
        f"[*] {len(active_hosts)} machine(s) active(s) trouvée(s)."
    )

    print()
    print("[*] Scan des ports...")
    print()

    scan_results = []

    for ip in active_hosts:

        result = scan_host(ip)

        scan_results.append(result)

    print()
    print("=" * 70)
    print("                         RESULTS")
    print("=" * 70)

    print(
        f"{'IP':<18}"
        f"{'HOSTNAME':<30}"
        f"OPEN PORTS"
    )

    print("-" * 70)

    for result in scan_results:

        ports = ", ".join(
            str(port)
            for port in result["open_ports"]
        )

        if not ports:
            ports = "None"

        print(
            f"{result['ip']:<18}"
            f"{result['hostname']:<30}"
            f"{ports}"
        )

    save_report(scan_results)

    print()
    print("=" * 70)
    print("                    SCAN TERMINÉ")
    print("=" * 70)


if __name__ == "__main__":
    main()
