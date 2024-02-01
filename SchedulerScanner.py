import re
import subprocess
import os
import platform
import datetime
import sys

operating_system = platform.system()


def get_quarter():
    now = datetime.datetime.now()
    month = now.month

    if 1 <= month <= 3:
        return "Q1"
    elif 4 <= month <= 6:
        return "Q2"
    elif 7 <= month <= 9:
        return "Q3"
    else:
        return "Q4"


def networks_from_file(subnet):
    nets = {}

    with open('Networks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if subnet in line:
                key, value = map(str.strip, line.split(':'))
                nets[key] = value
                name = line.split(':')[0].strip()
                return name
        return None


def confirm_subnet(subnet):
    found_subnet = networks_from_file(subnet)
    if found_subnet:
        with open("/data/NmapApp/nmap_log", 'a') as log:
            log.write(f"Subnet {found_subnet} found\n")
        return True, found_subnet
    with open("/data/NmapApp/nmap_log", 'a') as log:
        log.write(f"\n\033[1;31mSubnet '{subnet}' not found. Please update the Networks.txt file.\033[0m\n")
    return False


def create_directory(quarter, network):
    current_date = datetime.datetime.now()
    year = current_date.year
    # Определяем путь для создания директории в зависимости от операционной системы
    if operating_system == 'Windows':
        directory_path = f'D:\\NmapApp\ScanResults\{year}\{quarter}\{network}'
    else:
        directory_path = f'/data/NmapScanResults/{year}/{quarter}/{network}'

    # Проверяем, существует ли директория, и создаем её, если не существует
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        with open("/data/NmapApp/nmap_log", 'a') as log:
            log.write(f"The directory '{directory_path}' was created successfully.")
    else:
        with open("/data/NmapApp/nmap_log", 'a') as log:
            log.write(f"The directory '{directory_path}' already exists.")


def scan_for_live_hosts(ip_range):
    if operating_system == 'Windows':
        command = fr'C:\Program Files (x86)\Nmap\nmap.exe -sn {ip_range}'
    else:
        command = ["nmap", "-sn", ip_range]
    result = subprocess.run(command, capture_output=True, text=True)

    # Проверяем, завершилась ли команда успешно
    if result.returncode == 0:
        # Разделяем вывод на строки и создаем список
        data = result.stdout.strip().split('\n')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        live_hosts = ip_pattern.findall(' '.join(data))
        with open("/data/NmapApp/nmap_log", 'w') as log:
            for host in live_hosts:
                log.write(f"{host}\n")
        return live_hosts
    else:
        with open("/data/NmapApp/nmap_log", 'a') as log:
            log.write(f"Nmap command error: {result.stderr}\n")
        return []


def NmapApp():
    quarter = get_quarter()
    with open("/data/NmapApp/Schedule.txt", 'r') as networks_file:
        networks = networks_file.readlines()[1:]
    for network in networks:
        subnet = network.strip()
        confirm, network_name = confirm_subnet(subnet)
        if confirm:
            start_time = datetime.datetime.now()
            create_directory(quarter, network_name)
            live_hosts = scan_for_live_hosts(subnet)

            with open("/data/NmapApp/nmap_log", 'a') as log:
                log.write(f"Number of IPs: {len(live_hosts)}\n")

            counter = 0

            for host in live_hosts:
                counters: dict[str, int] = {
                    "Low": 0,
                    "Medium": 0,
                    "High": 0,
                    "Critical": 0
                }
                current_date = datetime.datetime.now()
                year = current_date.year
                if operating_system == 'Windows':
                    report_path = f'D:\\ScanResultsNmap\{year}\{quarter}\{network_name}\{host}.txt'
                    nmap_command = fr'C:\"Program Files (x86)"\Nmap\nmap.exe -sV --script vulners {host} > \
                    nmap_report.txt'
                else:
                    report_path = f'/data/ScanResultsNmap/{year}/{quarter}/{network_name}/{host}.txt'
                    nmap_command = f"sudo nmap -sV --script vulners {host} > nmap_report.txt"

                subprocess.run(nmap_command, shell=True, check=True)
                vulnerabilities, vul = parse_nmap_report('nmap_report.txt')
                if vul:
                    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: x['score'], reverse=True)
                    create_report(sorted_vulnerabilities, report_path, counters)
                else:
                    create_report(vulnerabilities, report_path)
                counter += 1
                progress = counter / len(live_hosts) * 100
                with open("/data/NmapApp/nmap_log", 'a') as log:
                    log.write(f"Progress: {progress:.2f}%\n")

                end_time = datetime.datetime.now()
                duration = end_time - start_time

                with open("/data/NmapApp/nmap_log", 'a') as log:
                    log.write(f"Duration of scan: {duration}\n")


def get_risk_category(score, counters):
    if 0.1 <= score <= 3.9:
        counters['Low'] += 1
        return "Low"
    elif 4.0 <= score <= 6.9:
        counters['Medium'] += 1
        return "Medium"
    elif 7.0 <= score <= 8.9:
        counters['High'] += 1
        return "High"
    elif 9.0 <= score <= 10.0:
        counters['Critical'] += 1
        return "Critical"
    else:
        return "Unknown"


def parse_nmap_report(report_path):
    vulnerabilities = []
    current_host = None
    current_port = None
    current_service = None

    with open(report_path, 'r') as file:
        for line in file:
            line = line.strip()

            # Поиск информации о хосте
            if line.startswith("NmapApp scan report for"):
                current_host = line.split()[-1]
            # Поиск информации о порте и сервисе
            elif re.match(r"^\d+\/\w+", line):
                parts = line.split()
                current_port = parts[0]
                current_service = parts[2]
            # Поиск уязвимостей
            elif line.startswith("|") and "*EXPLOIT*" not in line:
                match = re.match(r"\|\s+(.+)\s+(\d+\.\d+)\s+(https:\/\/vulners\.com\/.+)$", line)
                if match:
                    vulnerability = {
                        'host': current_host,
                        'port': current_port,
                        'service': current_service,
                        'name': match.group(1),
                        'score': float(match.group(2)),
                        'link': match.group(3)
                    }
                    vulnerabilities.append(vulnerability)
    if vulnerabilities:
        return vulnerabilities, True
    else:
        with open(report_path, 'r') as file:
            for line in file:
                vulnerabilities.append(line.strip())
            return vulnerabilities, False


def create_report(vulnerabilities, output_file, counters):
    with open(output_file, 'w') as file:
        for vulnerability in vulnerabilities:
            risk = get_risk_category(vulnerability['score'], counters)
            file.write(f"Host: {vulnerability['host']}\n")
            file.write(f"Port: {vulnerability['port']}\n")
            file.write(f"Service: {vulnerability['service']}\n")
            file.write(f"Vulnerability: {vulnerability['name']}\n")
            file.write(f"Score: {vulnerability['score']} (Risk: {risk})\n")
            file.write(f"Link: {vulnerability['link']}\n")
            file.write("-" * 50 + "\n")
    with open(output_file, 'r') as file:
        current_content = file.read()
    with open(output_file, 'w') as file:
        if vulnerabilities:
            file.write(f"Host: {vulnerabilities[0]['host']}\n")
            file.write(f"Critical: {counters['Critical']}\n")
            file.write(f"High: {counters['High']}\n")
            file.write(f"Medium: {counters['Medium']}\n")
            file.write(f"Low: {counters['Low']}\n")
            file.write(
                f"Summary: {counters['Critical'] + counters['High'] + counters['Medium'] + counters['Low']}\n")
            file.write("-" * 50 + "\n")
            file.write(current_content)


def create_report(vulnerabilities, output_file):
    with open(output_file, 'w') as file:
        for vulnerability in vulnerabilities:
            file.write(vulnerability + "\n")


if __name__ == "__main__":
    try:
        current_time = datetime.datetime.now()
        time_str = current_time.strftime("%Y-%m-%d %H:%M:%S")
        with open("/data/NmapApp/nmap_log", 'w') as log:
            log.write(f"Scaner started in {time_str}\n")
        NmapApp()
        with open("/data/NmapApp/nmap_log", 'a') as log:
            log.write(f"Scaner finished in {time_str}\n")
        with open('/data/NmapApp/Schedule.txt', 'w') as schedule:
            schedule.write("# Example of IP: 192.168.1.0/24")
    except Exception as e:
        with open('/data/NmapApp/nmap_log', 'a') as f:
            print(f'Ошибка: {e}', file=f)
