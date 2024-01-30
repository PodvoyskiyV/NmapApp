import re
import subprocess
import os
import platform
import datetime

operating_system = platform.system()


def get_quarter():
    print("\033[1;34mWhich quarter's scan do you want to run?\033[0m")
    print("\033[1;36mQ1\033[0m - January, February, March")
    print("\033[1;36mQ2\033[0m - April, May, June")
    print("\033[1;36mQ3\033[0m - July, August, September")
    print("\033[1;36mQ4\033[0m - October, November, December")
    quarter = input("Enter Q1, Q2, Q3, or Q4: ").upper()
    return quarter


def get_subnet():
    print("\n\033[1;34mEnter the IP subnet for scanning (e.g., 192.168.1.0/24):\033[0m")
    subnet = input("IP subnet: ")
    return subnet


def networks_from_file(subnet):
    nets = {}

    with open('Networks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if subnet in line:
                key, value = map(str.strip, line.split(':'))
                nets[key] = value
                name = line.split(':')[0].strip()
                print(name)
                return name
        return None


def confirm_subnet(subnet):
    found_subnet = networks_from_file(subnet)
    if found_subnet:
        print(f"\n\033[1;32mFound subnet:\033[0m {found_subnet}")
        confirm = input("Is this the correct subnet? (yes/no): ").lower()
        if confirm == "yes" or confirm == "y":
            return True, found_subnet
    print(f"\n\033[1;31mSubnet '{subnet}' not found. Please update the Networks.txt file.\033[0m")
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
        print(f"Директория '{directory_path}' успешно создана.")
    else:
        print(f"Директория '{directory_path}' уже существует.")


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
        print(live_hosts)
        return live_hosts
    else:
        # Если команда завершилась с ошибкой, выводим сообщение об ошибке
        print("Ошибка выполнения команды nmap:")
        print(result.stderr)
        return []


def NmapApp():
    quarter = get_quarter()
    subnet = get_subnet()
    confirm, network_name = confirm_subnet(subnet)
    if confirm:
        start_time = datetime.datetime.now()
        create_directory(quarter, network_name)
        live_hosts = scan_for_live_hosts(subnet)
        print(f"Number of IPs: {len(live_hosts)}")
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
                report_path = f'D:\\NmapApp\ScanResults\{year}\{quarter}\{network_name}\{host}.txt'
                nmap_command = fr'C:\"Program Files (x86)"\Nmap\nmap.exe -sV --script vulners {host} > nmap_report.txt'
            else:
                report_path = f'/data/NmapScanResults/{year}/{quarter}/{network_name}/{host}.txt'
                nmap_command = f"nmap -sV --script vulners {host} > nmap_report.txt"

            subprocess.run(nmap_command, shell=True, check=True)
            vulnerabilities, vul = parse_nmap_report('nmap_report.txt')
            if vul:
                sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: x['score'], reverse=True)
                create_report(sorted_vulnerabilities, report_path, counters)
            else:
                create_report(vulnerabilities, report_path)
            counter += 1
            progress = counter / len(live_hosts) * 100
            print(f"Progress: {progress:.2f}%")

        end_time = datetime.datetime.now()
        duration = end_time - start_time
        print("Duration of scan:", duration)


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
    NmapApp()
