import re
import subprocess
import os
import platform
import sys
import datetime
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QComboBox, \
    QStackedWidget, QProgressBar
from PyQt5.QtCore import Qt, QTimer, QDateTime

operating_system = platform.system()


class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()

        self.selected_quarter = None
        self.selected_subnet = None

        self.init_ui()

    def init_ui(self):
        # Создаем элементы интерфейса
        self.label_quarter = QLabel('Выберите квартал:')
        self.combo_quarter = QComboBox()
        self.combo_quarter.addItems(['Q1', 'Q2', 'Q3', 'Q4'])

        self.label_subnet = QLabel('Выберите подсеть:')
        self.combo_subnet = QComboBox()
        self.combo_subnet.addItems(network_names)

        self.button_run = QPushButton('Запустить')
        self.button_run.clicked.connect(self.prepare_for_scan)

        # Создаем QStackedWidget для управления страницами
        self.stacked_widget = QStackedWidget()

        # Страница "Выбор параметров"
        self.page_select_params = QWidget()
        v_layout_select_params = QVBoxLayout(self.page_select_params)
        v_layout_select_params.addWidget(self.label_quarter)
        v_layout_select_params.addWidget(self.combo_quarter)
        v_layout_select_params.addWidget(self.label_subnet)
        v_layout_select_params.addWidget(self.combo_subnet)
        v_layout_select_params.addWidget(self.button_run)

        # Страница "Подготовка к запуску"
        self.page_prepare_to_run = QWidget()
        v_layout_prepare_to_run = QVBoxLayout(self.page_prepare_to_run)
        v_layout_prepare_to_run.addWidget(QLabel('Подготовка к запуску...'))

        # Страница "Прогресс сканирования"
        self.page_scanning_progress = QWidget()
        v_layout_scanning_progress = QVBoxLayout(self.page_scanning_progress)
        self.progress_bar = QProgressBar()
        v_layout_scanning_progress.addWidget(self.progress_bar)

        # Страница "Сканирование завершено"
        self.page_scan_finished = QWidget()
        v_layout_scan_finished = QVBoxLayout(self.page_scan_finished)
        v_layout_scan_finished.addWidget(QLabel('Сканирование завершено'))

        # Добавляем страницы в QStackedWidget
        self.stacked_widget.addWidget(self.page_select_params)
        self.stacked_widget.addWidget(self.page_prepare_to_run)
        self.stacked_widget.addWidget(self.page_scanning_progress)
        self.stacked_widget.addWidget(self.page_scan_finished)

        # Создаем менеджер компоновки для основного окна
        v_layout_main = QVBoxLayout()
        v_layout_main.addWidget(self.stacked_widget)

        # Устанавливаем компоновку основного окна
        self.setLayout(v_layout_main)

        # Устанавливаем заголовок и размеры окна
        self.setWindowTitle('Network Scanner App')
        self.setGeometry(300, 300, 400, 200)

        # Отображаем окно
        self.show()

    def prepare_for_scan(self):
        # Получаем выбранные значения от пользователя
        self.selected_quarter = self.combo_quarter.currentText()
        self.selected_subnet = self.combo_subnet.currentText()

        # Переключаемся на страницу "Подготовка к запуску"
        self.stacked_widget.setCurrentIndex(1)

        create_directory(self.selected_quarter, self.selected_subnet)
        self.live_hosts = scan_for_live_hosts(networks[f'{self.selected_subnet}'])
        QTimer.singleShot(1000, self.start_scan)

    def start_scan(self):
        # Переключаемся на страницу "Прогресс сканирования"
        self.stacked_widget.setCurrentIndex(2)

        self.counter = 0

        for host in self.live_hosts:
            print(host)
            counters: dict[str, int] = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }
            current_date = datetime.datetime.now()
            year = current_date.year
            if operating_system == 'Windows':
                report_path = f'D:\\NmapApp\ScanResults\{year}\{self.selected_quarter}\{self.selected_subnet}\{host}.txt'
                nmap_command = fr'C:\"Program Files (x86)"\Nmap\nmap.exe -sV --script vulners {host} > nmap_report.txt'
            else:
                report_path = f'/home/vadim/Desktop/{year}/{self.selected_quarter}/{self.selected_subnet}/{host}.txt'
                nmap_command = f"nmap -sV --script vulners {host} > nmap_report.txt"

            subprocess.run(nmap_command, shell=True, check=True)
            vulnerabilities = parse_nmap_report('nmap_report.txt')
            sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: x['score'], reverse=True)
            create_report(sorted_vulnerabilities, report_path, counters)
            self.counter += 1
            self.scan_progress = int(self.counter / len(self.live_hosts) * 100)
            self.progress_bar.setValue(self.scan_progress)

        # Переход на страницу с завершенным сканированием
        self.stacked_widget.setCurrentIndex(3)


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


def create_directory(quarter, network):
    current_date = datetime.datetime.now()
    year = current_date.year
    # Определяем путь для создания директории в зависимости от операционной системы
    if operating_system == 'Windows':
        directory_path = f'D:\\NmapApp\ScanResults\{year}\{quarter}\{network}'
    else:
        current_user = os.getenv('USER')
        directory_path = f'/home/{current_user}/Desktop/{year}/{quarter}/{network}'

    # Проверяем, существует ли директория, и создаем её, если не существует
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"Директория '{directory_path}' успешно создана.")
    else:
        print(f"Директория '{directory_path}' уже существует.")


def networks_from_file():
    nets = {}
    nets_names = []

    with open('Networks.txt', 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                key, value = map(str.strip, line.split(':'))
                nets[key] = value
                name = line.split(':')[0].strip()
                nets_names.append(name)

    return nets, nets_names


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

    return vulnerabilities


def create_report(vulnerabilities, output_file, counters):
    vul = False
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


if __name__ == "__main__":
    networks, network_names = networks_from_file()
    app = QApplication(sys.argv)
    ex = NetworkScannerApp()
    sys.exit(app.exec_())
