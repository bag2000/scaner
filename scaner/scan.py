import requests
import argparse
import subprocess
import time
import configparser
import os

def loger(txt):
    with open("log.txt", "a") as f:
        f.write("\n" + txt)

# Получение полного пути к файлу скрипта
file_path = os.path.realpath(__file__)
# Получение директории, в которой находится файл скрипта
script_dir = os.path.dirname(file_path)
# Меняем рабочую директорию
os.chdir(script_dir)

config = configparser.ConfigParser()
config.read("../settings/settings.ini")
nmap_cmd = config["Nmap"]["nmap_cmd_scan_ip"].replace('"', '')


headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
base_port = '8000'
base_url = f'http://192.168.12.140:{base_port}'

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ip", help = "Scan ip. Arg. all or ip or subnet. Example: python3 scan.py -i all OR python3 scan.py -i 192.168.12.45 OR python3 scan.py -i 192.168.10.0")
args = parser.parse_args()

# Запуск nmap команды
def run_nmap_command(cmd: str):
    process = subprocess.run(cmd, capture_output=True, shell=True)
    ressult_ok = process.stdout.decode("utf-8")
    return ressult_ok


# Парсим лог nmap со списком хостов
def parse_network(nmap_result: str):
    hosts_list = []
    data_list = nmap_result.split('\n')
    for line in data_list:
        try:
            if line[0] == 'N':
                line_list = line.split(' ')
                ip = line_list[4]
                if ip[0].isdigit() and ip[0] != '_':
                    hosts_list.append(ip)
        except Exception:
            pass
    return hosts_list


# Парсим лог nmap ip
def parse_ip(nmap_result: str):
    open_ports = []
    open_ports_list = nmap_result.split('\n')
    for line in open_ports_list:
        try:
            if line[0].isdigit():
                port = line.split(' ')[0]
                port = port.split('/')
                if port[1] == 'tcp':
                    open_ports.append(port[0])            
        except Exception:
            pass
        
    if len(open_ports) == 0:
        open_ports = ['0']
    return open_ports


# Получаем всю очередь
def get_all_ip_from_queue():
    response = requests.get(f'{base_url}/api/queue',
                    headers=headers)
    response_json = response.json()
    return response_json


# Получаем все ip из базы данных
def get_all_ip_from_db():
    response = requests.get(f'{base_url}/api/ips',
                    headers=headers)
    response_json = response.json()
    return response_json

# Удаляем ip из очереди
def del_ip_from_queue(ip: str):
    requests.delete(f'{base_url}/api/queue/{ip}',
                    headers=headers)
    
    if is_ip_in_queue(ip):
        return False
    else:
        return True
    

# Проверяем, находится ли ip в очереди
def is_ip_in_queue(ip: str):
    response = requests.get(f'{base_url}/api/queue/{ip}',
                            headers=headers)
    
    if response.text == "null":
        return False
    else:
        return True


# Получаем и проверяем, находится ли ip в базе данных
def is_ip_in_db(ip: str):
    response = requests.get(f'{base_url}/api/ips/{ip}',
                            headers=headers)
    
    if response.text == "null":
        return False
    else:
        return response.json()


# Проверяем, является ли ip подсетью
def is_subnet(ip: str):
    aktet = ip.split('.')

    if aktet[3] == "0":
        return True
    else:
        return False


# Добавляем ip в очередь
def add_ip_to_queue(ip: str):

    if is_ip_in_queue(ip):
        return "In queue"
    else:

        data = {
            "ip_address": f"{ip}"
        }

        requests.post(f'{base_url}/api/queue', 
                                 headers=headers,
                                 json=data)
        
        if is_subnet(ip):
            cmd = f'sudo nmap -sn {ip}/24'
            log = run_nmap_command(cmd)
            ip_list = parse_network(log)

            for i in ip_list:
                add_ip_to_queue(i)            
        
        return True


# Добавляем ip в базу данных
def add_ip_to_db(ip: str, open_ports: list, log: str):
    
    ip_db = is_ip_in_db(ip)

    if ip_db:        
        # Если разрешенные порты и открытые порты равны 0
        if ip_db[4] == "0" and open_ports == ["0"]:
            open_ports = ", ".join(open_ports)
            status = "green"
        else:
            # Если разрешенные порты равны 0, тогда открытые порты записываются все
            if ip_db[4] == "0":
                open_ports = ", ".join(open_ports)
                status = "red"
            else:
                # Перебираем все открытые порты, исключаем разрешенные
                ports = []

                cleaned_allow_ports = []
                allow_ports = str(ip_db[4]).split(",")
                for p in allow_ports:
                    cleaned_allow_ports.append(p.strip())

                for port in open_ports:
                    if port not in cleaned_allow_ports:
                        ports.append(port)

                if len(ports) == 0 :
                    open_ports = "0"
                else:
                    open_ports = ", ".join(ports)

                if open_ports == "0":
                    status = "green"
                else:
                    status = "red"

        date = time.strftime("%d.%m.%y %H:%M:%S")
        data = {
            "name": f"{ip_db[1]}",
            "ip_address": f"{ip_db[2]}",
            "open_ports": f"{open_ports}",
            "allow_ports": f"{ip_db[4]}",
            "comments": f"{ip_db[5]}",
            "logs": f"{log}",
            "status": f"{status}",
            "enabled": f"{ip_db[8]}",
            "date": f"{date}"
            }
        requests.put(f'{base_url}/api/ips/{ip_db[2]}',
                      headers=headers,
                      json=data)
    else:
        if open_ports == ["0"]:
            status = "green"
        else:
            status = "red"
        
        open_ports = ", ".join(open_ports)
        date = time.strftime("%d.%m.%y %H:%M:%S")
        data = {
            "name": "",
            "ip_address": f"{ip}",
            "open_ports": f"{open_ports}",
            "allow_ports": "0",
            "comments": "",
            "logs": f"{log}",
            "status": f"{status}",
            "enabled": "true",
            "date": f"{date}"
        }
        requests.post(f'{base_url}/api/ips',
                      headers=headers,
                      json=data)        


# Сканируем ip
def scan_ip(ip: str):
    del_ip_from_queue(ip)
    cmd = 'sudo nmap ' + nmap_cmd + f' {ip}'
    log = run_nmap_command(cmd)
    open_ports = parse_ip(log)
    add_ip_to_db(ip, open_ports, log)


def validation(ip: str):
    valid = False
    ip_validation = str(ip).split(".")

    try:
        if 0 < int(ip_validation[0]) < 255 and -1 < int(ip_validation[1]) < 255:
                if -1 < int(ip_validation[2]) < 255 and -1 < int(ip_validation[3]) < 255:
                            valid = True
    except ValueError:
        pass

    return valid


def scaner(ip: str):
    valid = validation(ip)
    if ip != "all":                
        if valid:
            add_ip_to_queue(ip)            
            if is_subnet(ip):
                for i in get_all_ip_from_queue():
                    if is_ip_in_queue(i[1]):
                        scan_ip(i[1])
            else:
                if is_ip_in_queue(ip):
                    scan_ip(ip)

    else:
        for i in get_all_ip_from_db():
            add_ip_to_queue(i[2]) 
        
        for i in get_all_ip_from_queue():
            if is_ip_in_queue(i[1]):
                scan_ip(i[1])

if args.ip:    
    scaner(args.ip)
    
