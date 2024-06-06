import sqlite3
from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import threading
import configparser
import os
import uvicorn

# Получение полного пути к файлу скрипта
file_path = os.path.realpath(__file__)
# Получение директории, в которой находится файл скрипта
script_dir = os.path.dirname(file_path)
# Меняем рабочую директорию
os.chdir(script_dir)

config = configparser.ConfigParser()
config.read("settings/settings.ini")
main_page_address = config["Main"]["main_page_address"].replace('"', '')


class IP(BaseModel):
    name: str
    ip_address: str
    open_ports: str
    allow_ports: str
    comments: str
    logs: str
    status: str
    enabled: bool
    date: str


class Queue(BaseModel):
    ip_address: str


db_path = 'db/scaner.db'

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def run_cmd(cmd):
    process = subprocess.run(cmd, capture_output=True, shell=True)
    ressult_ok = process.stdout.decode("utf-8")
    ressult_err = process.stderr.decode("utf-8")
    return ressult_ok + ressult_err


run_cmd("python3 ./db/create_ips_table.py")

def execute_sql(sql, sql_list="None", fetchall=False, fetchone=False):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    if sql_list != "None":
        cur.execute(sql, sql_list)
        con.commit()
        con.close()
    elif fetchall:
        cur.execute(sql)
        fetch_all = cur.fetchall()
        con.commit()
        con.close()
        return fetch_all
    elif fetchone:
        cur.execute(sql)
        fetch_one = cur.fetchone()
        con.commit()
        con.close()
        return fetch_one
    else:
        cur.execute(sql)
        con.commit()
        con.close()


@app.get("/api/ips")
async def get_ips():
    sql = """SELECT * FROM ips"""
    ips = execute_sql(sql, fetchall=True)
    return ips


@app.get("/api/ips/{ip_address}")
async def get_ip(ip_address: str):
    sql = f"""SELECT * FROM ips WHERE ip_address = '{ip_address}';"""
    ip = execute_sql(sql, fetchone=True)
    return ip


@app.post("/api/ips")
async  def create_ip(data: IP):
    sql = """INSERT INTO ips (name, ip_address, open_ports, allow_ports, comments, logs, status, enabled, date) VALUES (?,?,?,?,?,?,?,?,?)"""
    sql_list = [data.name, data.ip_address,data.open_ports,data.allow_ports,data.comments,data.logs,data.status,data.enabled,data.date]
    try:
        execute_sql(sql, sql_list)
        stat = Response(status_code=status.HTTP_200_OK)
    except sqlite3.IntegrityError:
        stat = Response(status_code=status.HTTP_412_PRECONDITION_FAILED)
    return stat


@app.put("/api/ips/{ip_address}")
async def put_ip(data: IP, ip_address: str):
    sql = f"""
    UPDATE ips 
    SET name = '{data.name}', 
    ip_address = '{data.ip_address}', 
    open_ports = '{data.open_ports}', 
    allow_ports = '{data.allow_ports}', 
    comments = '{data.comments}', 
    logs = '{data.logs}', 
    status = '{data.status}',
    enabled = '{data.enabled}',
    date = '{data.date}'
    WHERE ip_address = '{ip_address}';
    """
    execute_sql(sql)
    return Response(status_code=status.HTTP_200_OK)


@app.delete("/api/ips/{ip_address}")
async def del_ip(ip_address: str):
    sql = f"""DELETE FROM ips WHERE ip_address = '{ip_address}';"""
    execute_sql(sql)
    return Response(status_code=status.HTTP_200_OK)


@app.post("/api/queue")
async  def create_queue(data: Queue):
    sql = """INSERT INTO queue (ip_address) VALUES (?)"""
    sql_list = [data.ip_address]
    try:
        execute_sql(sql, sql_list)
        stat = Response(status_code=status.HTTP_200_OK)
    except sqlite3.IntegrityError:
        stat = Response(status_code=status.HTTP_412_PRECONDITION_FAILED)
    return stat


@app.get("/api/queue")
async def get_queues():
    sql = """SELECT * FROM queue"""
    ips = execute_sql(sql, fetchall=True)
    return ips


@app.get("/api/queue/{ip_address}")
async def get_queue(ip_address: str):
    sql = f"""SELECT * FROM queue WHERE ip_address = '{ip_address}';"""
    ip = execute_sql(sql, fetchone=True)
    return ip


@app.delete("/api/queue/{ip_address}")
async def del_ip(ip_address: str):
    sql = f"""DELETE FROM queue WHERE ip_address = '{ip_address}';"""
    execute_sql(sql)
    return Response(status_code=status.HTTP_200_OK)


@app.get("/api/scan/{ip_address}")
async def scan_ip(ip_address: str): 
    if ip_address != 'all':
        t1 = threading.Thread(target=run_cmd, args=(f'sudo python3 ./scaner/scan.py -i {ip_address}',), daemon=True)
        t1.start()
    else:
        t1 = threading.Thread(target=run_cmd, args=('sudo python3 ./scaner/scan.py -i all',), daemon=True)
        t1.start()


@app.get("/api/settings/main_page_address")
async def get_main_page_address():
    return {"main_page_address": main_page_address}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)