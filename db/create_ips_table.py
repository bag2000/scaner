import sqlite3

import os

# Получение полного пути к файлу скрипта
file_path = os.path.realpath(__file__)
# Получение директории, в которой находится файл скрипта
script_dir = os.path.dirname(file_path)
# Меняем рабочую директорию
os.chdir(script_dir)

db_path = 'scaner.db'

con = sqlite3.connect(db_path)
cur = con.cursor()

sql = """CREATE TABLE IF NOT EXISTS ips (
ip_id INTEGER PRIMARY KEY,
name TEXT,
ip_address TEXT NOT NULL UNIQUE,
open_ports TEXT,
allow_ports TEXT,
comments TEXT,
logs TEXT,
status TEXT,
enabled BOOL,
date TEXT
)"""
cur.execute(sql)

sql = """CREATE TABLE IF NOT EXISTS queue (
ip_id INTEGER PRIMARY KEY,
ip_address TEXT NOT NULL UNIQUE
)"""
cur.execute(sql)

con.commit()
con.close()