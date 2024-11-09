# database.py
import sqlite3

def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('network_scanner.db')
    except sqlite3.Error as e:
        print(e)
    return conn

def setup_database():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            service_name TEXT,
            service_version TEXT,
            vulnerabilities TEXT,
            os_info TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()

def insert_scan_result(ip_address, port, service_name, service_version, vulnerabilities, os_info):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (ip_address, port, service_name, service_version, vulnerabilities, os_info)
        VALUES (?, ?, ?, ?, ?, ?);
    """, (ip_address, port, service_name, service_version, vulnerabilities, os_info))
    conn.commit()
    conn.close()

def fetch_all_scans():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans;")
    rows = cursor.fetchall()
    conn.close()
    return rows