import os
import re
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from typing import Dict, Optional

# --- Parser Regex ---
# Auth.log (SSH)
# Contoh: "Apr 20 00:00:01 server sshd[123]: Failed password for invalid user root from 192.168.1.100 port 123 ssh2"
SSH_FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
SSH_INVALID_PATTERN = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")

# Nginx access.log
# Contoh: '192.168.1.100 - - [20/Apr/2026:00:00:01 +0700] "GET /.env HTTP/1.1" 404 123'
NGINX_ACCESS_PATTERN = re.compile(r"(?P<ip>\S+) \S+ \S+ \[[^\]]+\] \"(?P<method>\S+) (?P<path>\S+) \S+\" (?P<status>\d+)")


def parse_auth_log(line: str) -> Optional[Dict]:
    match = SSH_FAILED_PATTERN.search(line) or SSH_INVALID_PATTERN.search(line)
    if match:
        return {
            "service": "ssh",
            "ip": match.group("ip"),
            "username": match.group("user"),
            "path": "",
            "raw_log": line.strip()
        }
    return None

def parse_nginx_log(line: str) -> Optional[Dict]:
    match = NGINX_ACCESS_PATTERN.search(line)
    if match:
        return {
            "service": "nginx",
            "ip": match.group("ip"),
            "path": match.group("path"),
            "status_code": match.group("status"),
            "username": "",
            "raw_log": line.strip()
        }
    return None


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, filepath: str, parser_func, callback=None):
        super().__init__()
        self.filepath = os.path.abspath(filepath)
        self.parser_func = parser_func
        self.callback = callback
        
        # Buka file dan langsung lompat ke paling akhir
        self._file = open(self.filepath, 'r')
        self._file.seek(0, os.SEEK_END)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.filepath:
            self._read_new_lines()

    def _read_new_lines(self):
        for line in self._file.readlines():
            if not line.strip():
                continue
            
            parsed_event = self.parser_func(line)
            if parsed_event:
                self.process_event(parsed_event)

    def process_event(self, event: dict):
        if self.callback:
            self.callback(event)
        else:
            print(f"\n🚨 [SENSOR DETECT] (No Callback) IP: {event.get('ip')}")


class LogSensor:
    def __init__(self, callback=None):
        self.observer = Observer()
        self.handlers = []
        self.callback = callback

    def watch_file(self, filepath: str, log_type: str):
        if not os.path.exists(filepath):
            open(filepath, 'w').close()
            
        parser = parse_auth_log if log_type == "auth" else parse_nginx_log
        handler = LogFileHandler(filepath, parser, self.callback)
        self.handlers.append(handler)
        
        dir_path = os.path.dirname(os.path.abspath(filepath))
        self.observer.schedule(handler, path=dir_path, recursive=False)
        print(f"[SENSOR] Attached watcher ke: {filepath}")

    def start(self):
        print("[SENSOR] Memulai monitoring log secara real-time...")
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
            print("[SENSOR] Monitoring dihentikan.")
        self.observer.join()
