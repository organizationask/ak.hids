import os
import time
from datetime import datetime
import threading
import platform

# Ensure the logs directory exists
os.makedirs("logs", exist_ok=True)

def log_event(log_file, message, detected_intrusions):
    """Log an event to the log file and append to intrusions."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"{timestamp} - {message}"
    with open(log_file, "a") as log:
        log.write(full_message + "\n")
    detected_intrusions.append(full_message)

def monitor_users_linux(log_file, detected_intrusions):
    """Monitor user login/logout activity on Linux."""
    auth_log_path = "/var/log/auth.log"
    if not os.path.exists(auth_log_path):
        log_event(log_file, "Authentication log file not found.", detected_intrusions)
        return

    try:
        with open(auth_log_path, "r") as auth_log:
            auth_log.seek(0, os.SEEK_END)
            log_event(log_file, f"Monitoring user activity on: {auth_log_path}", detected_intrusions)
            while True:
                line = auth_log.readline()
                if not line:
                    time.sleep(1)
                    continue
                if "session opened" in line or "session closed" in line:
                    log_event(log_file, f"User activity: {line.strip()}", detected_intrusions)
    except Exception as e:
        log_event(log_file, f"Error monitoring users: {e}", detected_intrusions)

def monitor_users_windows(log_file, detected_intrusions):
    """Monitor user login/logout activity on Windows."""
    try:
        import wmi
        c = wmi.WMI()
        log_event(log_file, "Monitoring user activity on Windows Event Log.", detected_intrusions)
        watcher = c.Win32_NTLogEvent(EventCode="4624")  # EventCode 4624 is for logon events
        for event in watcher:
            log_event(log_file, f"User activity: {event.InsertionStrings}", detected_intrusions)
    except ImportError:
        log_event(log_file, "The 'wmi' module is required for Windows user monitoring.", detected_intrusions)
    except Exception as e:
        log_event(log_file, f"Error monitoring users: {e}", detected_intrusions)

def monitor_users(log_file, detected_intrusions):
    """Monitor user activity based on the operating system."""
    if platform.system() == "Linux":
        monitor_users_linux(log_file, detected_intrusions)
    elif platform.system() == "Windows":
        monitor_users_windows(log_file, detected_intrusions)
    else:
        log_event(log_file, "Unsupported operating system for user monitoring.", detected_intrusions)

if __name__ == "__main__":
    LOG_FILE = "logs/intrusion_logs.txt"
    detected_intrusions = []

    # Start monitoring users
    threading.Thread(target=monitor_users, args=(LOG_FILE, detected_intrusions), daemon=True).start()