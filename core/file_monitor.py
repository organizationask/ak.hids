import os
import time

def monitor_files(directory, log_file, detected_intrusions):
    """Monitor a directory for file changes and log them."""
    previous_files = set(os.listdir(directory))
    while True:
        current_files = set(os.listdir(directory))
        added_files = current_files - previous_files
        removed_files = previous_files - current_files

        with open(log_file, "a") as log:
            for file in added_files:
                message = f"File added: {file}"
                log.write(message + "\n")
                detected_intrusions.append(message)
            for file in removed_files:
                message = f"File removed: {file}"
                log.write(message + "\n")
                detected_intrusions.append(message)

        previous_files = current_files
        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    DIRECTORY_TO_MONITOR = "C:\\path\\to\\directory"  # Replace with the directory you want to monitor
    LOG_FILE = "C:\\path\\to\\logs\\file_monitor_logs.txt"  # Replace with the path to your log file
    detected_intrusions = []

    try:
        # Ensure the directory to monitor exists
        if not os.path.exists(DIRECTORY_TO_MONITOR):
            os.makedirs(DIRECTORY_TO_MONITOR)

        # Ensure the directory for the log file exists
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        monitor_files(DIRECTORY_TO_MONITOR, LOG_FILE, detected_intrusions)
    except KeyboardInterrupt:
        print("File monitoring stopped.")