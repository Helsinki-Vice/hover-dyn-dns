import datetime

LOG_FILE = "./hover-update.log"

def log_output(message: str, logging: bool):
    """
    Logs a message to the log file and prints it to the console if logging is enabled.
    """
    if logging:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_FILE, 'a') as log_file:
            log_file.write(f"{timestamp} - {message}\n")
        print(f"{timestamp} - {message}")