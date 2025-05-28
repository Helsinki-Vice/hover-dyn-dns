import datetime

def log_output(message: str, log_filename: str | None, print_output: bool):
    """
    Logs a message to the log file and prints it to the console if logging is enabled.
    """
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if log_filename:
        with open(log_filename, 'a') as log_file:
            log_file.write(f"{timestamp} - {message}\n")
    
    if print_output:
        print(f"{timestamp} - {message}")