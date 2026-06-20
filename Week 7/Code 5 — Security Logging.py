import logging
import datetime

# Configure a security log file
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log_failed_login(username, ip_address):
    logging.warning(f"FAILED LOGIN | user={username} | ip={ip_address}")

def log_access(user_id, resource):
    logging.info(f"ACCESS | user={user_id} | resource={resource}")

def log_suspicious(description):
    logging.critical(f"SUSPICIOUS ACTIVITY | {description}")

# Usage
log_failed_login("admin", "192.168.1.55")
log_suspicious("Multiple failed logins from 192.168.1.55 in 60 seconds")
