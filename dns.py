import os
import json
import requests
import requests.cookies

from logging_out import log_output, LOG_FILE

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

IP_FILE = "./IP"

DNS_UPDATE_URL = "https://www.hover.com/api/dns/{}"
DOMAIN_CHECK_URL = "https://www.hover.com/api/domains"
DNS_ENTRIES_URL = "https://www.hover.com/api/dns"
DNS_SUBENTRIES_URL = "https://www.hover.com/api/control_panel/dns/"

# Proxy settings for mitmproxy
DEFAULT_PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

def load_config(config_file: str, logging) -> dict:
    """
    Loads the configuration from a JSON file.
    """
    try:
        with open(config_file, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        log_output(f"Error loading config file: {e}", logging)
        exit(1)

def get_external_ip(proxies) -> str:
    """
    Retrieves the external IP address using the ipify API.
    """
    response = requests.get("https://api.ipify.org", proxies=proxies, verify=True)
    return response.text

def get_dns_ip(domain: str) -> str | None:
    """
    Retrieves the IP address for a given domain using the getent hosts command.
    """
    response = os.popen(f"getent hosts {domain}").read().strip()
    return response.split()[0] if response else None

def submit_put_on_existing_dns_entry(dns_entry_id: str, domain: str, subdomain: str, new_ip_address: str, record_type: str, cookies: requests.cookies.RequestsCookieJar, proxies, logging: bool):
    """
    Updates an existing DNS record with a known ID.
    """
    put_data = {
        "domain": {
            "id": f"domain-{domain}",
            "dns_records": [
                {
                    "id": dns_entry_id,
                    "name": subdomain,
                    "type": record_type,
                    "content": new_ip_address,
                    "ttl": "900",
                    "is_default": False,
                    "can_revert": True
                }
            ]
        },
        "fields": {
            "content": new_ip_address,
            "ttl": "900"
        }
    }
    
    response = requests.put(url=DNS_SUBENTRIES_URL, json=put_data, cookies=cookies, proxies=proxies, verify=True)
    log_output(DNS_UPDATE_URL.format(dns_entry_id), logging)

    log_output(f"DNS update response status code: {response.status_code}", logging)
    log_output(f"DNS update response content: {response.content}", logging)
    return response

def submit_post_for_new_dns_entry(domain: str, subdomain: str, new_ip_address: str, record_type: str, cookies: requests.cookies.RequestsCookieJar, proxies, logging: bool):
    """
    Adds a new DNS record.
    """
    post_data = {
        "dns_record": {
            "name": subdomain,
            "content": new_ip_address,
            "type": record_type,
            "ttl": "900"
        },
        "id": f"domain-{domain}"
    }
    
    response = requests.post(url=DNS_SUBENTRIES_URL, json=post_data, cookies=cookies, proxies=proxies, verify=True)
    
    log_output(f"DNS update response status code: {response.status_code}", logging)
    log_output(f"DNS update response content: {response.content}", logging)
    return response

def get_dns_entries(cookies, proxies, logging):
    """
    Retrieves the DNS entries for the account.
    """
    response = requests.get(DNS_ENTRIES_URL, cookies=cookies, proxies=proxies, verify=True)
    if response.status_code == 200:
        return response.json()        
    else:
        logging(f"Failed to retrieve DNS entries. Status code: {response.status_code}, Response text: {response.text}", logging)
        exit(4)