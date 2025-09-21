import os
import socket
import requests
import requests.cookies
from typing import Literal
from dataclasses import dataclass

from logging_out import log_output

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

IP_FILE = "./IP"

DNS_UPDATE_URL = "https://www.hover.com/api/dns/{}"
DOMAIN_CHECK_URL = "https://www.hover.com/api/domains"
DNS_ENTRIES_URL = "https://www.hover.com/api/dns"
DNS_SUBENTRIES_URL = "https://www.hover.com/api/control_panel/dns/"

@dataclass
class DnsRecord:
    domain: str
    host: str
    value: str
    record_type: Literal["A", "AAAA", "CNAME", "MX", "SRV"]

    def is_ip4(self):
        return self.record_type == "A"
    
    def is_ip6(self):
        return self.record_type == "AAAA"
    
    def get_fqdn(self) -> str:
        if self.get_host() == "@":
            return self.domain
        
        return f"{self.host}.{self.domain}"
    
    def get_host(self) -> str:

        if self.host is None:
            return "@"
        
        return self.host

def get_external_ip(use_ipv6: bool) -> str:
    """
    Retrieves the external IP address using the ipify API.
    """
    api = "https://api6.ipify.org" if use_ipv6 else "https://api.ipify.org"
    response = requests.get(api, verify=True)
    return response.text

def get_dns_ip(domain: str, use_ipv6: bool) -> str | None:
    "Retrieves the IP address for a given domain."
    try:
        for addrinfo in socket.getaddrinfo(domain, 80, socket.AddressFamily.AF_INET6 if use_ipv6 else socket.AddressFamily.AF_INET):
            if isinstance(addrinfo[4][0], str):
                return addrinfo[4][0]
    except socket.gaierror:
        return None


def submit_dns_entry_update(record: DnsRecord, cookies: requests.cookies.RequestsCookieJar, dns_entry_id: str | None):
    """
    Updates a new or existing DNS record.
    """
    if dns_entry_id:
        http_method = requests.put
        json_data = {
            "domain": {
                "id": f"domain-{record.domain}",
                "dns_records": [
                    {
                        "id": dns_entry_id,
                        "name": record.host,
                        "type": record.record_type,
                        "content": record.value,
                        "ttl": "900",
                        "is_default": False,
                        "can_revert": True
                    }
                ]
            },
            "fields": {
                "content": record.value,
                "ttl": "900"
            }
        }
    else:
        http_method = requests.post
        json_data = {
            "dns_record": {
                "name": record.host,
                "content": record.value,
                "type": record.record_type,
                "ttl": "900"
            },
            "id": f"domain-{record.domain}"
        }

    response = http_method(url=DNS_SUBENTRIES_URL, json=json_data, cookies=cookies, verify=True)
    log_output(DNS_UPDATE_URL.format(dns_entry_id))
    log_output(f"DNS update response status code: {response.status_code}")
    log_output(f"DNS update response content: {response.content}")

    return response

def get_dns_entries(cookies, logging):
    """
    Retrieves the DNS entries for the account.
    """
    response = requests.get(DNS_ENTRIES_URL, cookies=cookies, verify=True)
    if response.status_code == 200:
        return response.json()        
    else:
        logging(f"Failed to retrieve DNS entries. Status code: {response.status_code}, Response text: {response.text}", logging)
        exit(4)