import os
import json
import datetime
import argparse
from dataclasses import dataclass
from typing import Literal

from authentication import login
from logging_out import log_output
from dns import IP_FILE, get_external_ip, get_dns_ip, DEFAULT_PROXIES, get_dns_entries, submit_put_on_existing_dns_entry, submit_post_for_new_dns_entry

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

@dataclass
class Config:
    username: str
    password: str
    totp_secret: str
    address: str
    domain: str
    host: str
    dns_record_type: Literal["A", "AAAA", "CNAME", "MX", "SRV"]
    cookiefile: str
    proxies: dict[str, str] | None
    do_get_dns_id: bool
    force: bool

    def get_fqdn(self) -> str:
        if self.get_host() == "@":
            return self.domain
        
        return f"{self.host}.{self.domain}"
    
    def get_host(self) -> str:

        if self.host is None:
            return "@"
        
        return self.host

def load_config() -> Config:

    parser = argparse.ArgumentParser(description='Hover DNS Update Script')
    parser.add_argument('--username', help='Hover.com user ID')
    parser.add_argument('--password', help='Hover.com user password')
    parser.add_argument('--totp_secret', help='TOTP shared secret from you hover account')
    parser.add_argument('--addr', nargs="?", help='IP address for the new DNS record, will use current address by default')
    parser.add_argument('--domain', help='Your \"naked\" domain name (i.e example.com) registered at Hover')
    parser.add_argument('--host', nargs="?", help='Hostname (i.e www) for the new record.')
    parser.add_argument('--type', nargs="?", default="A", help='DNS record type (A, AAAA, CNAME, etc.)')
    parser.add_argument('--cookiefile', nargs="?", default="cookies.json", help='File path of the cookie store')
    parser.add_argument('--mitm', action='store_true', help='Enable mitmproxy for HTTP/HTTPS requests')
    parser.add_argument('--getDNSID', action='store_true', help='Retrieve DNS entries for the account')
    parser.add_argument('--force', action='store_true', help='Forces DNS updates, even if they are already current')
    args = parser.parse_args()

    config = Config(
        username = args.username,
        password = args.password,
        totp_secret = args.totp_secret,
        address = args.addr,
        domain = args.domain,
        host = args.host,
        dns_record_type = args.type,
        cookiefile = args.cookiefile,
        proxies = DEFAULT_PROXIES if args.mitm else None,
        do_get_dns_id = args.getDNSID,
        force = args.force,
    )

    config.domain = str.replace(config.domain, "http://", "")
    config.domain = str.replace(config.domain, "https://", "")
    
    if config.address is None:
        config.address = get_external_ip(None, use_ipv6=config.dns_record_type=="AAAA")
    
    return config

if __name__ == "__main__":
    
    config = load_config()
    
    dns_ip = get_dns_ip(config.get_fqdn(), use_ipv6=config.dns_record_type=="AAAA")
    if dns_ip == config.address and not config.do_get_dns_id and not config.force:
        exit()
    log_output(f"Current IP of {config.address} does not match DNS record of {dns_ip}, performing update...")
    
    cookies = login(config.username, config.password, config.totp_secret, config.proxies)
    if not cookies:
        exit()
    log_output(f"Using username: {config.username}")
    existing_dns_entries = get_dns_entries(cookies, config.proxies, True)
    dns_id = None
    log_output(existing_dns_entries)
    for registed_domain in existing_dns_entries["domains"]:
        if registed_domain["domain_name"] == config.domain:
            for entry in registed_domain["entries"]:
                if entry["name"] == config.get_host() and entry["type"] == config.dns_record_type:
                    dns_id = entry["id"]
                    log_output(f"DNS record ID is {dns_id}")
                    if entry["content"] == config.address and not (config.do_get_dns_id or config.force):
                        log_output(f"DNS entry with ID {dns_id} ({config.get_fqdn()}) already matches current IP address of {config.address}. DNS up to date, waiting until the record replicates to local nameserver. exiting.")
                        exit()
            break
    else:
        log_output(f"Domain {config.domain} does not seem to be on your Hover account.")
        exit()
    if config.do_get_dns_id:
        print(dns_id)
        exit(0)
    if dns_id:
        submit_put_on_existing_dns_entry(dns_id, config.domain, config.host, config.address, config.dns_record_type, cookies, config.proxies)
    else:
        log_output(f"Could not find a {config.dns_record_type} DNS record for {config.get_fqdn()}. Creating a new one...")
        submit_post_for_new_dns_entry(config.domain, config.host, config.address, config.dns_record_type, cookies, None)
    
    with open(IP_FILE, 'w+') as file:
        file.write(str(config.address))
    
    exit()