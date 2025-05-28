import os
import json
import datetime
import argparse
from dataclasses import dataclass
from typing import Literal

from authentication import login
from logging_out import log_output
from dns import IP_FILE, load_config_file, get_external_ip, get_dns_ip, DEFAULT_PROXIES, get_dns_entries, submit_put_on_existing_dns_entry, submit_post_for_new_dns_entry

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
    configfile: str
    logfile: str
    cookiefile: str
    do_logging: bool
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
    parser.add_argument('--username', nargs='?', help='Hover.com user ID')
    parser.add_argument('--password', nargs="?", help='Hover.com user password')
    parser.add_argument('--totp_secret', nargs="?", help='TOTP shared secret from you hover account')
    parser.add_argument('--addr', nargs="?", help='IP address for the new DNS record, will use current address by default')
    parser.add_argument('--domain', nargs="?", help='Your domain name (i.e example.com) registered at Hover')
    parser.add_argument('--host', nargs="?", help='Hostname (i.e www) for the new record.')
    parser.add_argument('--type', nargs="?", default="A", help='DNS record type (A, AAAA, CNAME, etc.)')
    parser.add_argument('--config', nargs="?", default="config.json", help='File path a config file containing additinal arguments not passed on command line')
    parser.add_argument('--logfile', nargs="?", default="hover-update.log", help='File path of the logging file')
    parser.add_argument('--cookiefile', nargs="?", default="cookies.json", help='File path of the logging file')
    parser.add_argument('--logging', action='store_true', help='Enable logging to hover-update.log')
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
        configfile = args.config,
        logfile = args.logfile,
        cookiefile = args.cookiefile,
        do_logging = args.logging,
        proxies = DEFAULT_PROXIES if args.mitm else None,
        do_get_dns_id = args.getDNSID,
        force = args.force,
    )

    config_file_contents = {}
    if os.path.isfile(config.configfile):
        config_file_contents = load_config_file(config.configfile, config.logfile, config.do_logging)
        log_output(f"Using configuration from {config.configfile}", config.logfile, config.do_logging)
    
    file_username = config_file_contents.get("username")
    file_password = config_file_contents.get("password")
    file_domain = config_file_contents.get("domain")
    file_subdomain = config_file_contents.get("subdomain")
    file_totp_secret = config_file_contents.get("totp_secret")
    if file_username and not config.username:
        config.username = file_username
    if file_password and not config.password:
        config.password = file_password
    if file_domain and not config.domain:
        config.domain = file_domain
    if file_subdomain and not config.host:
        config.host = file_subdomain
    if file_totp_secret and not config.totp_secret:
        config.totp_secret = file_totp_secret
    
    config.domain = str.replace(config.domain, "http://", "")
    config.domain = str.replace(config.domain, "https://", "")
    
    if config.address is None:
        config.address = get_external_ip(None, use_ipv6=config.dns_record_type=="AAAA")
    
    return config

def delete_old_logs(log_file_name: str, max_age_days: int):
    # Check and delete log file if limit
    if os.path.isfile(log_file_name):
        log_age = (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(log_file_name))).days
        if log_age > max_age_days:
            os.remove(log_file_name)
            open(log_file_name, 'w').close()
            log_output(f"Log file was older than {max_age_days} days and has been deleted.", log_file_name, config.do_logging)


if __name__ == "__main__":
    
    config = load_config()
    delete_old_logs(config.logfile, 7)

    dns_ip = get_dns_ip(config.get_fqdn(), use_ipv6=config.dns_record_type=="AAAA")
    with open(IP_FILE, 'w+') as file:
        file.write(str(config.address))
    if dns_ip == config.address and not config.do_get_dns_id and not config.force:
        log_output(f"No action needed, DNS entry is up to date. (IP = {dns_ip})", config.logfile, config.do_logging)
        exit()
    log_output(f"Current IP of {config.address} does not match DNS record of {dns_ip}, performing update...", config.logfile, config.do_logging)

    cookies = login(config.username, config.password, config.totp_secret, config.proxies, config.logfile, config.do_logging)
    if not cookies:
        exit()
    log_output(f"Using username: {config.username}", config.logfile, config.do_logging)
    existing_dns_entries = get_dns_entries(cookies, config.proxies, config.do_logging)
    dns_id = None
    log_output(existing_dns_entries, config.logfile, config.do_logging)
    for registed_domain in existing_dns_entries["domains"]:
        if registed_domain["domain_name"] == config.domain:
            for entry in registed_domain["entries"]:
                if entry["name"] == config.get_host() and entry["type"] == config.dns_record_type:
                    dns_id = entry["id"]
                    log_output(f"DNS record ID is {dns_id}", config.logfile, config.do_logging)
                    if entry["content"] == config.address and not (config.do_get_dns_id or config.force):
                        log_output(f"DNS entry with ID {dns_id} ({config.get_fqdn()}) already matches current IP address of {config.address}. DNS up to date, waiting until the record replicates to local nameserver. exiting.", config.logfile, config.do_logging)
                        exit()
            break
    else:
        log_output(f"Domain {config.domain} does not seem to be on your Hover account.", config.logfile, config.do_logging)
        exit()
    if config.do_get_dns_id:
        print(dns_id)
        exit(0)
    if dns_id:
        submit_put_on_existing_dns_entry(dns_id, config.domain, config.host, config.address, config.dns_record_type, cookies, config.proxies, config.logfile, config.do_logging)
    else:
        log_output(f"Could not find a {config.dns_record_type} DNS record for {config.get_fqdn()}. Creating a new one...", config.logfile, config.do_logging)
        submit_post_for_new_dns_entry(config.domain, config.host, config.address, config.dns_record_type, cookies, None, config.logfile, config.do_logging)
    
    exit()