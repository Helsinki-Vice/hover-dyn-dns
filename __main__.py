import os
import argparse
from dataclasses import dataclass

from authentication import login
from logging_out import log_output
from dns import IP_FILE, DnsRecord, get_external_ip, get_dns_ip, get_dns_entries, submit_dns_entry_update

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

@dataclass
class Config:
    username: str
    password: str
    totp_secret: str
    dns_records: list[DnsRecord]
    cookiefile: str
    force: bool

def load_config() -> Config:

    parser = argparse.ArgumentParser(description='Hover DNS Update Script')
    parser.add_argument('--username', help='hover.com user ID')
    parser.add_argument('--password', help='hover.com user password')
    parser.add_argument('--totp_secret', help='TOTP shared secret from you hover account')
    parser.add_argument('--addr', nargs="?", help='IP address for the new DNS record, will use current address by default')
    parser.add_argument('--domain', help='Your \"naked\" domain name (i.e example.com) registered at Hover')
    parser.add_argument('--host', nargs="?", help='Comma-seperated list of hostnames (i.e @,www,mail) for the updated record(s). A hostname of @ refers to the naked domain name.')
    parser.add_argument('--type', nargs="?", default="A", help="DNS record type (A, AAAA, CNAME, etc.) for the updated record(s). Usage of 'A,AAAA' will update all IPv4 and IPv6 records for the provided host(s).")
    parser.add_argument('--cookiefile', nargs="?", default="cookies.json", help='File path of the cookie store')
    parser.add_argument('--force', action='store_true', help='Forces DNS updates, even if they are already current')
    args = parser.parse_args()
    records = []

    if args.host is None:
        args.host = "@"
    for host in args.host.split(","):
        for record_type in args.type.split(","):
            records.append(
                DnsRecord(
                    domain = args.domain,
                    host = host,
                    value = args.addr,
                    record_type = record_type
                )
            )
    config = Config(
        username = args.username,
        password = args.password,
        totp_secret = args.totp_secret,
        dns_records = records,
        cookiefile = args.cookiefile,
        force = args.force,
    )

    for record in config.dns_records:
        record.domain = str.replace(record.domain, "http://", "")
        record.domain = str.replace(record.domain, "https://", "")

        if not record.value:
            record.value = get_external_ip(use_ipv6=record.is_ip6())
    
    return config

if __name__ == "__main__":
    
    config = load_config()
    cookies = None
    
    for record in config.dns_records:
        dns_ip = get_dns_ip(record.get_fqdn(), use_ipv6=record.is_ip6())
        if dns_ip == record.value and not config.force:
            exit()
        log_output(f"Current IP of {record.value} does not match DNS record of {dns_ip}, performing update...")

        if not cookies:
            cookies = login(config.username, config.password, config.totp_secret)
        if not cookies:
            exit()
        log_output(f"Using username: {config.username}")
        existing_dns_entries = get_dns_entries(cookies, True)
        dns_id = None
        log_output(existing_dns_entries)
        for registed_domain in existing_dns_entries["domains"]:
            if registed_domain["domain_name"] == record.domain:
                for entry in registed_domain["entries"]:
                    if entry["name"] == record.get_host() and entry["type"] == record.record_type:
                        dns_id = entry["id"]
                        log_output(f"DNS record ID is {dns_id}")
                        if entry["content"] == record.value and not config.force:
                            log_output(f"DNS entry with ID {dns_id} ({record.get_fqdn()}) already matches current IP address of {record.value}. DNS up to date, waiting until the record replicates to local nameserver. exiting.")
                            exit()
                break
        else:
            log_output(f"Domain {record.domain} does not seem to be on your Hover account.")
            exit()

        submit_dns_entry_update(record, cookies, dns_id)

        if not dns_id:
            log_output(f"Could not find a {record.record_type} DNS record for {record.get_fqdn()}. Creating a new one...")

        with open(IP_FILE, 'w+') as file:
            file.write(str(record.value))
    
    exit()