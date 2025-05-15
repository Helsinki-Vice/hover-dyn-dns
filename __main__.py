import os
import json
import datetime
import argparse

from authentication import login
import logging_out
from logging_out import log_output, LOG_FILE
from dns import IP_FILE, load_config, get_external_ip, get_dns_ip, DEFAULT_PROXIES, get_dns_entries, submit_put_on_existing_dns_entry, submit_post_for_new_dns_entry

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

if __name__ == "__main__":
    # Parse command line arguments
    
    parser = argparse.ArgumentParser(description='Hover DNS Update Script')
    parser.add_argument('--username', nargs='?', help='Hover.com user ID')
    parser.add_argument('--password', nargs="?", help='Hover.com user password')
    parser.add_argument('--totp_secret', nargs="?", help='TOTP shared secret from you hover account')
    parser.add_argument('--addr', nargs="?", help='IP address for the new DNS record, will use current address by default')
    parser.add_argument('--domain', nargs="?", help='Your domain name (i.e example.com) registered at Hover')
    parser.add_argument('--host', nargs="?", help='Hostname (i.e www) for the new record.')
    parser.add_argument('--type', nargs="?", default="A", help='DNS record type (A, AAAA, CNAME, etc.)')
    parser.add_argument('--config', nargs="?", default="config.json", help='File path of the config file, this can be used instead of passing argument')
    parser.add_argument('--logfile', nargs="?", default="hover-update.log", help='File path of the logging file')
    parser.add_argument('--logging', action='store_true', help='Enable logging to hover-update.log')
    parser.add_argument('--mitm', action='store_true', help='Enable mitmproxy for HTTP/HTTPS requests')
    parser.add_argument('--getDNSID', action='store_true', help='Retrieve DNS entries for the account')
    parser.add_argument('--force', action='store_true', help='Forces DNS updates, even if they are already current')
   
    args = parser.parse_args()
    logging = args.logging
    proxies = DEFAULT_PROXIES if args.mitm else None
    LOG_FILE = args.logfile
    logging_out.LOG_FILE = LOG_FILE
    # Check and delete log file if older than 7 days
    if os.path.isfile(LOG_FILE):
        log_age = (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(LOG_FILE))).days
        if log_age > 7:
            os.remove(LOG_FILE)
            open(LOG_FILE, 'w').close()
            log_output("Log file was older than 7 days and has been deleted.", logging)

    # Load configuration
    config = {}
    if os.path.isfile(args.config):
        config = load_config(args.config, logging)
        log_output(f"Using configuration from {args.config}", logging)

    # Extract configuration values
    
    if not config.get('subdomain'):
        config.update({"subdomain": "@"})
    if args.username:
        config.update({"username": args.username})
    if args.password:
        config.update({"password": args.password})
    if args.domain:
        config.update({"domain": args.domain})
    if args.host:
        config.update({"subdomain": args.host})
    if args.totp_secret:
        config.update({"totp_secret": args.totp_secret})
    for required_field in ["username", "password", "domain", "subdomain", "totp_secret"]:
        value = config.get(required_field)
        if not value:
            log_output(f"Required config field '{required_field}' was absent from config file {args.config}.", logging)
            exit(1)
    username = config.get('username')
    password = config.get('password')
    domain = config.get('domain')
    subdomain = config.get('subdomain', "@")
    totp_secret = config.get('totp_secret')
    # Satisfy type checker
    assert(username is not None and password is not None and domain is not None and totp_secret is not None)

    domain = str.replace(domain, "http://", "")
    domain = str.replace(domain, "https://", "")
    if subdomain == "@":
        fq_domain_name = domain
    else:
        fq_domain_name = f"{subdomain}.{domain}"

    if args.addr:
        current_ip = args.addr
    else:
        current_ip = get_external_ip(None)
    dns_ip = get_dns_ip("sean-lauritzen.net")
    with open(IP_FILE, 'w+') as file:
        file.write(current_ip)
    if dns_ip == current_ip and not args.getDNSID and not args.force:
        log_output("No action needed, DNS entry is up to date.", logging)
        exit()
    log_output(f"Current IP of {current_ip} does not match DNS record of {dns_ip}, performing update...", logging)

    cookies = login(username, password, totp_secret, proxies, logging)
    if not cookies:
        exit()
    log_output(f"Using username: {username}", logging)
    existing_dns_entries = get_dns_entries(cookies, None, True)
    dns_id = None
    log_output(existing_dns_entries, logging)
    for d in existing_dns_entries["domains"]:
        if d["domain_name"] == domain:
            for entry in d["entries"]:
                if entry["name"] == subdomain:
                    dns_id = entry["id"]
                    log_output(f"DNS record ID is {dns_id}", logging)
                    if entry["content"] == current_ip and not (args.getDNSID or args.force):
                        log_output(f"DNS entry with ID {dns_id} ({fq_domain_name}) already matches current IP address of {current_ip}. DNS up to date, waiting until the record replicates to local nameserver. exiting.", logging)
                        exit()
            break
    else:
        log_output(f"Domain {domain} does not seem to be on your Hover account.", logging)
        exit()
    if args.getDNSID:
        print(dns_id)
        exit(0)
    if dns_id:
        submit_put_on_existing_dns_entry(dns_id, domain, subdomain, current_ip, args.type, cookies, None, logging)
    else:
        log_output(f"Could not find a DNS entry for {fq_domain_name}. Creating a new one...", logging)
        submit_post_for_new_dns_entry(domain, subdomain, current_ip, args.type, cookies, None, logging)
    
    #submit_put_on_existing_dns_entry(dns_id, domain, subdomain, current_ip, cookies, None, logging)
    exit()

    # Update DNS record
    update_response = update_dns(ipaddress, "@", resolved_ip, cookies, proxies, logging)
    
    try:
        update_response_json = update_response.json()
        update_success = update_response_json.get('succeeded')
    except json.JSONDecodeError:
        log_output(f"Update response is not in JSON format. Status code: {update_response.status_code}, Response text: {update_response.text}", logging)
        exit(2)

    log_output(f"Update response: {update_response_json}", logging)
    if not update_success:
        log_output("Setting failure! Exiting...", logging)
        exit(2)
    else:
        log_output("Setting success!", logging)
        with open(IP_FILE, 'w') as file:
            file.write(ipaddress)
        exit(0)
