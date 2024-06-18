import time
import os
import argparse
import configparser
import rich
from dotenv import load_dotenv
from zapv2 import ZAPv2
from bs4 import BeautifulSoup

# ------------------------------------
# $ Configuration
# ------------------------------------
# ZAP API key and base URL
load_dotenv()
api_key = os.getenv('API_KEY')
base_url = 'http://localhost:8080'

# Target URL to scan
target_url = 'http://testphp.vulnweb.com/guestbook.php'

# Session Variables
isNewSession = True
sessionName = "sentinel_test_session"

# Risk Levels
risk_levels = {
    'Informational': 0,
    'Low': 1,
    'Medium': 2,
    'High': 3,
}

# ------------------------------------
# $ Script Process
# ------------------------------------


def create_default_config(config_file):
    # Create a new config file with default values
    config = configparser.ConfigParser()

    print("Configuration file not found or empty. Please provide the following details:")

    zap_url = input("Enter ZAP URL (default: http://localhost:8080): ") or "http://localhost:8080"
    api_key = input("Enter ZAP API key (default: None): ") or "None"
    depth = input("Enter spider max depth (default: 0): ") or "0"
    duration = input("Enter scan max duration in seconds (default: 3000): ") or "3000"

    config['ZAP'] = {
        'zap_url': zap_url,
        'api_key': api_key
    }

    config['Scan'] = {
        'depth': depth,
        'duration': duration
    }

    with open(config_file, 'w') as configfile:
        config.write(configfile)
    config_path = os.path.abspath(__file__)
    config_path = os.path.dirname(config_path)
    config_path = os.path.join(config_path, config_file)
    print(f"Configuration saved to {config_path}")

def read_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    zap_url = config.get('ZAP', 'zap_url')
    api_key = config.get('ZAP', 'api_key')
    depth = config.getint('Scan', 'depth')
    duration = config.getint('Scan', 'duration')

    return zap_url, api_key, depth, duration

# Control flow based on target selection
def switch(cond):
    if cond == 1:
        scan_web_app(base_url, api_key)
    elif cond == 2:
        scan_html()

# Interactive Welcome Screen
# ================================
def show_welcome_screen():
    print('Welcome to Sentinel VS, a straightforward CLI tool for checking application vulnerabilities!')
    print("=================================")

    time.sleep(1)

    print('1. Scan web application/website for vulnerabilities.')
    print('2. Scan HTML file for vulnerabilities.')
    print("=================================")

    print('What would you like to scan today? Please select from the list above [1-2]: ', end=''),
    userTargetSelection = int(input())

    if userTargetSelection < 1 or userTargetSelection > 2:
        print("ERROR: Invalid or improper selection. Please try again.")
        exit()

    switch(userTargetSelection)

# Run ZAP Scan
# ================================
def filter_normal(zap_report):
    """ 
    Filter the results of a ZAP report/scan with no specific filtering or prioritization.

    Parameters
    ------------
    zap_report : any
        object or array of alerts from ZAP

    """
    pos = 1
    for alert in zap_report.alerts(baseurl=target_url):
        print(f"{ pos }. { alert['alert'] }")
        pos += 1

def filter_by_risk(zap_report):
    """ 
    Filter the results of a ZAP report/scan by risk level, i.e. high, low, etc.

    Parameters
    ------------
    zap_report : any
        object or array of alerts from ZAP
    """
    for (name, value) in risk_levels.items():
        print("--------------------------------")
        print(name)
        print("--------------------------------")
        pos = 1
        for alert in zap_report.alerts(baseurl=target_url, riskid=value):
            print(f"{ pos }. { alert['alert'] }")
            pos += 1

def scan_web_app(zapurl, target, apikey, depth, duration):
    # =============================
    # START
    # =============================
    # Initialize ZAP API client
    zap = ZAPv2(apikey=apikey, proxies={'http': zapurl, 'https': zapurl})
    core = zap.core

    # Start a new ZAP session
    if isNewSession:
        print('Create ZAP session: ' + sessionName + ' -> ' +
            core.new_session(name=sessionName, overwrite=True))
    else:
        print('Load ZAP session: ' + sessionName + ' -> ' +
            core.load_session(name=sessionName))

    # Open the URL in ZAP
    print(f"Accessing target {target}")
    zap.urlopen(target)
    time.sleep(2)

    # =============================
    # START SPIDER SCAN
    # =============================
    # Start the spider scan
    print(f"Starting spider scan on {target}")
    scan_id = zap.spider.scan(target, maxchildren=depth)

    # Poll the status until the spider scan is complete
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider scan progress: {zap.spider.status(scan_id)}%")
        time.sleep(2)

    print("----------------------------")
    print("Spider scan completed.")
    print("----------------------------")

    # =============================
    # START ACTIVE SCAN
    # =============================
    print(f"Starting active scan on {target}")
    scan_id = zap.ascan.scan(target)

    # Poll the status until the active scan is complete
    start_time = time.time()
    while int(zap.ascan.status(scan_id)) < 100:
        elapsed_time = time.time() - start_time
        if elapsed_time > duration:
            print('Maximum duration reached, stopping the scan...')
            zap.ascan.stop(scan_id)
            break
        print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(3)

    print("----------------------------")
    print("Active scan completed")
    print("----------------------------")
    print("#############################################")

    # =============================
    # PRINT RESULTS
    # =============================
    print("Scan report:")

    # Filter results by Risk Level
    # filter_normal(core)
    filter_by_risk(core)

    # Summary of alerts grouped by risk level.
    alerts_summary = core.alerts_summary(baseurl=target).items()

    print("#############################################")

    print("Scanning process completed. Scan found ", end='')

    # List number of vulnerabilities found by risk level.
    for idx, (alert, count) in enumerate(alerts_summary):
        if idx == len(alerts_summary) - 1:
            print(f"{count} {alert} vulnerabilities. ", end='')
        else:
            print(f"{count} {alert} vulnerabilities, ", end='')

    print("Please refer to the full report above for more information.")

def scan_html():
    print("Scanned Codebase")
    return 1

def main():
    # Open Config File
    config_file = 'config.ini'

    # Check if config file exits, if not create it
    if not os.path.exists(config_file) or os.path.getsize(config_file) == 0:
        create_default_config(config_file)
        return

    # Read data from config file.
    zapurl, apikey, depth, duration = read_config(config_file)

    # Create the top-level parser
    parser = argparse.ArgumentParser(description='Sentinel VS')
    
    # Create a subparsers object to hold the sub-commands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Define a 'scan' command
    scan_parser = subparsers.add_parser('scanweb', help='Perform an active scan')
    scan_parser.add_argument('target', type=str, help='The target URL for scanning')
    scan_parser.add_argument('--zapurl', type=str, help='The local URL for scanning proxy')
    scan_parser.add_argument('--apikey', type=str, help='API key for ZAP')
    scan_parser.add_argument('--depth', type=int, default=0, help='Maximum depth for scan. Default: 0 (infinite)')
    scan_parser.add_argument('--duration', type=float, default=300, help='Maximum duration of scan in seconds. Default: 300')

    # Define an 'interactive' command
    scan_parser = subparsers.add_parser('inter', help='Starts sentinel in the interactive mode.')
    
    # Define a 'report' command
    report_parser = subparsers.add_parser('report', help='Generate a scan report')
    report_parser.add_argument('scan_id', type=str, help='The ID of the scan')
    report_parser.add_argument('--format', type=str, choices=['json', 'html'], default='json', help='The format of the report')
    
    # Parse the arguments
    args = parser.parse_args()

    # Override with command-line arguments if provided
    if args.zapurl:
        zapurl = args.zapurl
    if args.apikey:
        apikey = args.apikey
    if args.depth is not None:
        depth = args.depth
    if args.duration is not None:
        duration = args.duration
    
    print("Config file found. Using it in the following scan...")
    # Call the appropriate function based on the command
    if args.command == 'scanweb':
        scan_web_app(zapurl, args.target, apikey, depth, duration)
    elif args.command == 'report':
        print("report")
    elif args.command == 'inter':
        show_welcome_screen()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()