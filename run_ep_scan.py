import argparse
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="BrightSec Scan Script")
    parser.add_argument('--api_key', type=str, required=True, help="API Key for BrightSec")
    parser.add_argument('--scan_name', type=str, required=True, help="Scan name for BrightSec")
    parser.add_argument('--project_name', type=str, required=True, help="Project name")
    parser.add_argument('--project_id', type=str, required=True, help="Project ID")
    return parser.parse_args()

args = get_args()

api_key = args.api_key  # API key passed as argument
scan_name = args.scan_name  
project_name = args.project_name  
project_id = args.project_id 

# Function to fetch entry points for a specific project
def fetch_entry_points(project_id):
    """Fetch entry points for a specific project from the BrightSec API."""
    headers = {
        "accept": "application/json",
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
    }

    base_url = f'https://app.brightsec.com/api/v2/projects/{project_id}/entry-points'
    url = f"{base_url}?limit=500"
    entry_point_ids = []

    page_number = 1
    while url:
        logger.info(f"Fetching page {page_number} of entry points for project {project_id}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            new_entry_points = [item['id'] for item in data['items'] if item.get('status') != 'tested']
            entry_point_ids.extend(new_entry_points)

            # Pagination handling
            if 'items' in data and data['items']:
                last_id = data['items'][-1]['id']
                last_created_at = data['items'][-1]['createdAt']
                url = f"{base_url}?limit=500&nextId={last_id}&nextCreatedAt={last_created_at}"
                page_number += 1
            else:
                url = None
        else:
            logger.error(f"Failed to fetch data for project {project_id}: {response.status_code}")
            url = None

    logger.info(f"Fetched {len(entry_point_ids)} entry points for project {project_id}.")
    
    # Save entry points to a .txt file
    with open('entrypoints.txt', 'w') as f:
        for entry_point in entry_point_ids:
            f.write(f"{entry_point}\n")
    
    logger.info(f"Entry points have been saved to 'entrypoints.txt'.")
    return entry_point_ids

# Function to start a scan
def start_scan(project_id, project_name, entry_point_ids):
    """Starts a scan with the provided entry points."""
    if len(entry_point_ids) == 0:
        logger.info(f"No entry points found for project {project_name}. Skipping scan.")
        return

    scan_payload = {
        "name": scan_name,
        "poolSize": 10,
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 3,
        "skipStaticParams": True,
        "slowEpTimeout": None,
        "extraHosts": None,
        "fileId": None,
        "targetTimeout": 5,
        "exclusions": {
            "requests": [
                {
                    "patterns": [
                        r"(?<excluded_file_ext>(\/\/[^?#]+\.)((?<image>jpg|jpeg|png|gif|svg|eps|webp|tif|tiff|bmp|psd|ai|raw|cr|pcx|tga|ico)|(?<video>mp4|avi|3gp|flv|h264|m4v|mkv|mov|mpg|mpeg|vob|wmv)|(?<audio>wav|mp3|ogg|wma|mid|midi|aif)|(?<document>doc|docx|odt|pdf|rtf|ods|xls|xlsx|odp|ppt|pptx)|(?<font>ttf|otf|fnt|fon))(?:$|#|\?))"
                    ],
                    "methods": []
                },
                {
                    "patterns": ["logout|signout"]
                }
            ]
        },
        "projectId": project_id,
# Before running the script, verify if a repeater is required. 
# If needed, include the Repeater ID in the payload configuration.
#       "repeaters": ["{REPEATER_ID}"],
        "entryPointIds": entry_point_ids,
        "schedule": {"type": "future", "nextRunAt": "2024-08-24T07:00:54.830Z"},
        "module": "dast",
# Provide the option to select either a bucket of tests or a specific list of individual tests to run against the target.  
# For details about available tests and their functionalities, refer to our documentation -> https://docs.brightsec.com/docs/creating-a-modern-scan
        "tests": [
            "amazon_s3_takeover", 
            "brute_force_login",
            "xxe",
            "cve_test",
            "csrf",
            #"broken_access_control", -> Needs second authentification to be configured and selected before running this test
            "common_files",
            "wordpress",
            "cookie_security", 
            "xss", 
            "css_injection", 
            "default_login_location", 
            "html_injection", 
            "retire_js", 
            "open_cloud_storage", 
            "proto_pollution", 
            "secret_tokens", 
            "stored_xss", 
            "unvalidated_redirect", 
            "version_control_systems", 
            "iframe_injection",
            "bopla", 
            "business_constraint_bypass", 
            "date_manipulation", 
            "excessive_data_exposure", 
            "id_enumeration", 
            "insecure_output_handling", 
            "mass_assignment", 
            "password_reset_poisoning", 
            "prompt_injection",
            "jwt", 
            "broken_saml_auth",  
            "directory_listing", 
            "email_injection", 
            "file_upload", 
            "full_path_disclosure", 
            "graphql_introspection", 
            "header_security", 
            "http_method_fuzzing", 
            "improper_asset_management", 
            "insecure_tls_configuration", 
            "ldapi", 
            "lfi", 
            "nosql", 
            "open_database", 
            "osi", 
            "rfi", 
            "sqli", 
            "server_side_js_injection", 
            "ssrf", 
            "ssti", 
            "xpathi"
            #"lrrl" -> Lack of Resources and Rate Limiting", THIS TEST CAN BE ONLY SELECTED TO RUN SCAN SUCCESSFULLY 
            # "This test checks for API endpoints who lack proper rate limiting and resource management.
            #  Those endpoints might be vulnerable to reset, bruteforcing and Denial of Service attacks."
        ],
#       "buckets": ["api", "business_logic", "client_side", "cve", "legacy", "server_side"],
#        Define which parts of the HTTP(S) request to test for vulnerabilities. 
#        Only parameters of the selected parts will be added to the scan’s attack surface
        "attackParamLocations": ["query", "fragment", "body"],
        "info": {"source": "api"}
    }

    url = f"https://app.brightsec.com/api/v1/scans"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"api-key {api_key}",
    }

    session = requests.Session()
    request = requests.Request('POST', url, headers=headers, json=scan_payload)
    prepared_request = session.prepare_request(request)

    try:
        response = session.send(prepared_request)
        if response.status_code == 201:
            response_json = response.json()
            scan_id = response_json.get('id', 'No ID found in response')
            logger.info(f"Request succeeded with status code 201. Scan ID: {scan_id}")
        else:
            logger.error(f"Request failed with status code {response.status_code}: {response.text}")
    except ValueError as e:
        logger.error(f"ValueError: {e}")

# Fetch entry points and write to file
entry_point_ids = fetch_entry_points(project_id)

# If there are entry points, start the scan
if entry_point_ids:
    start_scan(project_id, project_name, entry_point_ids)

print(f"Entry point IDs have been processed and scans have been initiated.")
