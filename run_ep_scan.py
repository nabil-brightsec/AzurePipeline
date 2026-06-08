import argparse
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(description="BrightSec Scan Script")
    parser.add_argument('--api_key', type=str, required=True, help="API Key for BrightSec")
    parser.add_argument('--scan_name', type=str, required=True, help="Scan name")
    parser.add_argument('--project_name', type=str, required=True, help="Project name")
    parser.add_argument('--project_id', type=str, required=True, help="Project ID")
    parser.add_argument('--discovery_id', type=str, required=True, help="Discovery ID")
    return parser.parse_args()

args = get_args()
api_key = args.api_key
scan_name = args.scan_name
project_name = args.project_name
project_id = args.project_id
discovery_id = args.discovery_id

def fetch_entry_points(project_id, discovery_id):
    headers = {
        "accept": "application/json",
        "Authorization": f"api-key {api_key}",
    }
    base_url = f'https://app.brightsec.com/api/v2/projects/{project_id}/discoveries/{discovery_id}/entry-points'
    url = f"{base_url}?limit=500"
    entry_point_ids = []
    page_number = 1

    while url:
        logger.info(f"Fetching page {page_number} of entry points for discovery {discovery_id}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            new_entry_points = [item['id'] for item in data['items'] if item.get('status') != 'tested']
            entry_point_ids.extend(new_entry_points)
            if 'items' in data and data['items']:
                last_id = data['items'][-1]['id']
                last_created_at = data['items'][-1]['createdAt']
                url = f"{base_url}?limit=500&nextId={last_id}&nextCreatedAt={last_created_at}"
                page_number += 1
            else:
                url = None
        else:
            logger.error(f"Failed to fetch entry points: {response.status_code} - {response.text}")
            url = None

    logger.info(f"Fetched {len(entry_point_ids)} entry points for discovery {discovery_id}.")
    with open('entrypoints.txt', 'w') as f:
        for ep in entry_point_ids:
            f.write(f"{ep}\n")
    return entry_point_ids

def start_scan(project_id, project_name, entry_point_ids):
    if len(entry_point_ids) == 0:
        logger.info(f"No entry points found. Skipping scan.")
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
        "entryPointIds": entry_point_ids,
        "schedule": {"type": "now"},
        "module": "dast",
        "tests": [
            "amazon_s3_takeover",
            "brute_force_login",
            "xxe",
            "cve_test",
            "csrf",
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
        ],
        "attackParamLocations": ["query", "fragment", "body"],
        "info": {"source": "api"}
    }

    url = "https://app.brightsec.com/api/v1/scans"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"api-key {api_key}",
    }

    try:
        response = requests.post(url, headers=headers, json=scan_payload)
        if response.status_code == 201:
            scan_id = response.json().get('id', 'No ID found')
            logger.info(f"Scan started successfully! Scan ID: {scan_id}")
        else:
            logger.error(f"Request failed with status code {response.status_code}: {response.text}")
    except Exception as e:
        logger.error(f"Error: {e}")

entry_point_ids = fetch_entry_points(project_id, discovery_id)
if entry_point_ids:
    start_scan(project_id, project_name, entry_point_ids)

print("Entry point IDs have been processed and scan has been initiated.")
