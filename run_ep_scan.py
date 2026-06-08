import argparse
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(description="BrightSec Scan Script")
    parser.add_argument('--api_key', type=str, required=True)
    parser.add_argument('--scan_name', type=str, required=True)
    parser.add_argument('--project_name', type=str, required=True)
    parser.add_argument('--project_id', type=str, required=True)
    parser.add_argument('--discovery_id', type=str, required=True)
    return parser.parse_args()

args = get_args()
api_key = args.api_key
scan_name = args.scan_name
project_name = args.project_name
project_id = args.project_id
discovery_id = args.discovery_id

def get_project_uuid(project_id):
    url = f"https://app.brightsec.com/api/v1/projects/{project_id}"
    headers = {
        "accept": "application/json",
        "Authorization": f"api-key {api_key}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        logger.info(f"Project ID confirmed: {data.get('id')}")
        return data
    else:
        logger.error(f"Failed to get project: {response.status_code} - {response.text}")
        return None

def fetch_entry_points(project_id, discovery_id):
    headers = {
        "accept": "application/json",
        "Authorization": f"api-key {api_key}",
    }
    base_url = f'https://app.brightsec.com/api/v2/projects/{project_id}/entry-points'
    entry_point_ids = []
    page_number = 1
    next_id = None
    next_created_at = None

    while True:
        url = f"{base_url}?limit=10&scanId={discovery_id}"
        if next_id and next_created_at:
            url += f"&nextId={next_id}&nextCreatedAt={next_created_at}"

        logger.info(f"Fetching page {page_number} of entry points")
        logger.info(f"URL: {url}")
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            logger.error(f"Failed to fetch entry points: {response.status_code} - {response.text}")
            break

        data = response.json()
        items = data.get('items', [])

        if not items:
            logger.info("No more items found.")
            break

        new_entry_points = [item['id'] for item in items if item.get('connectivity') != 'skipped']
        entry_point_ids.extend(new_entry_points)
        logger.info(f"Page {page_number}: got {len(items)} items, {len(new_entry_points)} usable")

        if len(items) < 10:
            break

        next_id = items[-1]['id']
        next_created_at = items[-1]['createdAt']
        page_number += 1

    logger.info(f"Total entry points fetched: {len(entry_point_ids)}")
    return entry_point_ids

def start_scan(entry_point_ids, project_uuid):
    if not entry_point_ids:
        logger.info("No entry points found. Skipping scan.")
        return

    scan_payload = {
        "name": scan_name,
        "projectId": project_uuid,
        "poolSize": 10,
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 3,
        "skipStaticParams": True,
        "entryPointIds": entry_point_ids,
        "module": "dast",
        "attackParamLocations": ["query", "fragment", "body"],
        "tests": [
            "amazon_s3_takeover", "brute_force_login", "xxe", "cve_test", "csrf",
            "common_files", "wordpress", "cookie_security", "xss", "css_injection",
            "default_login_location", "html_injection", "retire_js", "open_cloud_storage",
            "proto_pollution", "secret_tokens", "stored_xss", "unvalidated_redirect",
            "version_control_systems", "iframe_injection", "bopla", "business_constraint_bypass",
            "date_manipulation", "excessive_data_exposure", "id_enumeration",
            "insecure_output_handling", "mass_assignment", "password_reset_poisoning",
            "prompt_injection", "jwt", "broken_saml_auth", "directory_listing",
            "email_injection", "file_upload", "full_path_disclosure", "graphql_introspection",
            "header_security", "http_method_fuzzing", "improper_asset_management",
            "insecure_tls_configuration", "ldapi", "lfi", "nosql", "open_database",
            "osi", "rfi", "sqli", "server_side_js_injection", "ssrf", "ssti", "xpathi"
        ],
        "info": {"source": "api"}
    }

    url = "https://app.brightsec.com/api/v1/scans"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"api-key {api_key}",
    }

    response = requests.post(url, headers=headers, json=scan_payload)
    if response.status_code == 201:
        scan_id = response.json().get('id', 'No ID found')
        logger.info(f"Scan started successfully! Scan ID: {scan_id}")
    else:
        logger.error(f"Scan failed: {response.status_code} - {response.text}")

entry_point_ids = fetch_entry_points(project_id, discovery_id)
project_data = get_project_uuid(project_id)
if project_data:
    project_uuid = project_data.get('id', project_id)
    logger.info(f"Using project UUID: {project_uuid}")
    start_scan(entry_point_ids, project_uuid)
else:
    logger.error("Could not retrieve project UUID. Aborting scan.")
print("Done.")
