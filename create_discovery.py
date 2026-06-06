import requests
import json
import argparse
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(description='Run a Discovery in Bright Security')
    parser.add_argument('--apiKey', required=True, help='Bright Security API Key')
    parser.add_argument('--projectId', required=True, help='Project ID for which the discovery will be run')
    parser.add_argument('--targetUrl', required=True, help='Target URL for the discovery')
    parser.add_argument('--nameDiscovery', required=True, help='Name for the discovery')
    return parser.parse_args()

def run_discovery(api_key, project_id, target_url, name_discovery):
    url = f"https://app.brightsec.com/api/v2/projects/{project_id}/discoveries"

    headers = {
        'Authorization': f"Api-Key {api_key}",
        'Content-Type': 'application/json'
    }

    payload = {
        "name": name_discovery,
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
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 3,
        "slowEpTimeout": None,
        "subdomainsCrawl": False,
        "crawlerUrls": [target_url],
        "discoveryTypes": ["crawler"],
        "poolSize": 10
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))

        if response.status_code == 201:
            response_data = response.json()

            # ── The discovery ID comes back in the response ──
            discovery_id = response_data.get("id")

            if not discovery_id:
                logger.error("Discovery started but no ID returned in response.")
                logger.error(f"Full response: {response_data}")
                sys.exit(1)

            logger.info(f"Discovery started successfully! ID: {discovery_id}")

            # ── Pass the ID to the next Azure Pipeline stage ──
            # This is the Azure DevOps way to set a variable that other stages can read
            print(f"##vso[task.setvariable variable=DISCOVERY_ID;isOutput=true]{discovery_id}")
            print(f"Discovery ID: {discovery_id}")

        else:
            logger.error(f"Failed to start discovery. Status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error during discovery: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    args = get_args()
    run_discovery(args.apiKey, args.projectId, args.targetUrl, args.nameDiscovery)
