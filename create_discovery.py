import requests
import json
import argparse
import os

def run_discovery(api_key, project_id, target_url,name_discovery):
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
#       "authObjectId": ["7aj2039dn2bcsklla"],
#       "repeaters": ["nqV2nLFHVY97a1RPgeMwBG"],
        "crawlerUrls": [target_url],
        "discoveryTypes": ["crawler"],
        "poolSize": 10
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        
        if response.status_code == 201:
            print(f"Discovery for project {project_id} started successfully!")
        else:
            print(f"Failed to start discovery. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"Error during the discovery: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run a Discovery in BrightSec')
    
    # Command line arguments to pass the API key, project ID, and target URL
    parser.add_argument('--apiKey', required=True, help='BrightSec API Key')
    parser.add_argument('--projectId', required=True, help='Project ID for which the discovery will be run')
    parser.add_argument('--targetUrl', required=True, help='Target URL for the discovery')
    parser.add_argument('--nameDiscovery', required=True, help='Name for the discovery')

    args = parser.parse_args()
    
    # Run the discovery with the provided inputs
    run_discovery(args.apiKey, args.projectId, args.targetUrl, args.nameDiscovery)
