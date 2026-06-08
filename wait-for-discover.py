import requests
import argparse
import time
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api_key', required=True)
    parser.add_argument('--discovery_id', required=True)
    parser.add_argument('--project_id', required=True)
    parser.add_argument('--timeout', type=int, default=3600)
    parser.add_argument('--interval', type=int, default=30)
    return parser.parse_args()

def get_discovery_status(api_key, project_id, discovery_id):
    url = f"https://app.brightsec.com/api/v2/projects/{project_id}/discoveries/{discovery_id}"
    headers = {
        "accept": "application/json",
        "Authorization": f"Api-Key {api_key}"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"Failed to get discovery status: {response.status_code} - {response.text}")
        return None

def wait_for_discovery(api_key, project_id, discovery_id, timeout, interval):
    terminal_states = ["done", "failed", "stopped", "disrupted"]
    elapsed = 0
    logger.info(f"Starting to poll discovery ID: {discovery_id}")
    logger.info(f"Polling every {interval}s, timeout after {timeout}s")

    while elapsed < timeout:
        data = get_discovery_status(api_key, project_id, discovery_id)
        if data is None:
            logger.warning("Could not retrieve status, retrying...")
        else:
            status = data.get("status", "unknown")
            entry_points = data.get("discoveredEntryPoints", 0)
            logger.info(f"Status: {status} | Entry points found: {entry_points} | Elapsed: {elapsed}s")

            if status in terminal_states:
                if status == "done":
                    logger.info(f"Discovery completed! Total entry points: {entry_points}")
                    return True
                else:
                    logger.error(f"Discovery ended with status: {status}")
                    sys.exit(1)

        time.sleep(interval)
        elapsed += interval

    logger.error(f"Timeout reached after {timeout}s")
    sys.exit(1)

if __name__ == "__main__":
    args = get_args()
    wait_for_discovery(args.api_key, args.project_id, args.discovery_id, args.timeout, args.interval)
