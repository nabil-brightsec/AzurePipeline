import requests
import argparse
import time
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(description="Wait for Bright Security Discovery to complete")
    parser.add_argument('--api_key', type=str, required=True, help="Bright Security API Key")
    parser.add_argument('--discovery_id', type=str, required=True, help="Discovery ID to poll")
    parser.add_argument('--timeout', type=int, default=3600, help="Max wait time in seconds (default: 3600 = 1 hour)")
    parser.add_argument('--interval', type=int, default=30, help="Polling interval in seconds (default: 30)")
    return parser.parse_args()

def get_discovery_status(api_key, discovery_id):
    """Poll the Bright API for discovery status."""
    url = f"https://app.brightsec.com/api/v2/discoveries/{discovery_id}"
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

def wait_for_discovery(api_key, discovery_id, timeout, interval):
    """Poll until discovery is done, failed, or timeout reached."""
    # Terminal states — discovery is no longer running
    terminal_states = ["done", "failed", "stopped", "disrupted"]

    elapsed = 0
    logger.info(f"Starting to poll discovery ID: {discovery_id}")
    logger.info(f"Polling every {interval}s, timeout after {timeout}s")

    while elapsed < timeout:
        data = get_discovery_status(api_key, discovery_id)

        if data is None:
            logger.warning("Could not retrieve status, retrying...")
        else:
            status = data.get("status", "unknown")
            entry_points = data.get("discoveredEntryPoints", 0)
            logger.info(f"Status: {status} | Entry points found so far: {entry_points} | Elapsed: {elapsed}s")

            if status in terminal_states:
                if status == "done":
                    logger.info(f"Discovery completed successfully! Total entry points: {entry_points}")
                    return True
                else:
                    logger.error(f"Discovery ended with status: {status}. Cannot proceed with scan.")
                    sys.exit(1)

        time.sleep(interval)
        elapsed += interval

    logger.error(f"Timeout reached after {timeout}s. Discovery did not complete in time.")
    sys.exit(1)

if __name__ == "__main__":
    args = get_args()
    wait_for_discovery(args.api_key, args.discovery_id, args.timeout, args.interval)
