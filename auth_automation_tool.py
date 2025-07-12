import requests
import json
from typing import Optional, Dict
from dataclasses import dataclass
from cryptography.fernet import Fernet
import argparse
import logging
import os
import base64
import urllib.parse

# Set up logging
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "automation_execution.log")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=LOG_FILE,
    filemode="a"
)

@dataclass
class AutomationInput:
    id: str
    actionType: str
    serviceName: str
    hostname: str

def load_config() -> Dict:
    """Load and decrypt credentials from config.json."""
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
        
        fernet = Fernet(config["encryption_token"].encode())
        decrypted_config = config.copy()
        for key in ["api_password", "proxy_password"]:
            encrypted_value = base64.b64decode(config[key])
            decrypted_config[key] = fernet.decrypt(encrypted_value).decode()
        
        logging.info("Loaded and decrypted config")
        return decrypted_config
    
    except Exception as e:
        logging.error(f"Failed to load or decrypt config: {e}")
        raise

def test_proxy_connection(base_url: str, proxies: Dict) -> bool:
    """Test proxy connection by making a GET request to the base URL."""
    try:
        logging.info(f"Testing proxy connection to {base_url}")
        session = requests.Session()
        session.proxies = proxies
        response = session.get(base_url, headers={"User-Agent": "curl/7.68.0"}, timeout=10, verify=False)
        response.raise_for_status()
        logging.info(f"Proxy connection test successful: Status {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        logging.error(f"Proxy connection test failed: {e}")
        return False

def build_json_payload(inputs: AutomationInput, json_template: Dict) -> Dict:
    """Build JSON payload from inputs using the template."""
    payload = json_template.copy()
    payload["id"] = inputs.id
    if "extraVariables" in payload and payload["extraVariables"]:
        variables = payload["extraVariables"][0]["variables"]
        for var in variables:
            if var["key"] == "automation_id":
                var["value"] = inputs.id
            elif var["key"] == "actionType":
                var["value"] = inputs.actionType
            elif var["key"] == "serviceName":
                var["value"] = inputs.serviceName
            elif var["key"] == "hostname":
                var["value"] = inputs.hostname
    logging.info("Built JSON payload")
    return payload

def authenticate(config: Dict, proxies: Dict) -> Optional[str]:
    """Authenticate and retrieve an access token."""
    try:
        payload = {
            "grant_type": "password",
            "username": config["api_username"],
            "password": config["api_password"]
        }
        headers = {"Content-Type": "application/json", "User-Agent": "curl/7.68.0"}
        session = requests.Session()
        session.proxies = proxies
        logging.info("Attempting authentication")
        response = session.post(
            f"{config['base_url']}{config['auth_endpoint']}",
            json=payload,
            headers=headers,
            timeout=10,
            verify=False
        )
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            logging.error("No access token found in response")
            return None
        logging.info("Authentication successful")
        return access_token
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 407:
            logging.error("Proxy authentication failed: 407 Proxy Authentication Required")
        else:
            logging.error(f"Authentication HTTP error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Authentication request error: {e}")
        return None

def execute_automation(access_token: str, inputs: AutomationInput, config: Dict, proxies: Dict) -> Optional[Dict]:
    """Execute the automation with the provided inputs."""
    try:
        payload = build_json_payload(inputs, config["json_template"])
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
            "User-Agent": "curl/7.68.0"
        }
        session = requests.Session()
        session.proxies = proxies
        logging.info(f"Executing automation for {inputs.serviceName} ({inputs.actionType}) on {inputs.hostname}")
        response = session.post(
            f"{config['base_url']}{config['automation_endpoint']}",
            json=payload,
            headers=headers,
            timeout=15,
            verify=False
        )
        response.raise_for_status()
        logging.info("Automation executed successfully")
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code == 407:
            logging.error("Proxy authentication failed: 407 Proxy Authentication Required")
        else:
            logging.error(f"Automation HTTP error: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Automation request error: {e}")
        return None

def get_command_line_args() -> AutomationInput:
    """Parse command-line arguments for automation inputs."""
    parser = argparse.ArgumentParser(description="Execute automation with dynamic inputs")
    parser.add_argument("--id", required=True, help="Automation ID")
    parser.add_argument("--actionType", required=True, help="Action type")
    parser.add_argument("--serviceName", required=True, help="Name of the service")
    parser.add_argument("--hostname", required=True, help="Hostname of the target server")
    args = parser.parse_args()
    logging.info(f"Parsed command-line arguments: id={args.id}, actionType={args.actionType}, serviceName={args.serviceName}, hostname={args.hostname}")
    return AutomationInput(args.id, args.actionType, args.serviceName, args.hostname)

def main():
    # Load and decrypt config
    try:
        config = load_config()
    except Exception as e:
        print(f"Failed to load or decrypt config: {e}")
        return

    # Set up proxy with URL-encoded credentials
    proxy_username = urllib.parse.quote(config["proxy_username"])
    proxy_password = urllib.parse.quote(config["proxy_password"])
    proxy_string = f"http://{proxy_username}:{proxy_password}@{config['proxy_host']}:{config['proxy_port']}"
    proxies = {"http": proxy_string, "https": proxy_string}
    logging.info(f"Constructed proxy string: http://{proxy_username}:[REDACTED]@{config['proxy_host']}:{config['proxy_port']}")

    # Test proxy connection
    if not test_proxy_connection(config["base_url"], proxies):
        print("Proxy connection test failed. Check logs for details.")
        return

    # Get command-line inputs
    inputs = get_command_line_args()

    # Authenticate
    access_token = authenticate(config, proxies)
    if not access_token:
        print("Authentication failed. Check logs for details.")
        return

    # Execute automation
    result = execute_automation(access_token, inputs, config, proxies)
    if result:
        print("Automation completed successfully.")
    else:
        print("Automation failed. Check logs for details.")

if __name__ == "__main__":
    main()