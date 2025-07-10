import requests
from requests.auth import HTTPProxyAuth
import json
from typing import Optional, Dict
from dataclasses import dataclass
from cryptography.fernet import Fernet
import argparse
import logging
import os
import base64

# Set up logging
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "automation_execution.log")
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.DEBUG,
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

    def validate(self) -> bool:
        """Validate input fields."""
        valid_action_types = {"serviceStart", "serviceStop", "serviceStatus"}
        if not all([self.id, self.actionType, self.serviceName, self.hostname]):
            logging.error("Invalid inputs: All fields must be provided")
            return False
        if self.actionType not in valid_action_types:
            logging.error(f"Invalid actionType: {self.actionType}. Must be one of {valid_action_types}")
            return False
        logging.debug(f"Validated inputs: {self.__dict__}")
        return True

def load_and_decrypt_config() -> Dict:
    """Load and decrypt credentials from config.json."""
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
        
        required_keys = [
            "base_url", "auth_endpoint", "automation_endpoint",
            "proxy_host", "proxy_port", "api_username", "api_password",
            "proxy_username", "proxy_password", "encryption_token", "json_template"
        ]
        for key in required_keys:
            if key not in config:
                logging.error(f"Missing {key} in config file")
                raise ValueError(f"Missing {key} in config file")

        fernet = Fernet(config["encryption_token"].encode())  # Convert string to bytes
        decrypted_config = config.copy()
        # Decrypt passwords
        for key in ["api_password", "proxy_password"]:
            encrypted_value = base64.b64decode(config[key])
            decrypted_value = fernet.decrypt(encrypted_value).decode()
            decrypted_config[key] = decrypted_value
        
        logging.debug(f"Loaded and decrypted config: { {k: v if k not in ['api_password', 'proxy_password', 'encryption_token'] else '****' for k, v in decrypted_config.items()} }")
        return decrypted_config
    
    except FileNotFoundError:
        logging.error("config.json not found")
        raise
    except json.JSONDecodeError:
        logging.error("Invalid JSON format in config.json")
        raise
    except (ValueError, base64.binascii.Error, Fernet.InvalidToken) as e:
        logging.error(f"Error decrypting config: {e}")
        raise

def build_json_payload(inputs: AutomationInput, json_template: Dict) -> Dict:
    """Build JSON payload from inputs using the template."""
    payload = json_template.copy()
    payload["id"] = inputs.id
    # Update variables in extraVariables
    if "extraVariables" in payload and len(payload["extraVariables"]) > 0:
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
    logging.debug(f"Built JSON payload: {payload}")
    return payload

def authenticate(config: Dict, proxies: Dict, proxy_auth: HTTPProxyAuth) -> Optional[str]:
    """Authenticate with the automation tool and retrieve an access token."""
    payload = {
        "grant_type": "password",
        "username": config["api_username"],
        "password": config["api_password"]
    }
    headers = {"Content-Type": "application/json"}

    try:
        logging.info("Attempting authentication")
        response = requests.post(
            f"{config['base_url']}{config['auth_endpoint']}",
            json=payload,
            headers=headers,
            proxies=proxies,
            auth=proxy_auth,
            timeout=10
        )
        response.raise_for_status()
        response_data = response.json()
        access_token = response_data.get("access_token")
        if not access_token:
            logging.error("No access token found in response")
            return None
        logging.info("Authentication successful")
        logging.debug(f"Authentication response: {response_data}")
        return access_token

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"Authentication HTTP error: {http_err}")
        logging.debug(f"Response: {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Authentication request error: {req_err}")
        return None
    except ValueError as json_err:
        logging.error(f"Authentication JSON parsing error: {json_err}")
        return None

def execute_automation(access_token: str, inputs: AutomationInput, config: Dict, 
                      proxies: Dict, proxy_auth: HTTPProxyAuth) -> Optional[Dict]:
    """Execute the automation with the provided inputs."""
    if not inputs.validate():
        logging.error("Automation failed due to invalid inputs")
        return None

    payload = build_json_payload(inputs, config["json_template"])
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        logging.info(f"Executing automation for {inputs.serviceName} ({inputs.actionType}) on {inputs.hostname}")
        response = requests.post(
            f"{config['base_url']}{config['automation_endpoint']}",
            json=payload,
            headers=headers,
            proxies=proxies,
            auth=proxy_auth,
            timeout=15
        )
        response.raise_for_status()
        response_data = response.json()
        logging.info(f"Automation executed successfully: {response_data}")
        return response_data

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"Automation HTTP error: {http_err}")
        logging.debug(f"Response: {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Automation request error: {req_err}")
        return None
    except ValueError as json_err:
        logging.error(f"Automation JSON parsing error: {json_err}")
        return None

def get_command_line_args() -> AutomationInput:
    """Parse command-line arguments for automation inputs."""
    parser = argparse.ArgumentParser(description="Execute automation with dynamic inputs")
    parser.add_argument("--id", required=True, help="Automation ID")
    parser.add_argument("--actionType", required=True, help="Action type (serviceStart, serviceStop, serviceStatus)")
    parser.add_argument("--serviceName", required=True, help="Name of the service")
    parser.add_argument("--hostname", required=True, help="Hostname of the target server")
    args = parser.parse_args()
    logging.debug(f"Command-line arguments: {args.__dict__}")
    return AutomationInput(args.id, args.actionType, args.serviceName, args.hostname)

def main():
    # Load and decrypt config
    try:
        config = load_and_decrypt_config()
    except Exception as e:
        logging.error(f"Failed to load or decrypt config: {e}")
        print(f"Failed to load or decrypt config: {e}")
        return

    # Set up proxy
    proxies = {"https": f"http://{config['proxy_host']}:{config['proxy_port']}"}
    proxy_auth = HTTPProxyAuth(config["proxy_username"], config["proxy_password"])

    # Get command-line inputs
    inputs = get_command_line_args()

    # Authenticate
    access_token = authenticate(config, proxies, proxy_auth)
    if not access_token:
        logging.error("Authentication failed. Exiting.")
        print("Authentication failed. Exiting.")
        return

    # Execute automation
    result = execute_automation(access_token, inputs, config, proxies, proxy_auth)
    if result:
        logging.info("Automation completed successfully.")
        print("Automation completed successfully.")
    else:
        logging.error("Automation failed. Please check logs or inputs.")
        print("Automation failed. Please check logs or inputs.")

if __name__ == "__main__":
    main()