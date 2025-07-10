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
        
        # Log proxy details (mask password)
        logging.debug(f"Loaded and decrypted config: { {k: v if k not in ['api_password', 'proxy_password', 'encryption_token'] else '****' for k, v in decrypted_config.items()} }")
        logging.debug(f"Proxy configuration: host={config['proxy_host']}, port={config['proxy_port']}, username={config['proxy_username']}, password=****")
        # Temporary debug logging for decrypted credentials (remove after debugging)
        logging.debug(f"Decrypted proxy_username: {decrypted_config['proxy_username']}")
        logging.debug(f"Decrypted proxy_password: {decrypted_config['proxy_password']}")
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

def authenticate(config: Dict, proxies: Dict, verify_ssl: bool = False) -> Optional[str]:
    """Authenticate with the automation tool and retrieve an access token."""
    payload = {
        "grant_type": "password",
        "username": config["api_username"],
        "password": config["api_password"]
    }
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "curl/7.68.0"  # Mimic curl's User-Agent
    }

    try:
        logging.info("Attempting authentication")
        session = requests.Session()
        session.proxies = proxies
        logging.debug(f"Authentication request headers: {headers}")
        logging.debug(f"Authentication proxies: {proxies}")
        logging.debug(f"SSL verification: {verify_ssl}")
        response = session.post(
            f"{config['base_url']}{config['auth_endpoint']}",
            json=payload,
            headers=headers,
            timeout=10,
            verify=verify_ssl  # Set to False to match working code
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

    except requests.exceptions.SSLError as ssl_err:
        logging.error(f"SSL verification failed: {ssl_err}")
        logging.debug("SSL verification is disabled (verify=False). For production, provide a CA certificate bundle.")
        return None
    except requests.exceptions.HTTPError as http_err:
        if http_err.response and http_err.response.status_code == 407:
            logging.error("Proxy authentication failed: 407 Proxy Authentication Required")
            logging.debug(f"Proxy details: {proxies}")
        else:
            logging.error(f"Authentication HTTP error: {http_err}")
            logging.debug(f"Response: {http_err.response.text if http_err.response else 'No response'}")
        return None
    except requests.exceptions.ProxyError as proxy_err:
        logging.error(f"Proxy error: {proxy_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Authentication request error: {req_err}")
        return None
    except ValueError as json_err:
        logging.error(f"Authentication JSON parsing error: {json_err}")
        return None

def execute_automation(access_token: str, inputs: AutomationInput, config: Dict, 
                      proxies: Dict, verify_ssl: bool = False) -> Optional[Dict]:
    """Execute the automation with the provided inputs."""
    if not inputs.validate():
        logging.error("Automation failed due to invalid inputs")
        return None

    payload = build_json_payload(inputs, config["json_template"])
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "User-Agent": "curl/7.68.0"  # Mimic curl's User-Agent
    }

    try:
        logging.info(f"Executing automation for {inputs.serviceName} ({inputs.actionType}) on {inputs.hostname}")
        session = requests.Session()
        session.proxies = proxies
        logging.debug(f"Automation request headers: {headers}")
        logging.debug(f"Automation proxies: {proxies}")
        logging.debug(f"SSL verification: {verify_ssl}")
        response = session.post(
            f"{config['base_url']}{config['automation_endpoint']}",
            json=payload,
            headers=headers,
            timeout=15,
            verify=verify_ssl  # Set to False to match working code
        )
        response.raise_for_status()
        response_data = response.json()
        logging.info(f"Automation executed successfully: {response_data}")
        return response_data

    except requests.exceptions.SSLError as ssl_err:
        logging.error(f"SSL verification failed: {ssl_err}")
        logging.debug("SSL verification is disabled (verify=False). For production, provide a CA certificate bundle.")
        return None
    except requests.exceptions.HTTPError as http_err:
        if http_err.response and http_err.response.status_code == 407:
            logging.error("Proxy authentication failed: 407 Proxy Authentication Required")
            logging.debug(f"Proxy details: {proxies}")
        else:
            logging.error(f"Automation HTTP error: {http_err}")
            logging.debug(f"Response: {http_err.response.text if http_err.response else 'No response'}")
        return None
    except requests.exceptions.ProxyError as proxy_err:
        logging.error(f"Automation proxy error: {proxy_err}")
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

    # Set up proxy with URL-encoded credentials
    proxy_username = urllib.parse.quote(config["proxy_username"])
    proxy_password = urllib.parse.quote(config["proxy_password"])
    proxy_string = f"http://{proxy_username}:{proxy_password}@{config['proxy_host']}:{config['proxy_port']}"
    proxies = {"https": proxy_string}
    logging.debug(f"Constructed proxy string: {proxies}")
    # proxies = {}  # Uncomment for no-proxy debugging

    # Get command-line inputs
    inputs = get_command_line_args()

    # Authenticate
    access_token = authenticate(config, proxies)
    if not access_token:
        logging.error("Authentication failed. Exiting.")
        print("Authentication failed. Exiting.")
        return

    # Execute automation
    result = execute_automation(access_token, inputs, config, proxies)
    if result:
        logging.info("Automation completed successfully.")
        print("Automation completed successfully.")
    else:
        logging.error("Automation failed. Please check logs or inputs.")
        print("Automation failed. Please check logs or inputs.")

if __name__ == "__main__":
    main()