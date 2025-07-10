from cryptography.fernet import Fernet
import json
import base64

# Generate Fernet key
key = Fernet.generate_key()  # Returns bytes
fernet = Fernet(key)

# Configuration to save
config = {
    "base_url": "https://dev.aa.com",
    "auth_endpoint": "/auth-service/token/",
    "automation_endpoint": "/automation/execute/",
    "proxy_host": "proxy.example.com",
    "proxy_port": 8080,
    "api_username": "api_user",
    "api_password": "api_pass",
    "proxy_username": "proxy_user",
    "proxy_password": "proxy_pass",
    "encryption_token": key.decode(),  # Store as string in config.json
    "json_template": {
        "id": "default_id",
        "extraVariables": [
            {
                "variables": [
                    {
                        "key": "automation_id",
                        "value": ""
                    },
                    {
                        "key": "actionType",
                        "value": ""
                    },
                    {
                        "key": "serviceName",
                        "value": ""
                    },
                    {
                        "key": "hostname",
                        "value": ""
                    }
                ]
            }
        ]
    }
}

# Encrypt passwords
encrypted_config = config.copy()
for key in ["api_password", "proxy_password"]:
    encrypted_value = fernet.encrypt(config[key].encode())
    encrypted_config[key] = base64.b64encode(encrypted_value).decode()

# Save to config.json
with open("config.json", "w") as f:
    json.dump(encrypted_config, f, indent=2)

print("Config file created: config.json")
print(f"Encryption token: {config['encryption_token']}")  # Use stored string