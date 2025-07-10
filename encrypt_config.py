from cryptography.fernet import Fernet
import json
import base64

# Generate Fernet key
key = Fernet.generate_key()
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
    "encryption_token": key.decode(),
    "json_template": {
        "id": "default_id",
        "data": []
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
print(f"Encryption token: {key.decode()}")  # For reference (stored in config.json)