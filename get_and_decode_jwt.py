import base64
import json
import jwt
import requests
import sys


def b64url_decode(data):
    data += '=' * (-len(data) % 4)  # Fix padding
    return base64.urlsafe_b64decode(data)

# Send the request to the server to obtain token and store in token
url = f"http://{sys.argv[1]}/api/v1.0/example1"
headers = {
    "Content-Type": "application/json"
}
data = {
    "username": "user",
    "password": "password1"
}

response = requests.post(url, headers=headers, json=data)
json_string = response.text
response_data = json.loads(json_string)
jwt_token = response_data["token"]
header_b64, payload_b64, signature_b64 = jwt_token.split(".")

header_bytes = b64url_decode(header_b64)
payload_bytes = b64url_decode(payload_b64)
signature_bytes = b64url_decode(signature_b64)

print("Header:", header_bytes.decode('utf-8'))
print("Payload:", payload_bytes.decode('utf-8'))

# Signature is binary — represent as hex or base64
print("Signature (hex):", signature_bytes.hex())

