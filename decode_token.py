import base64
import json

def b64url_decode(data):
    data += '=' * (-len(data) % 4)  # Fix padding
    return base64.urlsafe_b64decode(data)

jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InBhc3N3b3JkMSIsImFkbWluIjowLCJmbGFnIjoiVEhNezljYzAzOWNjLWQ4NWYtNDVkMS1hYzNiLTgxOGM4MzgzYTU2MH0ifQ.TkIH_A1zu1mu-zu6_9w_R4FUlYadkyjmXWyD5sqWd5U"

header_b64, payload_b64, signature_b64 = jwt_token.split(".")

header_bytes = b64url_decode(header_b64)
payload_bytes = b64url_decode(payload_b64)
signature_bytes = b64url_decode(signature_b64)

print("Header:", header_bytes.decode('utf-8'))
print("Payload:", payload_bytes.decode('utf-8'))

# Signature is binary — represent as hex or base64
print("Signature (hex):", signature_bytes.hex())
