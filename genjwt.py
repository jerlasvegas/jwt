import jwt

class JWT:
    def __init__(self):
        self.username = ''
        self.password = ''

    def get_payload(self):
        payload = {
            'username' : self.username,
            'password' : self.password,
        }

        access_token = jwt.encode(payload, self.secret, algorithm="HS256")
        print (access_token)
