from jwt import decode, encode


class JWTHandler:
    def __init__(self, raw_req, callback_private_key, cosigner_pubkey):
        self.raw_req = raw_req
        self.callback_private_key = callback_private_key
        self.cosigner_pubkey = cosigner_pubkey
        self.request_id = None

    def set_request_id(self, request_id):
        self.request_id = request_id

    def authenticate_request(self):
        decoded_request = decode(
            self.raw_req, self.cosigner_pubkey, algorithms=["RS256"]
        )
        self.set_request_id(decoded_request["requestId"])
        return decoded_request

    def sign_approve_response(self):
        return encode(
            {"action": "APPROVE", "requestId": self.request_id},
            self.callback_private_key,
            algorithm="RS256",
        )

    def sign_reject_response(self):
        return encode(
            {
                "action": "REJECT",
                "rejectionReason": "BTC transaction validation failed",
                "requestId": self.request_id,
            },
            self.callback_private_key,
            algorithm="RS256",
        )
