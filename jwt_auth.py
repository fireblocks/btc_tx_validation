from jwt import decode, encode


class JWTHandler:
    def __init__(self, raw_req, callback_private_key, cosigner_pubkey):
        """Callback authentication class.

        :param raw_req: the encoded JWT sent by the co-signer
        :param callback_private_key: the private key that used for signing the response
        :param cosigner_pubkey: the cosigner's public key
        """
        self.raw_req = raw_req
        self.callback_private_key = callback_private_key
        self.cosigner_pubkey = cosigner_pubkey
        self.request_id = None


    def set_request_id(self, request_id):
        """Sets the request id for the instance.
        :param request_id (str): the specific request id
        :return:
        """
        self.request_id = request_id


    def authenticate_request(self):
        """Authenticate a single request sent by the co-signer

        :return: decoded JWT payload (dict)
        """
        decoded_request = decode(
            self.raw_req, self.cosigner_pubkey, algorithms=["RS256"]
        )
        self.set_request_id(decoded_request["requestId"])
        return decoded_request


    def sign_approve_response(self):
        """Sign an approval response

        :return: Encoded JWT (str)
        """
        return encode(
            {"action": "APPROVE", "requestId": self.request_id},
            self.callback_private_key,
            algorithm="RS256",
        )

    def sign_reject_response(self):
        """Sign a rejection response

        :return: Encoded JWT (str)
        """
        return encode(
            {
                "action": "REJECT",
                "rejectionReason": "BTC transaction validation failed",
                "requestId": self.request_id,
            },
            self.callback_private_key,
            algorithm="RS256",
        )
