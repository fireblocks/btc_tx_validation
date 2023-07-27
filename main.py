import json
from jwt import DecodeError
from jwt_auth import JWTHandler
from flask import Flask, request, Response
from bitcoin_validator import BitcoinValidator


app = Flask(__name__)


@app.route("/v2/tx_sign_request", methods=["POST"])
def tx_sign_request():
    raw_body = request.data
    with open("cosigner_public.pem", "r") as f1, open(
        "callback_private.pem", "r"
    ) as f2:
        cosigner_pubkey = f1.read()
        callback_private_key = f2.read()
    try:
        jwt_handler = JWTHandler(
            raw_body,
            cosigner_pubkey=cosigner_pubkey,
            callback_private_key=callback_private_key,
        )
        callback_metadata = jwt_handler.authenticate_request()
        if callback_metadata["asset"] == "BTC":
            bitcoin_validator = BitcoinValidator(callback_metadata)
            if bitcoin_validator.validate_tx():
                print("Approve")
                return Response(response=jwt_handler.sign_reject_response())
            print("Reject")
            return Response(response=jwt_handler.sign_reject_response())
    except DecodeError:
        return Response(
            status=401, response=json.dumps({"message": "Authentication Failed"})
        )


if __name__ == "__main__":
    # run app in debug mode on port 8080
    app.run(debug=True, port=8080)
