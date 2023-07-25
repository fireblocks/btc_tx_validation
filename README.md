# BTC transaction validation on the Co-Signer callback handler

BTC transactions are more complex than ETH. This is due the UTXO (Unspent transaction output) model. In addition to the complex transaction model, BTC transactions can be of different types:

Legacy transactions
SegWit (Segregated Witness) transactions

SegWit in a nutshell - it is an improvement over the current bitcoin blockchain which reduces the size needed to store transactions in a block. This is done by removing certain signatures with counting serialized witness data as one unit and core block data as four units.

Legacy addresses begin with 1 (for example: ```1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC```)
SegWit addresses begin with bc1 (for example: ```bc1q3j5qmxchekaykrumz97f9pfv5p9xj7petf645z```)


## BTC callback payload example

```json
{
  "txId": "3acaf94b-e77f-41f3-b68e-a1fa26e131f9",
  "operation": "TRANSFER",
  "sourceType": "VAULT",
  "sourceId": "0",
  "destType": "ONE_TIME_ADDRESS",
  "destId": "",
  "asset": "BTC",
  "amount": 0.000876,
  "amountStr": "0.00087600",
  "requestedAmount": 0.000876,
  "requestedAmountStr": "0.000876",
  "fee": "0.00004164",
  "destAddressType": "ONE_TIME",
  "destAddress": "1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC",
  "destinations": [
    {
      "amountNative": 0.000876,
      "amountNativeStr": "0.000876",
      "amountUSD": 25.64271683,
      "dstAddress": "1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC",
      "dstAddressType": "ONE_TIME",
      "dstId": "",
      "dstType": "ONE_TIME_ADDRESS",
      "displayDstAddress": "1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC",
      "action": "ALLOW",
      "actionInfo": {
        "capturedRuleNum": 5,
        "rulesSnapshotId": 8164,
        "byGlobalPolicy": false,
        "byRule": true,
        "capturedRule": "{\"type\":\"TRANSFER\",\"transactionType\":\"TRANSFER\",\"asset\":\"*\",\"amount\":0,\"operators\":{\"wildcard\":\"*\"},\"applyForApprove\":true,\"action\":\"ALLOW\",\"src\":{\"ids\":[[\"*\"]]},\"dst\":{\"ids\":[[\"*\"]]},\"dstAddressType\":\"*\",\"amountCurrency\":\"USD\",\"amountScope\":\"SINGLE_TX\",\"periodSec\":0}"
      }
    }
  ],
  "rawTx": [
    {
      "keyDerivationPath": "[ 44, 0, 0, 0, 0 ]",
      "rawTx": "0100000002c845e228b169e8713414f51f5a60a1c670aaf57138811279ddc3b530fe4c4ac8000000001976a91495f6fbf9976938f6bffc646adf8b54a8f70620eb88acffffffffa3d781905b0122466f72efa1f751cf8e2cb9f6fda8efedf989443bd358ec5f480000000000ffffffff0230560100000000001976a9148ca80d9b17cdba4b0f9b117c92852ca04a69783988ac2b4901000000000016001495f6fbf9976938f6bffc646adf8b54a8f70620eb0000000001000000",
      "payload": "74bac76ffa277c14ba33ff1be302ed07e0a1e5dceebdc5f161df8d9d688b613c"
    },
    {
      "keyDerivationPath": "[ 44, 0, 0, 0, 0 ]",
      "rawTx": "0100000002c845e228b169e8713414f51f5a60a1c670aaf57138811279ddc3b530fe4c4ac80000000000ffffffffa3d781905b0122466f72efa1f751cf8e2cb9f6fda8efedf989443bd358ec5f48000000001976a91495f6fbf9976938f6bffc646adf8b54a8f70620eb88acffffffff0230560100000000001976a9148ca80d9b17cdba4b0f9b117c92852ca04a69783988ac2b4901000000000016001495f6fbf9976938f6bffc646adf8b54a8f70620eb0000000001000000",
      "payload": "ea70ff4dd53c7e99948ee3a27e070fe4efea2e3d9dd793eadea86cb04c8103be"
    }
  ],
  "players": [
    "21926ecc-4a8a-4614-bbac-7c591aa7efdd",
    "27900737-46f6-4097-a169-d0ff45649ed5",
    "f89cac50-c656-4e74-879f-041aff8d01b5"
  ],
  "requestId": "3acaf94b-e77f-41f3-b68e-a1fa26e131f9"
}
```

We can see that unlike in ETH, we can have more than 1 object in the rawTx array. This is due to the fact that one needs to sign on every UTXO he spends, hence each object contains the specific UTXO data and the hash that needs to be signed. There are 2 UTXOs (inputs) In our example transaction.
Moreover, in this specific example, we are looking at a Legacy transaction. We will explain how to differentiate between Segwit and Legacy later in the guide.

Another important thing to mention is that there is no python implementation of verifying Segwit RAW transactions (at least that I could find), therefore we are going to use bitcoinlib for validating a legacy transaction and write our own logic for SegWit (brace yourself).


## Creating our Callback Application
We are going to use python and FastAPI in this guide.
First, let’s install some dependencies:\
``` pip install fastapi pyjwt bitcoinlib uvicorn bech32 fireblocks-sdk aiofiles```

Creating our FastAPI application and route:
```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI()

@app.post("/v2/tx_sign_request")
async def authorize_tx_request(request: Request) -> JSONResponse:
    pass

if __name__ == "__main__":
    uvicorn.run(app, port=8008)
```

## JWT Verification:
First we will create a JWTHandler class:
```python
import jwt

class JWTHandler:
    def __init__(self, raw_req, callback_private_key, cosigner_pubkey):
        self.raw_req = raw_req
        self.callback_private_key = callback_private_key
        self.cosigner_pubkey = cosigner_pubkey
        self.request_id = None

    def set_request_id(self, request_id):
        self.request_id = request_id

    def authenticate_request(self):
        decoded_request = jwt.decode(
            self.raw_req, self.cosigner_pubkey, algorithms=["RS256"]
        )
        self.set_request_id(decoded_request["requestId"])
        return decoded_request

    def sign_approve_response(self):
        return jwt.encode(
            {"action": "APPROVE", "requestId": self.request_id},
            self.callback_private_key,
            algorithm="RS256",
        )

    def sign_reject_response(self):
        return jwt.encode(
            {
                "action": "REJECT",
                "rejectionReason": "BTC transaction validation failed",
                "requestId": self.request_id,
            },
            self.callback_private_key,
            algorithm="RS256",
        )

```

The class above should be instantiated with the following parameters:
raw_req - the body (JWT) of the HTTP request we received
callback_private_key - the private key of your callback server
cosigner_pubkey - the cosigner public key 
request_id - none (we will set this value later)

It also has the following methods:
set_request_id - a setter for the request ID we got in our HTTP request
authenticate_request - uses the jwt module in order to verify the signed JWT and returns the decoded payload
sign_approve_response - Creates and signs the APPROVE response
sign_reject_response - Creates and signs the REJECT response

### Verifying the JWT
```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import jwt
from jwt import
import aiofiles

app = FastAPI()

class JWTHandler:
    def __init__(self, raw_req, callback_private_key, cosigner_pubkey):
        self.raw_req = raw_req
        self.callback_private_key = callback_private_key
        self.cosigner_pubkey = cosigner_pubkey
        self.request_id = None

    def set_request_id(self, request_id):
        self.request_id = request_id

    def authenticate_request(self):
        decoded_request = jwt.decode(
            self.raw_req, self.cosigner_pubkey, algorithms=["RS256"]
        )
        self.set_request_id(decoded_request["requestId"])
        return decoded_request

    def sign_approve_response(self):
        return jwt.encode(
            {"action": "APPROVE", "requestId": self.request_id},
            self.callback_private_key,
            algorithm="RS256")

    def sign_reject_response(self):
        return jwt.encode(
            {
                "action": "REJECT",
                "rejectionReason": "BTC transaction validation failed",
                "requestId": self.request_id,
            },
            self.callback_private_key,
            algorithm="RS256", 
)

@app.post("/v2/tx_sign_request")
async def authorize_tx_request(request: Request) -> JSONResponse:
    raw_body = await request.body()
    async with aiofiles.open("cosigner_public.pem", "r") as f1, aiofiles.open(
        "callback_private.pem", "r"
    ) as f2:
        cosigner_pubkey = await f1.read()
        callback_private_key = await f2.read()
    try:
        jwt_handler = JWTHandler(
            raw_body,
            cosigner_pubkey=cosigner_pubkey,
            callback_private_key=callback_private_key
        )
        callback_metadata = jwt_handler.authenticate_request()
    except DecodeError:
        return JSONResponse(
            status_code=401, content={"message": "Authentication Failed"}
        )


if __name__ == "__main__":
    uvicorn.run(app, port=8008)
```

## Creating utility classes
To make this code reusable and composable we will define an abstract class BaseValidator:
```python
import abc

class BaseValidator(abc.ABC):
    @abc.abstractmethod
    def validate_tx(self) -> bool:
        raise NotImplementedError

```

In addition we will need to access Fireblocks API hence let’s define a FireblocksClient class:
```python
from fireblocks_sdk import FireblocksSDK

class FireblocksClient:
    def __init__(self):
        self.api_key = "my_api_key"
        with open("path_to_my_secret_key_file", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)

```

Now we can create a BitcoinValidator class that inherits from the BaseValidator class and implement the validate_tx method:
```python
class BitcoinValidator(BaseValidator):
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_tx(self) -> bool:
        pass
```

As mentioned before, we need to have the ability to validate 2 different types of transactions, so let’s implement the validate_legacy_tx and validate_segwit_tx methods:
```python
class BitcoinValidator(BaseValidator):
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_segwit_tx(self) -> bool:
        pass
   
    def validate_legacy_tx(self) -> bool:
        pass

    def validate_tx(self) -> bool:
        pass
```

Now we can implement the validate_tx logic:
```python
import bitcoinlib

class BitcoinValidator(BaseValidator):
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_segwit_tx(self) -> bool:
        pass

    def validate_legacy_tx(self) -> bool:
        pass

        def validate_tx(self) -> bool:
        try:
            return self.validate_legacy_tx()
        except bitcoinlib.transactions.TransactionError:
            return self.validate_segwit_tx()
        except (SegwitTransactionValidationException, Exception):
            return False
```

So actually what happens here is that instead of trying to identify whether the transaction we are trying to validate is Legacy or Segwit, we will just try…except any transaction validation error that will be raised. 

## Validating Legacy transactions

As mentioned above, we are going to use bitcoinlib for legacy transactions and our own implementation of the segwit transactions verification, so let’s start with the easy one - legacy:
```python
        def validate_legacy_tx(self):
        tx_outputs = {}
        filtered_tx_refs = {}
        tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
        for raw_input in self.raw_tx:
            tx_outputs = {"total_outputs_amount": 0}
            filtered_tx_refs = {"total_inputs_amount": 0}
            parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(
                raw_input["rawTx"], strict=False
            ).as_dict()
            for i, utxo in enumerate(parsed_tx["inputs"]):
                tx_ref = BitcoinUtils.find_tx_ref(
                    utxo["prev_txid"], utxo["output_n"], tx_refs
                )
                if tx_ref is not None:
                    filtered_tx_refs["total_inputs_amount"] += int(
                        float(tx_refs[tx_ref]["amount"]) * 10**8
                    )
                else:
                    raise bitcoinlib.transactions.TransactionError(
                        "Input hash does not exits in transaction refs"
                    )
                tx_outputs[parsed_tx["outputs"][i]["address"]] = parsed_tx["outputs"][i]["value"]
                tx_outputs["total_outputs_amount"] += parsed_tx["outputs"][i]["value"]

        tx_fee = int(float(self.metadata["fee"]) * 10**8)
        metadata_amount = self.metadata["destinations"][0]["amountNative"] * 10**8
        metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]
        if (
            metadata_destination not in tx_outputs
            or metadata_amount != tx_outputs[metadata_destination]
            or filtered_tx_refs["total_inputs_amount"]
            - tx_outputs["total_outputs_amount"]
            - tx_fee
            > 0
        ):
            return False
        return True
```

Let's try to understand what’s going on here:



