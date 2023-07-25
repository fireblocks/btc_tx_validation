# BTC transaction validation on the Co-Signer callback handler

BTC transactions are more complex than ETH. This is due the UTXO (Unspent transaction output) model. In addition to the complex transaction model, BTC transactions can be of different types:

Legacy transactions
SegWit (Segregated Witness) transactions

SegWit in a nutshell - it is an improvement over the current bitcoin blockchain which reduces the size needed to store transactions in a block. This is done by removing certain signatures with counting serialized witness data as one unit and core block data as four units.

Legacy addresses begin with 1 (for example: ```1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC```)
SegWit addresses begin with bc1 (for example: ```bc1q3j5qmxchekaykrumz97f9pfv5p9xj7petf645z```)


## BTC callback payload example

```
{
  "txId": "153736c6-7308-4e6e-b633-d243ab1211df",
  "operation": "TRANSFER",
  "sourceType": "VAULT",
  "sourceId": "25",
  "destType": "VAULT",
  "destId": "0",
  "asset": "BTC",
  "amount": 0.0005,
  "amountStr": "0.00050000",
  "requestedAmount": 0.0005,
  "requestedAmountStr": "0.0005",
  "fee": "0.00002598",
  "destAddressType": "WHITELISTED",
  "destAddress": "bc1qjhm0h7vhdyu0d0luv34dlz654rmsvg8twywk99",
  "destinations": [
    {
      "amountNative": 0.0005,
      "amountNativeStr": "0.0005",
      "amountUSD": 14.98097333,
      "dstAddressType": "WHITELISTED",
      "dstId": "0",
      "dstWalletId": "",
      "dstName": "Main Vault - ID 0",
      "dstSubType": "",
      "dstType": "VAULT",
      "displayDstAddress": "bc1qjhm0h7vhdyu0d0luv34dlz654rmsvg8twywk99",
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
      "keyDerivationPath": "[ 44, 0, 25, 0, 0 ]",
      "rawTx": "01000000b10723f7207447d6df6cfe68dde56180f8dfb5beef0fbf4fc3835c16a8d40195752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adf0c9e8670413c6c965f9e2a8de2bf881512b8e7ebc067cbf6078d20c18f86086000000001976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac50c3000000000000fffffffff04d4108c16d20695cd2617917f6fd12ccb88a95faee6ba0ff8908a74fbdfba10000000001000000",
      "payload": "29d5a9b584b6f34d0f6b8c3e63b8b8d995b35efc7ccae7efb09ac59c00f6690d"
    },
    {
      "keyDerivationPath": "[ 44, 0, 25, 0, 0 ]",
      "rawTx": "01000000b10723f7207447d6df6cfe68dde56180f8dfb5beef0fbf4fc3835c16a8d40195752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632addab66c1c2cb4ff9b4aee2dffd89202728612859b5c8804b790f7719f91df380a000000001976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac50c3000000000000fffffffff04d4108c16d20695cd2617917f6fd12ccb88a95faee6ba0ff8908a74fbdfba10000000001000000",
      "payload": "77b3e791aeadca9498701ceb6b58fc84efb96ca787c8220fb9c622b97c101596"
    }
  ],
  "players": [
    "21926ecc-4a8a-4614-bbac-7c591aa7efdd",
    "27900737-46f6-4097-a169-d0ff45649ed5",
    "f89cac50-c656-4e74-879f-041aff8d01b5"
  ],
  "requestId": "153736c6-7308-4e6e-b633-d243ab1211df"
}
```

We can see that unlike in ETH, we can have more than 1 object in the rawTx array. This is due to the fact that one needs to sign on every UTXO he spends, hence each object contains the specific UTXO data and the hash that needs to be signed. There are 2 UTXOs (inputs) In our example transaction.
Moreover, in this specific example, we are looking at a Segwit transaction. We will explain how to differentiate between Segwit and Legacy later in the guide.

Another important thing to mention is that there is no python implementation of verifying Segwit RAW transactions (at least that I could find), therefore we are going to use bitcoinlib for validating a legacy transaction and write our own logic for SegWit (brace yourself).


## Creating our Callback Application
We are going to use python and FastAPI in this guide.
First, let’s install some dependencies:\
``` pip install fastapi pyjwt bitcoinlib uvicorn bech32 fireblocks-sdk ```

Creating our FastAPI application and route:
```
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
```
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
```
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import jwt
from jwt import 
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
    with open("cosigner_public.pem", "r") as f1, open(
        "callback_private.pem", "r"
    ) as f2:
        cosigner_pubkey = f1.read()
        callback_private_key = f2.read()
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
```
import abc

class BaseValidator(abc.ABC):
    @abc.abstractmethod
    def validate_tx(self) -> bool:
        raise NotImplementedError

```

In addition we will need to access Fireblocks API hence let’s define a FireblocksClient class:
```
from fireblocks_sdk import FireblocksSDK

class FireblocksClient:
    def __init__(self):
        self.api_key = "my_api_key"
        with open("path_to_my_secret_key_file", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)

```

Now we can create a BitcoinValidator class that inherits from the BaseValidator class and implement the validate_tx method:
```
class BitcoinValidator(BaseValidator):
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_tx(self) -> bool:
        pass
```

As mentioned before, we need to have the ability to validate 2 different types of transactions, so let’s implement the validate_legacy_tx and validate_segwit_tx methods:
```
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
```
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
            self.validate_legacy_tx()
        except bitcoinlib.transactions.TransactionError:
            self.validate_segwit_tx()
        except SegwitTransactionValidationException:
            return False

```

So actually what happens here is that instead of trying to identify whether the transaction we are trying to validate is Legacy or Segwit, we will just try…except any transaction validation error that will be raised. 

## Validating Legacy transactions

As mentioned above, we are going to use bitcoinlib for legacy transactions and our own implementation of the segwit transactions verification, so let’s start with the easy one - legacy:
```
def validate_legacy_tx(self):
    amount = 0
    for raw_input in self.raw_tx:
        parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(raw_input["rawTx"], strict=False)
        tx_refs = self.fireblocks.get_tx_refs()
        tx_ref = BitcoinUtils.find_tx_ref(tx_refs)
        amount += float(tx_ref["amount"])
        if self.metadata["destAddress"] != parsed_tx["outputs"]["address"]:
            raise bitcoinlib.transactions.TransactionError("The parsed destination address is different from the one in the metadata")
        if len(self.raw_tx) != len(parsed_tx.inputs):
            raise bitcoinlib.transactions.TransactionError("Num of inputs does not equal to the number of provided inputs in the metadata")
        if parsed_tx["outputs"]["value"] / 10**8 != raw_input["amount"]:
            raise bitcoinlib.transactions.TransactionError("Output amount does not equal to the requested amount")
        if amount / 10**8 - float(self.metadata["fee"]) == self.metadata["amount"]:
            raise bitcoinlib.transactions.TransactionError( "The sum of inputs minus the fee does not equal to the requested amount")
```

Let's try to understand what’s going on here:



