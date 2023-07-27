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
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI()

@app.post("/v2/tx_sign_request")
async def authorize_tx_request(request: Request) -> Response:
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
from fastapi import FastAPI, Request, Response
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

## Creating helpers
Let's define 2 exceptions:

```python
class SegwitTransactionValidationException(Exception):
    def __init__(self, msg: str):
        self.message = msg
        super().__init__(self.message)


class LegacyTransactionValidationException(Exception):
    def __init__(self, msg: str):
        self.message = msg
        super().__init__(self.message)
```


We will need to access Fireblocks API so let’s also define a FireblocksClient class. This class will have a few methods that we will use later on:
```python
from fireblocks_sdk import FireblocksSDK

class FireblocksClient:
    def __init__(self):
        self.api_key = "my_api_key"
        with open("path_to_my_secret_key_file", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)
    
    def get_tx_refs(self, vault_account_id):
        return self.client.get_unspent_inputs(str(vault_account_id), "BTC")

    def get_change_address(self, vault_account_id):
        addresses = self.client.get_deposit_addresses(str(vault_account_id), "BTC")
        for address in addresses:
            if address["addressFormat"] == "SEGWIT" and address["type"] == "Permanent":
                return address["address"]


```

Now we can create a BitcoinValidator class that inherits from the BaseValidator class and implement the validate_tx method:
```python
class BitcoinValidator:
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_tx(self) -> bool:
        pass
```

As mentioned before, we need to have the ability to validate 2 different types of transactions, so let’s implement the validate_legacy_tx and validate_segwit_tx methods:
```python
class BitcoinValidator:
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

class BitcoinValidator:
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
        except (SegwitTransactionValidationException, LegacyTransactionValidationException, Exception):
            return False
```

So actually what happens here is that instead of trying to identify whether the transaction we are trying to validate is Legacy or Segwit, we will just try…except any legacy transaction parsing error that will be raised. 


## Validating Legacy transactions

As mentioned above, we are going to use bitcoinlib for legacy transactions and our own implementation of the segwit transactions verification, so let’s start with the easy one - legacy:
```python
def validate_legacy_tx(self):
    parsed_tx_outputs = {"total_outputs_amount": 0}
    parsed_tx_inputs = {"total_inputs_amount": 0}
    tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
    for i, raw_input in enumerate(self.raw_tx):
        parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(raw_input["rawTx"], strict=False).as_dict()
        if len(self.raw_tx) != len(parsed_tx['inputs']):
            raise LegacyTransactionValidationException("Number of inputs in the parsed tx doesn't match")
        tx_ref = BitcoinUtils.find_tx_ref(
                parsed_tx['inputs'][i]["prev_txid"], parsed_tx['inputs'][i]["output_n"], tx_refs)
        if tx_ref is not None:
            parsed_tx_inputs[parsed_tx['inputs'][i]["prev_txid"]] = int(float(tx_refs[tx_ref]["amount"]) * 10 ** 8)
            parsed_tx_inputs["total_inputs_amount"] += int(float(tx_refs[tx_ref]["amount"]) * 10 ** 8)
        else:
            raise LegacyTransactionValidationException("Input hash does not exits in transaction refs")
        parsed_tx_outputs[parsed_tx["outputs"][i]["address"]] = parsed_tx["outputs"][i]["value"]
        parsed_tx_outputs["total_outputs_amount"] += parsed_tx["outputs"][i]["value"]

    tx_fee = int(float(self.metadata["fee"]) * 10**8)
    metadata_amount = self.metadata["destinations"][0]["amountNative"] * 10**8
    metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]

    if (
        metadata_destination not in parsed_tx_outputs
        or metadata_amount != parsed_tx_outputs[metadata_destination]
        or parsed_tx_inputs["total_inputs_amount"]
        - parsed_tx_outputs["total_outputs_amount"]
        - tx_fee
        > 0
    ):
        return False
    return True
```

Let's try to understand what’s going on here:


Basically, the raw transaction does include a previous transaction hash but does not contain any information about the amount of this input.
In order to get the amounts we need to somehow get the list of unspent transaction outputs for our source address.
Here we are using the Fireblocks API, specifically [list unspent transaction outputs endoint](https://developers.fireblocks.com/reference/get_vault-accounts-vaultaccountid-assetid-unspent-inputs).
But it's not mandatory and any external API that provides that info can be used here:
```python
tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
```


Iterating through the entire ```rawTx``` array that contains all the inputs of our transaction:
```python
for i, raw_input in enumerate(self.raw_tx):
```


Parsing the raw transaction hex by using the bitcoinlib library:
```python 
parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(
                raw_input["rawTx"], strict=False
            ).as_dict()
```
It should look similar to:
```
{
    'block_hash': None,
    'block_height': None,
    'coinbase': False,
    'confirmations': None,
    'date': None,
    'fee': None,
    'fee_per_kb': None,
    'flag': None,
    'input_total': 0,
    'inputs': [
        {
            'address': '',
            'compressed': True,
            'double_spend': False,
            'encoding': 'base58',
            'index_n': 0,
            'locktime_cltv': None,
            'locktime_csv': None,
            'output_n': 0,
            'prev_txid': 'c84a4cfe30b5c3dd7912813871f5aa70c6a1605a1ff5143471e869b128e245c8',
            'public_hash': '',
            'public_keys': [],
            'redeemscript': '',
            'script': '76a91495f6fbf9976938f6bffc646adf8b54a8f70620eb88ac',
            'script_code': '',
            'script_type': 'p2pkh',
            'sequence': 4294967295,
            'signatures': [],
            'sigs_required': 1,
            'sort': False,
            'unlocking_script': '76a91495f6fbf9976938f6bffc646adf8b54a8f70620eb88ac',
            'unlocking_script_unsigned': '',
            'valid': None,
            'value': 0,
            'witness': '',
            'witness_type': 'legacy'
        },
        {
            'address': '',
            'compressed': True,
            'double_spend': False,
            'encoding': 'base58',
            'index_n': 1,
            'locktime_cltv': None,
            'locktime_csv': None,
            'output_n': 0,
            'prev_txid': '485fec58d33b4489f9edefa8fdf6b92c8ecf51f7a1ef726f4622015b9081d7a3',
            'public_hash': '',
            'public_keys': [],
            'redeemscript': '',
            'script': '',
            'script_code': '',
            'script_type': 'sig_pubkey',
            'sequence': 4294967295,
            'signatures': [],
            'sigs_required': 1,
            'sort': False,
            'unlocking_script': '',
            'unlocking_script_unsigned': '',
            'valid': None,
            'value': 0,
            'witness': '',
            'witness_type': 'legacy'
        }
    ],
    'locktime': 0,
    'network': 'bitcoin',
    'output_total': 169457,
    'outputs': [
        {
            'address': '1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC',
            'output_n': 0,
            'public_hash': '8ca80d9b17cdba4b0f9b117c92852ca04a697839',
            'public_key': '',
            'script': '76a9148ca80d9b17cdba4b0f9b117c92852ca04a69783988ac',
            'script_type': 'p2pkh',
            'spending_index_n': None,
            'spending_txid': '',
            'spent': False,
            'value': 87600
        },
        {
            'address': 'bc1qjhm0h7vhdyu0d0luv34dlz654rmsvg8twywk99',
            'output_n': 1,
            'public_hash': '95f6fbf9976938f6bffc646adf8b54a8f70620eb',
            'public_key': '',
            'script': '001495f6fbf9976938f6bffc646adf8b54a8f70620eb',
            'script_type': 'p2wpkh',
            'spending_index_n': None,
            'spending_txid': '',
            'spent': False,
            'value': 81857
        }
    ],
    'raw': '0100000002c845e228b169e8713414f51f5a60a1c670aaf57138811279ddc3b530fe4c4ac8000000001976a91495f6fbf9976938f6bffc646adf8b54a8f70620eb88acffffffffa3d781905b0122466f72efa1f751cf8e2cb9f6fda8efedf989443bd358ec5f480000000000ffffffff0230560100000000001976a9148ca80d9b17cdba4b0f9b117c92852ca04a69783988acc13f01000000000016001495f6fbf9976938f6bffc646adf8b54a8f70620eb00000000',
    'size': 182,
    'status': 'new',
    'txhash': '',
    'txid': 'd534a415ed84b830db38ab05dc66b99f553254020e8a792a35eba2c7dcffcf1d',
    'verified': False,
    'version': 1,
    'vsize': 182,
    'witness_type': 'legacy'
}
```
Inputs and Ouputs arrays is actually what we're looking for.


Once we have the parsed transaction we can compare the number of inputs in it and the number of inputs in our callback payload. It has to be exactly the same number. If not - we are throwing an error:
```python
if len(self.raw_tx) != len(parsed_tx['inputs']):
    raise bitcoinlib.transactions.TransactionError("Number of inputs in the parsed tx doesn't match")
```


We need to find the amount for each input in the parsed transaction therefore we are looking for it in our transaction references that we quiried via Fireblocks API before by using the ```find_tx_ref``` utility function.
If the input is not found we throw an error, else we are saving the previous transaction hash as key and the amount as the value in our ```filtered_tx_refs``` dictionary. Also we are saving the total amount of all the inputs in the same dictionary:
```python
tx_ref = BitcoinUtils.find_tx_ref(parsed_tx['inputs'][i]["prev_txid"], parsed_tx['inputs'][i]["output_n"], tx_refs)
if tx_ref is not None:
    parsed_tx_inputs[parsed_tx['inputs'][i]["prev_txid"]] = int(float(tx_refs[tx_ref]["amount"]) * 10 ** 8)
    parsed_tx_inputs["total_inputs_amount"] += int(float(tx_refs[tx_ref]["amount"]) * 10 ** 8)
else:
    raise bitcoinlib.transactions.TransactionError(
        "Input hash does not exits in transaction refs")
```


Similar logic for the outputs as well:
```python
parsed_tx_outputs[parsed_tx["outputs"][i]["address"]] = parsed_tx["outputs"][i]["value"]
parsed_tx_outputs["total_outputs_amount"] += parsed_tx["outputs"][i]["value"]
```


Here we are just getting the transaction fee value, the transaction amount and the transaction destination from our callback payload:
```python
tx_fee = int(float(self.metadata["fee"]) * 10**8)
metadata_amount = self.metadata["destinations"][0]["amountNative"] * 10**8
metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]
```


Now, after having all the parsed inputs, outputs and their amounts and by also having the transaction fee, amount and the destination from our callback payload, we can actually apply our approval logic:
```python
if (
    len(tx_outputs) > 2
    or
    metadata_destination not in parsed_tx_outputs
    or metadata_amount != parsed_tx_outputs[metadata_destination]
    or parsed_tx_inputs["total_inputs_amount"]
    - parsed_tx_outputs["total_outputs_amount"]
    - tx_fee
    > 0
):
    return False
```
So the logic is quite simple. It has 4 conditions and will return False (reject) if:
1. The number of destinations in the parsed outputs greater than 2 (1 is our destination address and the second is change in case it exists)
2. Our destination address does not exist in the parsed transaction outputs 
3. The amount that we are trying to send is different from the parsed transaction output value
4. The total inputs amount minus the total outputs amount minus the transaction fee is greated than 0 

If none of these conditions were met, we will return True and basically approve the legacy transaction signing.

## Validating SegWit transaction

We are going to parse SegWit transactions without any external library. This is how the SegWit raw transaction input looks like in the callback payload (for each UTXO):

```
01000000b10723f7207447d6df6cfe68dde56180f8dfb5beef0fbf4fc3835c16a8d40195752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adf0c9e8670413c6c965f9e2a8de2bf881512b8e7ebc067cbf6078d20c18f86086000000001976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac50c3000000000000fffffffff04d4108c16d20695cd2617917f6fd12ccb88a95faee6ba0ff8908a74fbdfba10000000001000000
```

After manual parsing(can be found as Native P2WPKH hash preimage in [here]:(https://en.bitcoin.it/wiki/BIP_0143)):
```
nVersion:     01000000
hashPrevouts: b10723f7207447d6df6cfe68dde56180f8dfb5beef0fbf4fc3835c16a8d40195
hashSequence: 752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad
inputHash:    f0c9e8670413c6c965f9e2a8de2bf881512b8e7ebc067cbf6078d20c18f86086
inputIndex:   00000000
scriptCode:   1976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac
amount:       50c3000000000000
nSequence:    ffffffff
hashOutputs:  04d4108c16d20695cd2617917f6fd12ccb88a95faee6ba0ff8908a74fbdfba1
nLockTime:    00000000
nHashType:    01000000
```

While the scriptCode (```1976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac```) is:
```
scriptSize:       19 (1 byte)
OP_DUP:           76 (1 byte)
OP_HASH:          a9 (1 byte)
ripemd160 size:   14 (1 byte)
pubkeyHash:       84d685df1cf10dd7849402eef1d902bbbeec721a (20 bytes)
OP_EQUALVERIFY:   88 (1 byte)
OP_CHECKSIG:      ac (1 byte)
```

We can write a few utility functions that will help us to parse this raw payload.
The first one is ```parseP2WPKHScript``` which will receive the scriptCode (without the size byte), parse it and will return the pubkeyHash:
```python
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC

def parseP2WPKHScript(script_code):
    assert script_code[0] == OP_DUP, "byte 0 is not OP_DUP"
    assert script_code[1] == OP_HASH160, "byte 1 is not OP_HASH160"
    assert script_code[2] == 20, "byte 2 is not 20" # 14 in hex is 20 in decimal
    assert script_code[23] == OP_EQUALVERIFY, "byte 23 is not OP_EQUALVERIFY"
    assert script_code[24] == OP_CHECKSIG, "byte 24 is not OP_CHECKSIG"
    pubkey_hash = script_code[3:23]
    return pubkey_hash
```

Next we'll need a utility function that will be able to verify that the encoded pubkey hash and the address that spends the input are the same:
```python
def verify_address(address, pubkey_hash):
    if address.startswith("bc1"):
        assert address == bech32.encode("bc", 0, pubkey_hash), "Segwit addresses don't match"
    else:
        assert address == base58.b58encode_check(b"\x00" + pubkey_hash).decode(), "Legacy addresses don't match"
``` 

Let's implement our validate_segwit_tx method and see what additional utility method we'll need there:
```python
def validate_segwit_tx(self):
    source_vault_account_id = self.metadata["sourceId"]
    tx_refs = self.fireblocks.get_tx_refs(source_vault_account_id)
    total_amount = 0
    inputs = bytearray()
    for input_to_sign in self.metadata["rawTx"]:
        raw_input = bytearray.fromhex(input_to_sign["rawTx"])
        parsed_input_hash = raw_input[68:100]
        parsed_input_index = int.from_bytes(raw_input[100:104], "little")
        inputs += serializeInputPoint(parsed_input_hash, parsed_input_index)
        total_amount += int.from_bytes(raw_input[130:138], "little")
    payload_amount = int(float(self.metadata["requestedAmountStr"]) * 10 ** 8)
    changeAmount = total_amount - payload_amount - int(float(self.metadata["fee"]) * 10 ** 8)
    outputs = serializeOutput(self.metadata["destAddress"], payload_amount)
    if changeAmount > 0:
        change_address = self.fireblocks.get_change_address(source_vault_account_id)
        outputs += serializeOutput(change_address, changeAmount)
    for input_to_sign in self.metadata["rawTx"]:
        rawTx = bytearray.fromhex(input_to_sign["rawTx"])
        verifySingleSegwitTx(rawTx, tx_refs, doubleSHA(outputs))
    return True
```