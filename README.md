# BTC transaction validation on the Co-Signer callback handler

BTC transactions are more complex than ETH. This is due the UTXO (Unspent transaction output) model. In addition to the complex transaction model, BTC transactions can be of different types:

Legacy transactions\
SegWit (Segregated Witness) transactions

SegWit in a nutshell - an improvement over the current bitcoin blockchain which reduces the size needed to store transactions in a block. This is done by removing certain signatures with counting serialized witness data as one unit and core block data as four units.

Legacy addresses begin with 1 (for example: ```1DpivPqJkLxbRwm4GpxXsNPKS29ou1NYdC```)\
SegWit addresses begin with bc1 (for example: ```bc1q3j5qmxchekaykrumz97f9pfv5p9xj7petf645z```)

Kindly note that this code should be referenced as an example only.

Source code can be found [here](https://github.com/SlavaSereb/btc_validation)

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

We can see that unlike in ETH, we can have more than 1 object in the rawTx array. This is due to the fact that one needs to sign on every UTXO he spends, hence each object contains the specific UTXO data and the hash that needs to be signed. There are 2 UTXOs (inputs) in our example transaction.
Moreover, in this specific example, we are looking at a Legacy transaction. We will explain how to differentiate between Segwit and Legacy later in the guide.

Another important thing to mention is that there is no python implementation of verifying Segwit RAW transactions (at least that I could find), therefore we are going to use bitcoinlib for validating a legacy transaction and write our own logic for SegWit (brace yourself).


## Creating our Callback Application
We are going to use Python and Flask in this guide.\
First, let’s install some dependencies:\
``` pip install flask pyjwt bitcoinlib bech32 fireblocks-sdk```

Creating our Flask application and route:
```python
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/v2/tx_sign_request", methods=['POST'])
def tx_sign_request():
    pass

if __name__ == '__main__':
    # run app in debug mode on port 8080
    app.run(debug=True, port=8080)
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

The class above should be instantiated with the following parameters:\
```raw_req``` - the body (JWT) of the HTTP request we received\
```callback_private_key``` - the private key of your callback server\
```cosigner_pubkey``` - the cosigner public key\
```request_id``` - none (we will set this value later)\

It also has the following methods:\
```set_request_id``` - a setter for the request ID we got in our HTTP request\
```authenticate_request``` - uses the jwt module in order to verify the signed JWT and returns the decoded payload\
```sign_approve_response``` - Creates and signs the APPROVE response\
```sign_reject_response``` - Creates and signs the REJECT response\

### Verifying the JWT
```python
from jwt import decode, encode, DecodeError
from flask import Flask, request, Response

app = Flask(__name__)

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
            {
                "action": "APPROVE", 
                "requestId": self.request_id
            },
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

@app.route("/v2/tx_sign_request", methods=['POST'])
def tx_sign_request():
    raw_body = request.data
    with open("cosigner_public.pem", "r") as f1, open("private.pem", "r") as f2:
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
        return Response(status=401, response=json.dumps({"message": "Authentication Failed"}))

if __name__ == '__main__':
    # run app in debug mode on port 8080
    app.run(debug=True, port=8080)
```

## Creating helpers
Let's define a custom exception:

```python
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

Now we can create a BitcoinValidator class and implement the ```validate_tx``` method:
```python
class BitcoinValidator:
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksConnector()
    
    def validate_tx(self) -> bool:
        pass
```

As mentioned before, we need to have the ability to validate 2 different types of transactions, so let’s implement the ```validate_legacy_tx``` and ```validate_segwit_tx``` methods:
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


Now we can implement the ```validate_tx``` logic:
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

So actually what happens here is that instead of trying to identify whether the transaction we are trying to validate is Legacy or Segwit, we will just ```try…except``` any legacy transaction parsing error that will be raised. 


## Validating Legacy transactions

Just before the validation process, let's define a few helpers that we'll cover a bit later:
```python
from decimal import Decimal

def find_tx_ref(input, index, tx_refs):
    for i in range(len(tx_refs)):
        ref = tx_refs[i]
        if (
            ref["input"]["txHash"].lower() == input
            and ref["input"]["index"] == index
        ):
            return i
    return None

def parse_legacy_tx_output(parsed_tx):
    parsed_tx_outputs = {"total_outputs_amount": 0}
    for output in parsed_tx["outputs"]:
        parsed_tx_outputs[output["address"]] = output["value"]
        parsed_tx_outputs["total_outputs_amount"] += output["value"]
    return parsed_tx_outputs

def parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs):
    parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(raw_input["rawTx"], strict=False).as_dict()
    if num_of_inputs != len(parsed_tx['inputs']):
        raise LegacyTransactionValidationException("Number of inputs in the parsed tx doesn't match")
    for i, input_tx in enumerate(parsed_tx['inputs']):
        tx_ref = find_tx_ref(input_tx["prev_txid"], input_tx["output_n"], tx_refs)
        if tx_ref is not None:
            amount_decimal = Decimal(tx_refs[tx_ref]["amount"])
            if i == num_of_inputs - 1:
                parsed_tx['inputs'][i]["amount"] = int(amount_decimal * Decimal(10 ** 8)) - sum(
                    tx["amount"] for tx in parsed_tx['inputs'][:i])
            else:
                parsed_tx['inputs'][i]["amount"] = int(amount_decimal * Decimal(10 ** 8))
        else:
            raise LegacyTransactionValidationException("Input hash does not exist in transaction refs")
    return parsed_tx
```

As mentioned before, we are using bitcoinlib for legacy transactions:
```python
from decimal import Decimal

def validate_legacy_tx(self):
    bitcoinlib.transactions.Transaction.parse_hex(self.metadata["rawTx"][0]["rawTx"], strict=False).as_dict()
    tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
    num_of_inputs = len(self.metadata['rawTx'])
    parsed_txs = [parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs) for raw_input in self.metadata["rawTx"]]
    parsed_tx_outputs = parse_legacy_tx_output(parsed_txs[0])

    tx_fee = int(Decimal(self.metadata["fee"]) * Decimal(10 ** 8))
    metadata_amount = int(Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10 ** 8))
    metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]

    if len(parsed_txs[0]["outputs"]) == 1:
        metadata_amount -= tx_fee

    if (
        metadata_destination not in parsed_tx_outputs
        or metadata_amount != parsed_tx_outputs[metadata_destination]
        or sum(tx["amount"] for tx in parsed_txs[0]['inputs'])
        - parsed_tx_outputs["total_outputs_amount"] - tx_fee > 0
    ):
        return False
    return True
```

Let's try to understand what is going on here:

First of all we are trying to parse the first raw input with bitcoinlib.\
If it will raise exception, we'll know that this is NOT a legacy transaction and we'll move on to SegWit validation:
```python
bitcoinlib.transactions.Transaction.parse_hex(self.metadata["rawTx"][0]["rawTx"], strict=False).as_dict()
```

The raw transaction does include a previous transaction hash but does not contain any information about the amount of this input. In order to get the amounts we need to somehow get the list of unspent transaction outputs for our source address. \
Here we are using the Fireblocks API, specifically [list unspent transaction outputs endoint](https://developers.fireblocks.com/reference/get_vault-accounts-vaultaccountid-assetid-unspent-inputs).
But it's not mandatory and any external API that provides that info can be used here.\
In addition we are checking the number of raw inputs in our payload:
```python
tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
num_of_inputs = len(self.metadata['rawTx'])
```

Iterating through the entire ```rawTx``` list that contains all the inputs of our transaction and parsing each by using the ```parse_legacy_tx_input``` function.\
The function ```parse_legacy_tx_input``` takes a raw input of a legacy transaction, along with the transaction references (```tx_refs```) and the total number of inputs in the transaction (```num_of_inputs```). Its purpose is to parse and enrich the raw input data by fetching additional information from the ```tx_refs``` and replacing the original amount field in each input with the accurate amount in satoshis:
```python
parsed_txs = [parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs) for raw_input in self.metadata["rawTx"]]
```

Parsing the raw transaction hex by using the bitcoinlib library should yield a result similar to this:
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
```inputs``` and ```ouputs``` lists are actually what we're looking for.


The ```parse_legacy_tx_output``` function takes a single parsed legacy transaction input (parsed_tx), which is represented as a dictionary, and its purpose is to extract and organize information about the outputs of the legacy transaction:
```python
parsed_tx_outputs = parse_legacy_tx_output(parsed_txs[0])
```

Getting the transaction fee, amount and the destination from the callback payload:
```python
tx_fee = int(Decimal(self.metadata["fee"]) * Decimal(10 ** 8))
metadata_amount = int(Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10 ** 8))
metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]
```

Checking if there is only 1 output. If so, the amount is the the entire amount minus fee (this is a scenario where there is no change output and this is a full balance transaction):
```python
if len(parsed_txs[0]["outputs"]) == 1:
    metadata_amount -= tx_fee
```

And finally we are checking the values and decide if we approve this transaction or not.\
The logic is quite simple - it has 3 conditions and will return False (reject) if:\
A. Our destination address does not exist in the parsed transaction outputs.\
B. The amount that we are trying to send is different from the parsed transaction output value.\
C. The total inputs amount minus the total outputs amount minus the transaction fee is greated than 0.

```python
if (
    metadata_destination not in parsed_tx_outputs
    or metadata_amount != parsed_tx_outputs[metadata_destination]
    or sum(tx["amount"] for tx in parsed_txs[0]['inputs'])
    - parsed_tx_outputs["total_outputs_amount"] - tx_fee > 0
    ):
        return False
    return True
```
If none of these conditions are met, we will return ```True``` and basically approve the legacy transaction signing.

## Validating SegWit transaction

We are going to parse SegWit transactions without any external library.\
This is how the SegWit raw transaction input looks like in the callback payload (for each UTXO):

```
01000000b10723f7207447d6df6cfe68dde56180f8dfb5beef0fbf4fc3835c16a8d40195752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632adf0c9e8670413c6c965f9e2a8de2bf881512b8e7ebc067cbf6078d20c18f86086000000001976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac50c3000000000000fffffffff04d4108c16d20695cd2617917f6fd12ccb88a95faee6ba0ff8908a74fbdfba10000000001000000
```

After manual parsing (can be found as Native P2WPKH hash preimage in [here](https://en.bitcoin.it/wiki/BIP_0143)):
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

While the ```scriptCode (1976a91484d685df1cf10dd7849402eef1d902bbbeec721a88ac)``` is:
```
scriptSize:       19 (1 byte)
OP_DUP:           76 (1 byte)
OP_HASH:          a9 (1 byte)
ripemd160 size:   14 (1 byte)
pubkeyHash:       84d685df1cf10dd7849402eef1d902bbbeec721a (20 bytes)
OP_EQUALVERIFY:   88 (1 byte)
OP_CHECKSIG:      ac (1 byte)
```

Let's define the OP codes as global constants so we can use them later in different parts of our code:
```python
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC
```

We can write a few utility functions that will help us to parse this raw payload.
The first one is ```parseP2WPKHScript``` which will receive the ```scriptCode``` (without the size byte), parse it and will return the pubkeyHash:
```python
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
import base58
import bech32

def verify_address(address, pubkey_hash):
    if address.startswith("bc1"):
        assert(address == bech32.encode('bc', 0, pubkey_hash)),\
            "The provided SegWit address and parsed pubkey are different"
    else:
        assert(address == base58.b58encode_check(b'\x00' + pubkey_hash).decode()), \
            "The provided Legacy address and parsed pubkey are different"
``` 

Another function that we'll need here is an output serialization function. This function is required since the raw input payload does not contain any information about the destination(s) and the amount(s). The only thing that it actually has is the hash of all the serialized outputs. 
So we need a function that will create a serialized output based on the information we know (destination addresses and amounts) and then we'll be able to hash all these and compare it with the parsed output hash:
```python
def serialize_output(to_address, amount):
    output_buffer = bytearray()
    output_buffer += int(amount).to_bytes(8, "little")
    if to_address.startswith("bc1"):
        version, pubkey = bech32.decode("bc", to_address)
        output_buffer.append(0x16)
        output_buffer.append(version)
        output_buffer.append(0x14)
        output_buffer += bytearray(pubkey)
    else:
        addr = base58.b58decode_check(to_address)
        addrType = addr[0]
        pubkey = addr[1:]
        if addrType == 0:  # P2PKH
            output_buffer.append(0x19)
            output_buffer.append(OP_DUP)
            output_buffer.append(OP_HASH160)
            output_buffer.append(20)
            output_buffer += bytearray(pubkey)
            output_buffer.append(OP_EQUALVERIFY)
            output_buffer.append(OP_CHECKSIG)
        elif addrType == 5:  # P2SH
            output_buffer.append(0x17)
            output_buffer.append(OP_HASH160)
            output_buffer.append(20)
            output_buffer += bytearray(pubkey)
            output_buffer.append(OP_EQUAL)
        else:
            assert False, "Destination address is in an unknown format"
    return output_buffer
```

In addition, we'll need 2 more functions:  
A hashing function - this function will apply double SHA256 algorithm as required in Bitcoin.\
A reversing function that will returned the reversed bytes (Bitcoin uses little endian system).
```python
import hashlib

def double_sha(buffer):
    return hashlib.sha256(hashlib.sha256(buffer_to_hash).digest()).digest()

def parse_hash(bytes_to_parse):
    bytes_to_parse.reverse()
    return bytes_to_parse
```

Another very important helper function is ```verify_single_segwit_input``` that actually parses the raw input.
This function expects to get the raw input, transaction references and the double SHA256 of the serialized outputs.
The function parses the relevant parts of the transaction and raises an ```AssertionError``` in case there is some unexpected mismatch:
```python
def verify_single_segwit_input(raw_input, tx_refs, output_hash):
    input_hash = parse_hash(raw_input[68: 100])
    input_index = int.from_bytes(raw_input[100: 104], "little")
    script_size = raw_input[104]
    pubkey_hash = parseP2WPKHScript(raw_input[105: 130])
    sequence = int.from_bytes(raw_input[138:142], "little")
    outputs_hash = raw_input[142: 174]
    locktime = int.from_bytes(raw_input[174: 178], "little")
    sighash = int.from_bytes(raw_input[178: 182], "little")
    tx_ref_index = find_tx_ref(input_hash.hex(), input_index, tx_refs)
    assert tx_ref_index is not None, "Input hash does not exist in transaction refs"
    tx_ref = tx_refs[tx_ref_index]
    verify_address(tx_ref["address"], pubkey_hash)
    amount = int.from_bytes(raw_input[130:138], "little")
    parsed_amount = int(Decimal(tx_ref["amount"]) * Decimal(10 ** 8))
    assert script_size == 0x19, "Script size is not 25 bytes"
    assert amount == parsed_amount, "The provided amount is different from the parsed amount"
    assert sequence == 0xFFFFFFFF, "Sequence is not -1"  # fireblocks currently uses sequence -1
    assert outputs_hash == output_hash, "The provided output hash is different from the parsed output hash"
    assert locktime == 0, "Lock time is not 0"  # fireblocks currently doesn't set locktime
    assert sighash == 1, "Sighash is not 1"  # the current protocol version is 1
```

A few additional helper functions will be needed for better code readability of our validation function.
The ```calculate_total_amount``` function calculates the total amount of inputs in a legacy transaction by summing the amounts extracted from the raw input data of each input in the transaction.
The ```calculate_change_amount``` function determines the change amount in a transaction, which represents the excess amount that needs to be sent back to the sender to balance the transaction and ensure that the inputs and outputs match:
```python
def calculate_total_amount(raw_txs):
    return sum(int.from_bytes(bytearray.fromhex(raw_input["rawTx"])[130:138], "little") for raw_input in raw_txs)

def calculate_change_amount(total_amount, payload_amount, fee):
    change_amount = total_amount - payload_amount - int(float(fee) * 10 ** 8)
    return payload_amount - int(float(fee) * 10 ** 8) if change_amount < 0 else change_amount
```

The last helper function is ```build_outputs``` function.
The ```build_outputs``` function is responsible for constructing the outputs for a transaction. It takes 3 parameters as input: ```metadata``` (containing information about the transaction), ```payload_amount``` (the amount intended for the recipient), and ```change_amount``` (the amount that needs to be sent back to the sender as change, if applicable).
Kindly note to implement this function within the ```BitcoinValidator``` class (unlike any other helper function):
```python
def build_outputs(metadata, payload_amount, change_amount):
    outputs = serialize_output(metadata["destAddress"], payload_amount)
    if change_amount > 0:
        change_address = self.fireblocks.get_change_address(metadata["sourceId"])
        outputs += serialize_output(change_address, change_amount)
    return outputs
```

And now let's implement our ```validate_segwit_tx``` method in the ```BitcoinValidator``` class:
```python
def validate_segwit_tx(self):
    source_vault_account_id = self.metadata["sourceId"]
    tx_refs = self.fireblocks.get_tx_refs(source_vault_account_id)
    total_amount = calculate_total_amount(self.metadata["rawTx"])
    payload_amount = int(float(self.metadata["destinations"][0]["amountNative"]) * 10 ** 8)
    change_amount = calculate_change_amount(total_amount, payload_amount, self.metadata["fee"])
    outputs = build_outputs(self.metadata, payload_amount, change_amount)

    for input_to_sign in self.metadata["rawTx"]:
        try:
            verify_single_segwit_input(bytearray.fromhex(input_to_sign['rawTx']), tx_refs, double_sha(outputs))
        except AssertionError as e:
            print(e)
            return False
    return True
```
### What is actually going on here?

The ```validate_segwit_tx``` function is responsible for validating a SegWit (Segregated Witness) transaction based on the provided metadata and raw input data. It ensures that the transaction meets the necessary requirements and that all inputs are valid.
It starts by extracting the ```source_vault_account_id``` from the callback payload dictionary and then fetches the transaction references (```tx_refs```) associated with the ```source_vault_account_id``` using ```fireblocks.get_tx_refs()```:
```python
source_vault_account_id = self.metadata["sourceId"]
tx_refs = self.fireblocks.get_tx_refs(source_vault_account_id)
```

It calculates the ```total_amount``` of all inputs in the transaction using the ```calculate_total_amount``` function with the ```metadata["rawTx"]``` as input, then get the transaction amount from the callback payload and calculates the change by using the ```calculate_change_amount``` function, which determines whether there's a change output or not:
```python
total_amount = calculate_total_amount(self.metadata["rawTx"])
payload_amount = int(float(self.metadata["destinations"][0]["amountNative"]) * 10 ** 8)
change_amount = calculate_change_amount(total_amount, payload_amount, self.metadata["fee"])
```

The outputs are serialized using the ```build_outputs``` function:
```python
outputs = build_outputs(self.metadata, payload_amount, change_amount)
```

The function then iterates through each raw input in ```metadata["rawTx"]```. For each input, it attempts to verify the input by calling the ```verify_single_segwit_input``` function.
If any input fails the verification (raises an ```AssertionError```), the error is printed, and the function returns ```False```, indicating that the SegWit transaction is not valid.\
If all inputs pass the verification, the function returns ```True```, indicating that the SegWit transaction is valid:
```python
for input_to_sign in self.metadata["rawTx"]:
    try:
        verify_single_segwit_input(bytearray.fromhex(input_to_sign['rawTx']), tx_refs, double_sha(outputs))
    except AssertionError as e:
        print(e)
        return False
return True
```


Our ```BitcointValidator``` class with both ```validate_legacy_tx``` and ```validate_segwit_tx``` methods:
```python
class BitcoinValidator:
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksClient()

    def build_outputs(self, payload_amount, fee, change_amount):
        if not change_amount:
            outputs = serialize_output(self.metadata["destAddress"], payload_amount - fee)
        else:
            outputs = serialize_output(self.metadata["destAddress"], payload_amount)
            change_address = self.fireblocks.get_change_address(self.metadata["sourceId"])
            outputs += serialize_output(change_address, change_amount)
        return outputs

    def validate_segwit_tx(self):
        source_vault_account_id = self.metadata["sourceId"]
        tx_refs = self.fireblocks.get_tx_refs(source_vault_account_id)
        total_amount = calculate_total_amount(self.metadata["rawTx"])
        payload_amount = int(Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10 ** 8))
        fee = int(Decimal(self.metadata["fee"]) * Decimal(10 ** 8))
        change_amount = calculate_change_amount(total_amount, payload_amount, fee)
        outputs = self.build_outputs(payload_amount, fee, change_amount)

        for input_to_sign in self.metadata["rawTx"]:
            try:
                verify_single_segwit_input(bytearray.fromhex(input_to_sign['rawTx']), tx_refs, double_sha(outputs))
            except AssertionError as e:
                print(e)
                return False
        return True

    def validate_legacy_tx(self):
        bitcoinlib.transactions.Transaction.parse_hex(self.metadata["rawTx"][0]["rawTx"], strict=False).as_dict()
        tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
        num_of_inputs = len(self.metadata['rawTx'])
        parsed_txs = [parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs) for raw_input in self.metadata["rawTx"]]
        parsed_tx_outputs = parse_legacy_tx_output(parsed_txs[0])

        tx_fee = int(Decimal(self.metadata["fee"]) * Decimal(10 ** 8))
        metadata_amount = int(Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10 ** 8))
        metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]

        if len(parsed_txs[0]["outputs"]) == 1:
            metadata_amount -= tx_fee

        if (
            metadata_destination not in parsed_tx_outputs
            or metadata_amount != parsed_tx_outputs[metadata_destination]
            or sum(tx["amount"] for tx in parsed_txs[0]['inputs'])
            - parsed_tx_outputs["total_outputs_amount"] - tx_fee > 0
        ):
            return False
        return True

    def validate_tx(self) -> bool:
        try:
            return self.validate_legacy_tx()
        except bitcoinlib.transactions.TransactionError:
            return self.validate_segwit_tx()
        except (LegacyTransactionValidationException, AssertionError, Exception):
            return False

```

And finally, our API route to validate a BTC transaction:
```python
@app.route("/v2/tx_sign_request", methods=['POST'])
def tx_sign_request():
    raw_body = request.data
    with \
            open("/Users/slavaserebriannyi/callback_extra_params/cosigner_public.pem", "r") as f1, \
            open("/Users/slavaserebriannyi/callback_extra_params/private.pem", "r") as f2:
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
                return Response(response=jwt_handler.sign_approve_response())
            return Response(response=jwt_handler.sign_reject_response())
    except DecodeError:
        return Response(status=401, response=json.dumps({"message": "Authentication Failed"}))


if __name__ == '__main__':
    # run app in debug mode on port 8080
    app.run(debug=True, port=8080)
```
