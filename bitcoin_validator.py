import base58
import bech32
import hashlib
from decimal import Decimal


OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CHECKSIG = 0xAC


def parseP2WPKHScript(script_code):
    """Parse segwit script
    
    :param script_code: the script code of the raw tx
    :return: pybkey_hash (str)
    """
    assert script_code[0] == OP_DUP
    assert script_code[1] == OP_HASH160
    assert script_code[2] == 20  # ripemd160 size
    pubkey_hash = script_code[3:23]
    assert script_code[23] == OP_EQUALVERIFY
    assert script_code[24] == OP_CHECKSIG
    return pubkey_hash


def serialize_input_point(tx_ref, index):
    """Serialize a single input
    
    :param tx_ref: previous transaction hash
    :param index: previous transaction vOut
    :return: serialized input (bytearray)
    """
    buffer = bytearray()
    buffer += tx_ref
    buffer += index.to_bytes(4, "little")
    return buffer


def parse_hash(bytes_to_parse):
    bytes_to_parse.reverse()
    return bytes_to_parse


def find_tx_ref(tx_input, index, tx_refs):
    """Find a specific previous transaction hash in the unspent transaction outputs list
    
    :param tx_input: previous transaction hash 
    :param index: previous transaction vOut
    :param tx_refs: unspent transaction outputs list 
    :return: index in the unspent transaction outputs list (int) | None 
    """
    for i in range(len(tx_refs)):
        ref = tx_refs[i]
        if (
            ref["input"]["txHash"].lower() == tx_input
            and ref["input"]["index"] == index
        ):
            return i
    return None


def verify_address(address, pubkey_hash):
    """Compare the parsed and the callback payload addresses
    
    :param address: address from the callback payload
    :param pubkey_hash: the parsed pubkey hash
    :return: 
    """
    if address.startswith("bc1"):
        assert address == bech32.encode(
            "bc", 0, pubkey_hash
        ), "The provided SegWit address and parsed pubkey are different"
    else:
        assert (
            address == base58.b58encode_check(b"\x00" + pubkey_hash).decode()
        ), "The provided Legacy address and parsed pubkey are different"


def double_sha(buffer_to_hash):
    """Generate double SHA256 
    
    :param buffer_to_hash: message to hash 
    :return: double sha256 hash (str)
    """
    return hashlib.sha256(hashlib.sha256(buffer_to_hash).digest()).digest()


def serialize_output(to_address, amount):
    """Serialize a single transaction output
    
    :param to_address: the destination address 
    :param amount: the amount for this address
    :return: the serialized output (bytearray)
    """
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
            assert False
    return output_buffer



