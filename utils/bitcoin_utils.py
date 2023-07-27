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
    assert script_code[0] == OP_DUP
    assert script_code[1] == OP_HASH160
    assert script_code[2] == 20  # ripemd160 size
    pubkey_hash = script_code[3:23]
    assert script_code[23] == OP_EQUALVERIFY
    assert script_code[24] == OP_CHECKSIG
    return pubkey_hash


def serialize_input_point(tx_ref, index):
    buffer = bytearray()
    buffer += tx_ref
    buffer += index.to_bytes(4, "little")
    return buffer


def parse_hash(bytes_to_parse):
    bytes_to_parse.reverse()
    return bytes_to_parse


def find_tx_ref(tx_input, index, tx_refs):
    for i in range(len(tx_refs)):
        ref = tx_refs[i]
        if (
            ref["input"]["txHash"].lower() == tx_input
            and ref["input"]["index"] == index
        ):
            return i
    return None


def verify_address(address, pubkey_hash):
    if address.startswith("bc1"):
        assert address == bech32.encode(
            "bc", 0, pubkey_hash
        ), "The provided SegWit address and parsed pubkey are different"
    else:
        assert (
            address == base58.b58encode_check(b"\x00" + pubkey_hash).decode()
        ), "The provided Legacy address and parsed pubkey are different"


def double_sha(buffer_to_hash):
    return hashlib.sha256(hashlib.sha256(buffer_to_hash).digest()).digest()


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
            assert False
    return output_buffer


def verify_single_segwit_input(raw_input, tx_refs, output_hash):
    input_hash = parse_hash(raw_input[68:100])
    input_index = int.from_bytes(raw_input[100:104], "little")
    script_size = raw_input[104]
    pubkey_hash = parseP2WPKHScript(raw_input[105:130])
    sequence = int.from_bytes(raw_input[138:142], "little")
    outputs_hash = raw_input[142:174]
    locktime = int.from_bytes(raw_input[174:178], "little")
    sighash = int.from_bytes(raw_input[178:182], "little")
    tx_ref_index = find_tx_ref(input_hash.hex(), input_index, tx_refs)
    assert tx_ref_index is not None, "Input hash does not exist in transaction refs"
    tx_ref = tx_refs[tx_ref_index]
    verify_address(tx_ref["address"], pubkey_hash)
    amount = int.from_bytes(raw_input[130:138], "little")
    parsed_amount = int(Decimal(tx_ref["amount"]) * Decimal(10**8))
    assert script_size == 0x19, "Script size is not 25 bytes"
    assert (
        amount == parsed_amount
    ), "The provided amount is different from the parsed amount"
    assert (
        sequence == 0xFFFFFFFF
    ), "Sequence is not -1"  # fireblocks currently uses sequence -1
    assert (
        outputs_hash == output_hash
    ), "The provided output hash is different from the parsed output hash"
    assert (
        locktime == 0
    ), "Lock time is not 0"  # fireblocks currently doesn't set locktime
    assert sighash == 1, "Sighash is not 1"  # the current protocol version is 1
