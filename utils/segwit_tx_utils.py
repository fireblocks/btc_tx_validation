from decimal import Decimal
from .bitcoin_utils import parse_hash, parseP2WPKHScript, find_tx_ref, verify_address


def calculate_total_amount(raw_txs):
    """Calculate the total amount of the parsed amount values for all the inputs
    
    :param raw_txs: raw transaction inputs
    :return: int
    """
    return sum(
        int.from_bytes(bytearray.fromhex(raw_input["rawTx"])[130:138], "little")
        for raw_input in raw_txs
    )


def calculate_change_amount(total_amount, payload_amount, fee):
    """Calculate the change output amount
    
    :param total_amount: the total amount of the inputs 
    :param payload_amount: the amount provided in the payload
    :param fee: the fee provided in the payload
    :return: int | None
    """
    change_amount = total_amount - payload_amount - fee
    return None if change_amount < 0 else change_amount


def verify_single_segwit_input(raw_input, tx_refs, output_hash):
    """Verify a single segwit raw input 
    
    :param raw_input: a single raw input to parse 
    :param tx_refs: unspent transaction outputs list
    :param output_hash: the hash of the outputs
    :return: 
    """
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