def calculate_total_amount(raw_txs):
    return sum(
        int.from_bytes(bytearray.fromhex(raw_input["rawTx"])[130:138], "little")
        for raw_input in raw_txs
    )


def calculate_change_amount(total_amount, payload_amount, fee):
    change_amount = total_amount - payload_amount - fee
    return None if change_amount < 0 else change_amount
