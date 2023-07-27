import bitcoinlib
from decimal import Decimal
from bitcoin_utils import find_tx_ref


class LegacyTransactionValidationException(Exception):
    def __init__(self, msg: str):
        self.message = msg
        super().__init__(self.message)


def parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs):
    parsed_tx = bitcoinlib.transactions.Transaction.parse_hex(
        raw_input["rawTx"], strict=False
    ).as_dict()
    if num_of_inputs != len(parsed_tx["inputs"]):
        raise LegacyTransactionValidationException(
            "Number of inputs in the parsed tx doesn't match"
        )
    for i, input_tx in enumerate(parsed_tx["inputs"]):
        tx_ref = find_tx_ref(input_tx["prev_txid"], input_tx["output_n"], tx_refs)
        if tx_ref is not None:
            amount_decimal = Decimal(tx_refs[tx_ref]["amount"])
            if i == num_of_inputs - 1:
                parsed_tx["inputs"][i]["amount"] = int(
                    amount_decimal * Decimal(10**8)
                ) - sum(tx["amount"] for tx in parsed_tx["inputs"][:i])
            else:
                parsed_tx["inputs"][i]["amount"] = int(
                    amount_decimal * Decimal(10**8)
                )
        else:
            raise LegacyTransactionValidationException(
                "Input hash does not exist in transaction refs"
            )
    return parsed_tx


def parse_legacy_tx_output(parsed_tx):
    parsed_tx_outputs = {"total_outputs_amount": 0}
    for output in parsed_tx["outputs"]:
        parsed_tx_outputs[output["address"]] = output["value"]
        parsed_tx_outputs["total_outputs_amount"] += output["value"]
    return parsed_tx_outputs
