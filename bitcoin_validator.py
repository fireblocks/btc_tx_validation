import bitcoinlib
from decimal import Decimal
from fireblocks import FireblocksClient
from utils.bitcoin_utils import serialize_output, verify_single_segwit_input, double_sha
from utils.legacy_tx_utils import (
    parse_legacy_tx_input,
    parse_legacy_tx_output,
    LegacyTransactionValidationException,
)
from utils.segwit_tx_utils import calculate_total_amount, calculate_change_amount


class BitcoinValidator:
    def __init__(self, callback_metadata):
        self.raw_tx = callback_metadata["rawTx"]
        self.metadata = callback_metadata
        self.fireblocks = FireblocksClient()

    def build_outputs(self, payload_amount, fee, change_amount):
        if not change_amount:
            outputs = serialize_output(
                self.metadata["destAddress"], payload_amount - fee
            )
        else:
            outputs = serialize_output(self.metadata["destAddress"], payload_amount)
            change_address = self.fireblocks.get_change_address(
                self.metadata["sourceId"]
            )
            outputs += serialize_output(change_address, change_amount)
        return outputs

    def validate_segwit_tx(self):
        source_vault_account_id = self.metadata["sourceId"]
        tx_refs = self.fireblocks.get_tx_refs(source_vault_account_id)
        total_amount = calculate_total_amount(self.metadata["rawTx"])
        payload_amount = int(
            Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10**8)
        )
        fee = int(Decimal(self.metadata["fee"]) * Decimal(10**8))
        change_amount = calculate_change_amount(total_amount, payload_amount, fee)
        outputs = self.build_outputs(payload_amount, fee, change_amount)

        for input_to_sign in self.metadata["rawTx"]:
            try:
                verify_single_segwit_input(
                    bytearray.fromhex(input_to_sign["rawTx"]),
                    tx_refs,
                    double_sha(outputs),
                )
            except AssertionError as e:
                print(e)
                return False
        return True

    def validate_legacy_tx(self):
        bitcoinlib.transactions.Transaction.parse_hex(
            self.metadata["rawTx"][0]["rawTx"], strict=False
        ).as_dict()
        tx_refs = self.fireblocks.get_tx_refs(self.metadata["sourceId"])
        num_of_inputs = len(self.metadata["rawTx"])
        parsed_txs = [
            parse_legacy_tx_input(raw_input, tx_refs, num_of_inputs)
            for raw_input in self.metadata["rawTx"]
        ]
        parsed_tx_outputs = parse_legacy_tx_output(parsed_txs[0])

        tx_fee = int(Decimal(self.metadata["fee"]) * Decimal(10**8))
        metadata_amount = int(
            Decimal(self.metadata["destinations"][0]["amountNative"]) * Decimal(10**8)
        )
        metadata_destination = self.metadata["destinations"][0]["displayDstAddress"]

        if len(parsed_txs[0]["outputs"]) == 1:
            metadata_amount -= tx_fee

        if (
            metadata_destination not in parsed_tx_outputs
            or metadata_amount != parsed_tx_outputs[metadata_destination]
            or sum(tx["amount"] for tx in parsed_txs[0]["inputs"])
            - parsed_tx_outputs["total_outputs_amount"]
            - tx_fee
            > 0
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
