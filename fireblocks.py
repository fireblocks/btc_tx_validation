from fireblocks_sdk import FireblocksSDK


class FireblocksClient:
    def __init__(self):
        self.api_key = "<your_api_key>"
        with open("<path_to_your_api_key>", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)

    def get_tx_refs(self, vault_account_id):
        return self.client.get_unspent_inputs(str(vault_account_id), "BTC")

    def get_change_address(self, vault_account_id):
        addresses = self.client.get_deposit_addresses(str(vault_account_id), "BTC")
        for address in addresses:
            if address["addressFormat"] == "SEGWIT" and address["type"] == "Permanent":
                return address["address"]
