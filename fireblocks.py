from fireblocks_sdk import FireblocksSDK


class FireblocksClient:
    def __init__(self):
        self.api_key = "66b36f2c-fac0-41f7-9cf9-bfa3e20f3f8f"
        with open("/Users/slavaserebriannyi/api_keys/fireblocks_secret.key", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)

    def get_tx_refs(self, vault_account_id):
        return self.client.get_unspent_inputs(str(vault_account_id), "BTC")

    def get_change_address(self, vault_account_id):
        addresses = self.client.get_deposit_addresses(str(vault_account_id), "BTC")
        for address in addresses:
            if address["addressFormat"] == "SEGWIT" and address["type"] == "Permanent":
                return address["address"]
