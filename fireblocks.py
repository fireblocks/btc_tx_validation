from fireblocks_sdk import FireblocksSDK


class FireblocksClient:
    """
    Fireblocks Client - uses Fireblocks SDK.
    """
    def __init__(self):
        self.api_key = "<your_api_key>"
        with open("<path_to_your_secret_key>", "r") as kf:
            self.secret_key = kf.read()
        self.client = FireblocksSDK(self.secret_key, self.api_key)

    def get_tx_refs(self, vault_account_id):
        """Get the unspent transaction outputs for a vault account
        
        :param vault_account_id (str): the id of the vault account 
        :return: unspent transaction outputs (list)
        """
        return self.client.get_unspent_inputs(str(vault_account_id), "BTC")

    def get_change_address(self, vault_account_id):
        """
        Get the change address for a BTC wallet in a vault account.
        The change address is the permanent segwit address of the wallet.
        
        :param vault_account_id (str): the id of the vault account  
        :return:  change address (str)
        """
        addresses = self.client.get_deposit_addresses(str(vault_account_id), "BTC")
        for address in addresses:
            if address["addressFormat"] == "SEGWIT" and address["type"] == "Permanent":
                return address["address"]