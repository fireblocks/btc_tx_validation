import json

def restructure_key_link_payload(input_json):
    """
    Reads a JSON file, extracts 'txMetaData' and 'signInfo' from the payload,
    and writes them into a new JSON file.

    Parameters:
        input_file (str): The input JSON file to process.
        output_file (str): The file to save the new JSON structure.

    Returns:
        None
    """

    original_json = input_json
    # Traverse to the 'txMetaData' and 'signInfo' fields
    messages = original_json.get("messages", [])
    if not messages:
        raise ValueError("No 'messages' found in the provided JSON.")

    message = messages[0].get("message", {})
    payload = message.get("payload", {})

    # If the payload is a stringified JSON, parse it
    if isinstance(payload, str):
        payload = json.loads(payload)
    # Extract txMetaData and signInfo
    metadata = payload.get("metadata", None)
    tx_metadata = metadata.get("txMetaData", None)
    sign_info = payload.get("signInfo", None)


    if tx_metadata is None:
        raise ValueError("Field 'txMetaData' not found in the payload.")
    if sign_info is None:
        raise ValueError("Field 'signInfo' not found in the payload.")

    # Create the new JSON structure
    new_json = tx_metadata
    new_json["rawTx"] = sign_info
    new_json["sourceId"] = tx_metadata["srcId"]
    new_json["fee"] = metadata["coinbaseFee"]

    return new_json
