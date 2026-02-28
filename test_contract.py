import json
import os
import time
import urllib.request


RPC_URL = os.getenv("GENLAYER_RPC_URL", "https://studio.genlayer.com/api")
CONTRACT_ADDRESS = os.getenv("GENLAYER_CONTRACT", "0x57a3212cbca238455291ad8ca2CA51F4D269Ae6F")
FROM_ADDRESS = os.getenv("GENLAYER_FROM", "")
API_KEY = os.getenv("GENLAYER_API_KEY", "")

# Use gen_sendTransaction for writes (StudioNet often accepts unsigned txs)
CALL_WRITE = os.getenv("GENLAYER_WRITE_METHOD", "gen_sendTransaction")
CALL_VIEW = os.getenv("GENLAYER_VIEW_METHOD", "gen_call")

POLL_SECONDS = 5
POLL_ATTEMPTS = 10


def _rpc_call(method: str, params):
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "GenLayerTest/1.0"}
    if API_KEY:
        # Try common header names
        headers["Authorization"] = f"Bearer {API_KEY}"
        headers["x-api-key"] = API_KEY
    req = urllib.request.Request(
        RPC_URL, data=data, headers=headers
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def _call_write(method: str, args):
    tx_obj = {"to": CONTRACT_ADDRESS, "method": method, "args": args}
    if FROM_ADDRESS:
        tx_obj["from"] = FROM_ADDRESS
    return _rpc_call(CALL_WRITE, [tx_obj])


def _call_view(method: str, args):
    call_obj = {"to": CONTRACT_ADDRESS, "method": method, "args": args}
    return _rpc_call(CALL_VIEW, [call_obj])


def _poll_analysis(tx_hash: str) -> str:
    for _ in range(POLL_ATTEMPTS):
        res = _call_view("get_tx_analysis_readable", [tx_hash])
        data = res.get("result")
        if isinstance(data, str) and data and "No analysis found" not in data:
            return data
        time.sleep(POLL_SECONDS)
    return "No analysis found after polling."


def main():
    print(f"RPC: {RPC_URL}")
    print(f"Contract: {CONTRACT_ADDRESS}")

    # 1) Analyze normal tx
    tx_hash_normal = "0xTEST123"
    tx_data_normal = "transfer(user=0xabc, amount=1)"
    print("Analyze normal tx...")
    print(_call_write("analyze_transaction", [tx_data_normal, tx_hash_normal]))
    print("Analysis (normal):", _poll_analysis(tx_hash_normal))

    # 2) Add attack pattern
    print("Add attack pattern...")
    print(_call_write("add_attack_pattern", ["suspicious_call", "Known exploit signature"]))

    # 3) Analyze threat tx
    tx_hash_threat = "0xTHREAT1"
    tx_data_threat = "call: suspicious_call target=0xdeadbeef"
    print("Analyze threat tx...")
    print(_call_write("analyze_transaction", [tx_data_threat, tx_hash_threat]))
    print("Analysis (threat):", _poll_analysis(tx_hash_threat))

    # 4) Check paused
    print("Paused?", _call_view("get_paused", []))

    # 5) Unpause
    print("Unpause...")
    print(_call_write("unpause", []))
    print("Paused after unpause?", _call_view("get_paused", []))

    # 6) Notifications for admin (uses FROM_ADDRESS if provided)
    if FROM_ADDRESS:
        print("Notifications:", _call_view("get_notifications", [FROM_ADDRESS]))

    # 7) Recent analyses
    print("Recent analyses:", _call_view("get_recent_analyses", [5]))


if __name__ == "__main__":
    main()
