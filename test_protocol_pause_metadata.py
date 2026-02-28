def test_cross_protocol_pause_methods_exist():
    with open("hack_detection_contract.py", "r", encoding="utf-8") as f:
        src = f.read()

    required = [
        "class ProtocolPauseSignal(Event):",
        "def register_protocol(",
        "def unregister_protocol(",
        "def pause_protocol(",
        "def clear_protocol_pause(",
        "def should_pause_protocol(",
        "def get_protocol_pause_status(",
    ]
    for token in required:
        assert token in src, f"Missing expected contract API: {token}"

