def test_metadata_lines():
    with open('hack_detection_contract.py', 'r', encoding='utf-8') as f:
        first_line = next(f).strip()
    assert 'depends' in first_line.lower(), f"Expected 'Depends' in first line, got: {first_line}"
    assert 'runner' not in first_line.lower(), f"Did not expect 'runner' in first line, got: {first_line}"