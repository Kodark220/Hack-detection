import json
import os
import time
import urllib.request
import argparse
import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple


RPC_URL = os.getenv("GENLAYER_RPC_URL", "https://studio.genlayer.com/api")
CONTRACT_ADDRESS = os.getenv("GENLAYER_CONTRACT", "")
FROM_ADDRESS = os.getenv("GENLAYER_FROM", "")
API_KEY = os.getenv("GENLAYER_API_KEY", "")
CALL_WRITE = os.getenv("GENLAYER_WRITE_METHOD", "gen_sendTransaction")
CALL_VIEW = os.getenv("GENLAYER_VIEW_METHOD", "gen_call")

PATTERN_FEED_URLS = [
    u.strip() for u in os.getenv("PATTERN_FEED_URLS", "").split(",") if u.strip()
]
PATTERN_MIN_CONFIDENCE = int(os.getenv("PATTERN_MIN_CONFIDENCE", "70"))
PATTERN_MAX_PER_RUN = int(os.getenv("PATTERN_MAX_PER_RUN", "10"))
PATTERN_DRY_RUN = os.getenv("PATTERN_DRY_RUN", "1") == "1"
PATTERN_SOURCE_ALLOWLIST = [
    d.strip().lower()
    for d in os.getenv("PATTERN_SOURCE_ALLOWLIST", "").split(",")
    if d.strip()
]
PATTERN_SIGNATURE_REGEX = os.getenv(
    "PATTERN_SIGNATURE_REGEX",
    r"^[a-zA-Z0-9_\-:.()/,\s]{6,180}$",
)


def _rpc_call(method: str, params: List[Any]) -> Dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "PatternUpdater/1.0"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
        headers["x-api-key"] = API_KEY
    req = urllib.request.Request(RPC_URL, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def _call_view(method: str, args: List[Any]) -> Dict[str, Any]:
    call_obj = {"to": CONTRACT_ADDRESS, "method": method, "args": args}
    return _rpc_call(CALL_VIEW, [call_obj])


def _call_write(method: str, args: List[Any]) -> Dict[str, Any]:
    tx_obj = {"to": CONTRACT_ADDRESS, "method": method, "args": args}
    if FROM_ADDRESS:
        tx_obj["from"] = FROM_ADDRESS
    return _rpc_call(CALL_WRITE, [tx_obj])


def _fetch_text(url: str) -> Tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "PatternUpdater/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        content_type = (resp.headers.get("Content-Type") or "").lower()
        body = resp.read().decode("utf-8", errors="replace")
    return body, content_type


def _is_source_allowed(url: str) -> bool:
    if not PATTERN_SOURCE_ALLOWLIST:
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in PATTERN_SOURCE_ALLOWLIST


def _normalize_signature(signature: str) -> str:
    sig = (signature or "").strip().lower()
    for ch in ["\n", "\r", "\t"]:
        sig = sig.replace(ch, " ")
    sig = " ".join(sig.split())
    return sig[:180]


def _normalize_description(description: str) -> str:
    desc = (description or "").strip()
    for ch in ["\n", "\r", "\t"]:
        desc = desc.replace(ch, " ")
    desc = " ".join(desc.split())
    return desc[:300]


def _is_valid_signature(signature: str, compiled_re: re.Pattern) -> bool:
    return bool(compiled_re.fullmatch(signature))


def _heuristic_confidence(signature: str, description: str) -> int:
    text = f"{signature} {description}".lower()
    score = 45
    if "reentrancy" in text:
        score += 20
    if "drain" in text or "stolen" in text or "exploit" in text:
        score += 15
    if "bridge" in text or "oracle" in text or "flash loan" in text:
        score += 10
    if len(signature) >= 6:
        score += 10
    return min(score, 100)


def _extract_patterns_from_json(obj: Any) -> List[Dict[str, Any]]:
    patterns: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("patterns"), list):
            items = obj["patterns"]
        else:
            items = [obj]
    elif isinstance(obj, list):
        items = obj
    else:
        items = []

    for item in items:
        if isinstance(item, str):
            patterns.append({"signature": item, "description": "Imported from feed"})
            continue
        if not isinstance(item, dict):
            continue
        signature = item.get("signature") or item.get("pattern") or item.get("ioc") or ""
        description = item.get("description") or item.get("title") or "Imported from feed"
        confidence = item.get("confidence")
        patterns.append(
            {
                "signature": signature,
                "description": description,
                "confidence": confidence,
            }
        )
    return patterns


def _extract_patterns(raw_text: str, content_type: str) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    # JSON feed: either [{"signature":"...","description":"..."}] or {"patterns":[...]}
    if "json" in content_type or raw_text.strip().startswith("{") or raw_text.strip().startswith("["):
        try:
            obj = json.loads(raw_text)
            return _extract_patterns_from_json(obj)
        except Exception:
            pass

    # Line feed: "signature|description|confidence"
    for line in raw_text.splitlines():
        row = line.strip()
        if not row or row.startswith("#"):
            continue
        parts = [p.strip() for p in row.split("|")]
        if len(parts) == 1:
            candidates.append({"signature": parts[0], "description": "Imported from feed"})
        elif len(parts) == 2:
            candidates.append({"signature": parts[0], "description": parts[1]})
        else:
            try:
                conf = int(parts[2])
            except Exception:
                conf = None
            candidates.append(
                {"signature": parts[0], "description": parts[1], "confidence": conf}
            )
    return candidates


def _get_onchain_signatures() -> set:
    try:
        res = _call_view("get_attack_patterns", [])
        data = res.get("result")
        if data is None:
            return set()
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                return set()
        seen = set()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    sig = _normalize_signature(str(item.get("signature", "")))
                    if sig:
                        seen.add(sig)
        return seen
    except Exception as exc:
        print(f"Warning: could not read on-chain patterns ({exc}). Continuing with empty set.")
        return set()


def _run_once(compiled_re: re.Pattern) -> None:
    if not CONTRACT_ADDRESS:
        raise RuntimeError("Set GENLAYER_CONTRACT env var.")
    if not PATTERN_FEED_URLS:
        raise RuntimeError("Set PATTERN_FEED_URLS to one or more comma-separated feed URLs.")

    onchain = _get_onchain_signatures()
    local_seen = set()
    candidates: List[Tuple[int, str, str]] = []

    for url in PATTERN_FEED_URLS:
        if not _is_source_allowed(url):
            print(f"Feed blocked (not in allowlist): {url}")
            continue
        try:
            raw_text, content_type = _fetch_text(url)
            extracted = _extract_patterns(raw_text, content_type)
            print(f"Feed {url}: extracted {len(extracted)} candidate patterns")
            for item in extracted:
                signature = _normalize_signature(str(item.get("signature", "")))
                description = _normalize_description(str(item.get("description", "")))
                if not signature:
                    continue
                if not _is_valid_signature(signature, compiled_re):
                    print(f"Rejected signature by regex: {signature}")
                    continue
                if signature in onchain or signature in local_seen:
                    continue
                confidence = item.get("confidence")
                if confidence is None:
                    confidence = _heuristic_confidence(signature, description)
                try:
                    confidence = int(confidence)
                except Exception:
                    confidence = 0
                if confidence < PATTERN_MIN_CONFIDENCE:
                    continue
                local_seen.add(signature)
                candidates.append((confidence, signature, description))
        except Exception as exc:
            print(f"Feed error: {url} -> {exc}")

    candidates.sort(reverse=True, key=lambda x: x[0])
    selected = candidates[:PATTERN_MAX_PER_RUN]

    print(f"Selected {len(selected)} new patterns (min confidence={PATTERN_MIN_CONFIDENCE})")
    for conf, sig, desc in selected:
        print(f"- [{conf}] {sig} :: {desc}")

    if not selected:
        return

    if PATTERN_DRY_RUN:
        print("Dry run mode is enabled (PATTERN_DRY_RUN=1). No on-chain writes performed.")
        return

    for conf, sig, desc in selected:
        try:
            res = _call_write("add_attack_pattern", [sig, desc])
            print(f"Submitted pattern [{conf}] {sig} -> {res}")
        except Exception as exc:
            print(f"Submit failed for signature '{sig}': {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch, vet, and submit attack patterns to HackDetection."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Run continuously, sleeping N seconds between runs (0 = run once).",
    )
    args = parser.parse_args()

    try:
        compiled_re = re.compile(PATTERN_SIGNATURE_REGEX)
    except re.error as exc:
        raise RuntimeError(f"Invalid PATTERN_SIGNATURE_REGEX: {exc}") from exc

    if args.interval <= 0:
        _run_once(compiled_re)
        return

    print(f"Scheduler mode enabled. Interval={args.interval}s")
    while True:
        try:
            _run_once(compiled_re)
        except Exception as exc:
            print(f"Run failed: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
