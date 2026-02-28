import hashlib
import json
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple


RPC_URL = "https://studio.genlayer.com/api"
CONTRACT_ADDRESS = "0x57a3212cbca238455291ad8ca2CA51F4D269Ae6F"

# RPC method: use "gen_sendTransaction" if your RPC supports it.
# If unsure, start with "gen_call" (won't persist on-chain).
CALL_METHOD = "gen_sendTransaction"  # or "gen_call"

# Optional fields for some RPC backends
FROM_ADDRESS = ""  # set if your RPC requires a sender

POLL_SECONDS = 45
SCORE_THRESHOLD = 60

STATE_FILE = "monitor_state.json"


KEYWORDS = {
    "exploit": 30,
    "hacked": 30,
    "hack": 25,
    "drained": 30,
    "breach": 25,
    "attack": 20,
    "bridge": 20,
    "reentrancy": 35,
    "oracle": 20,
    "rug": 25,
    "rugpull": 25,
    "liquidation": 15,
    "protocol": 10,
    "vulnerability": 25,
    "critical": 20,
    "incident": 15,
    "exploiters": 25,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_state() -> Dict[str, Any]:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"seen": {}}


def _save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def _score_text(text: str) -> Tuple[int, List[str]]:
    t = text.lower()
    score = 0
    hits: List[str] = []
    for k, v in KEYWORDS.items():
        if k in t:
            score += v
            hits.append(k)
    return min(score, 100), hits


def _hash_id(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _fetch_rss(url: str) -> List[Dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "GenLayerMonitor/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = resp.read()
    root = ET.fromstring(data)
    items = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        guid = (item.findtext("guid") or link).strip()
        items.append({"title": title, "link": link, "pub_date": pub_date, "id": guid})
    return items


def _news_sources() -> List[str]:
    q = urllib.parse.quote("defi hack exploit bridge protocol vulnerability")
    return [
        f"https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en",
        "https://www.coindesk.com/arc/outboundfeeds/rss/",
        "https://cointelegraph.com/rss",
    ]


def _rpc_call(method: str, params: List[Any]) -> Dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time()),
        "method": method,
        "params": params,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        RPC_URL, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
    return json.loads(raw)


def _call_analyze(tx_data: str, tx_hash: str) -> None:
    args = [tx_data, tx_hash]
    tx_obj = {"to": CONTRACT_ADDRESS, "method": "analyze_transaction", "args": args}
    if FROM_ADDRESS:
        tx_obj["from"] = FROM_ADDRESS
    # Some StudioNet setups expect params: [tx_obj]
    result = _rpc_call(CALL_METHOD, [tx_obj])
    print(f"[{_now_iso()}] analyze_transaction -> {result}")


def main() -> None:
    state = _load_state()
    seen = state.get("seen", {})
    print(f"[{_now_iso()}] Monitor started.")

    while True:
        try:
            sources = _news_sources()
            new_items = []
            for src in sources:
                try:
                    items = _fetch_rss(src)
                    new_items.extend(items)
                except Exception as e:
                    print(f"[{_now_iso()}] RSS error: {src} -> {e}")

            for item in new_items:
                item_id = _hash_id(item.get("id", "") + item.get("link", ""))
                if item_id in seen:
                    continue
                seen[item_id] = _now_iso()

                text = f"{item.get('title','')} {item.get('link','')} {item.get('pub_date','')}"
                score, hits = _score_text(text)
                if score >= SCORE_THRESHOLD:
                    tx_hash = "0x" + _hash_id(item.get("link", item_id))[:64]
                    tx_data = (
                        f"news_alert title='{item.get('title','')}' "
                        f"link='{item.get('link','')}' "
                        f"pub_date='{item.get('pub_date','')}' "
                        f"score={score} hits={hits}"
                    )
                    print(f"[{_now_iso()}] Alert score={score} hits={hits}")
                    _call_analyze(tx_data, tx_hash)

            state["seen"] = seen
            _save_state(state)
        except Exception as e:
            print(f"[{_now_iso()}] Loop error: {e}")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
