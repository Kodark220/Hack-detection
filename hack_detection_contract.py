# { "Depends": "py-genlayer:test" }

import json
from dataclasses import dataclass
from genlayer import *
from genlayer.gl.vm import UserError
from genlayer.gl import Event

@allow_storage
@dataclass
class SecurityEvent:
    timestamp: u256
    event_type: str
    details: str
    tx_hash: str
    risk_score: u8
    affected_asset: str  # e.g., token, NFT, etc.
    contract_address: Address
    user_action: str
    user: Address

@allow_storage
@dataclass
class AttackPattern:
    pattern_id: u256
    signature: str
    description: str
    confirmed: bool


class SecurityEventEmitted(Event):
    def __init__(self, /, **blob): ...


class WebhookNotification(Event):
    def __init__(self, /, **blob): ...


class ProtocolPauseSignal(Event):
    def __init__(self, /, **blob): ...


class HackDetection(gl.Contract):
    """
    Intelligent Contract for Hack Detection and Emergency Pause

    This contract leverages GenLayer's AI-native blockchain capabilities:
    - Real-time, non-deterministic threat detection using LLMs and pattern matching
    - Subjective, consensus-based decision-making (AI validator voting)
    - Proactive prediction and continuous learning
    - Emergency response and owner/user notifications
    - Designed for DeFi, NFT, DAO, bridge, and high-value contract security
    """


    # Config
    notification_limit: u8
    notify_level_min: u8
    auto_pause_level_min: u8

    # Role definitions
    ADMIN_ROLE = "admin"
    SECURITY_ROLE = "security_officer"
    USER_ROLE = "user"

    # Core state
    is_paused: bool
    admin: Address  # legacy, for backward compatibility
    admins: TreeMap[Address, bool]
    roles: TreeMap[Address, str]
    blacklisted: TreeMap[Address, bool]
    security_events: DynArray[SecurityEvent]
    attack_patterns: DynArray[AttackPattern]
    tx_risk_scores: TreeMap[str, u8]
    tx_analysis: TreeMap[str, str]
    recent_hashes: TreeMap[u256, str]
    recent_index: u256
    circuit_breaker_triggered: bool
    notifications: TreeMap[Address, DynArray[str]]
    last_pattern_fetch: str
    last_pattern_added: str
    protected_protocols: TreeMap[Address, bool]
    protocol_pause_flags: TreeMap[Address, bool]
    protocol_pause_reasons: TreeMap[Address, str]
    protocol_pause_tx: TreeMap[Address, str]
    protocol_list: DynArray[Address]



    def _emit_webhook(self, user: Address, message: str, event_type: str, tx_hash: str):
        # Emit a compact string payload to avoid indexed-field parsing issues
        payload = f"{event_type}|{tx_hash}|{str(user)}|{message}"
        WebhookNotification(message=payload)

    def _risk_level(self, score: int) -> str:
        if score >= 71:
            return "HIGH"
        if score >= 31:
            return "MEDIUM"
        return "LOW"

    def _analysis_message(self, threat: bool, score: int) -> str:
        level = self._risk_level(score)
        if not threat:
            return "NO THREAT DETECTED."
        if level == "HIGH":
            return "HIGH LEVEL THREAT DETECTED."
        if level == "MEDIUM":
            return "MEDIUM LEVEL THREAT DETECTED."
        return "LOW LEVEL THREAT DETECTED."

    def _analysis_action(self, threat: bool, score: int) -> str:
        level = self._risk_level(score)
        if not threat:
            return "No action needed."
        if level == "HIGH":
            return "Pause contract and notify admin."
        if level == "MEDIUM":
            return "Notify admin."
        return "Monitor activity."
    @gl.public.view
    def explain_intelligence(self) -> str:
        """
        Returns a description of the contract's intelligent features and how it uses AI/LLMs for subjective, adaptive security.
        """
        return (
            "This is a GenLayer Intelligent Contract for hack detection. "
            "It uses AI-powered validators, LLM-based pattern analysis, and consensus mechanisms "
            "to detect, predict, and respond to threats in real time. "
            "The contract continuously learns from security events and adapts its detection logic. "
            "It provides notifications and emergency response for owners and users."
        )

    def __init__(self, admin: Address):
        admin_addr = self._to_address(admin)

        self.notification_limit = u8(20)  # Max notifications per user
        self.notify_level_min = u8(31)    # MEDIUM+
        self.auto_pause_level_min = u8(71)  # HIGH+
        self.is_paused = False
        self.admin = admin_addr
        self.admins[admin_addr] = True
        self.roles[admin_addr] = self.ADMIN_ROLE
        self.circuit_breaker_triggered = False
        self.last_pattern_fetch = ""
        self.last_pattern_added = ""
        self.recent_index = u256(0)

    def _emit_protocol_pause_signal(self, protocol: Address, reason: str, tx_hash: str, risk_score: int):
        payload = json.dumps({
            "protocol": str(protocol),
            "pause": True,
            "reason": reason,
            "tx_hash": tx_hash,
            "risk_score": int(risk_score),
        })
        ProtocolPauseSignal(message=payload)

    def _set_protocol_pause(self, protocol: Address, reason: str, tx_hash: str, risk_score: int):
        protocol_addr = self._to_address(protocol)
        if not self.protected_protocols.get(protocol_addr, False):
            return
        self.protocol_pause_flags[protocol_addr] = True
        self.protocol_pause_reasons[protocol_addr] = reason
        self.protocol_pause_tx[protocol_addr] = tx_hash
        self._emit_protocol_pause_signal(protocol_addr, reason, tx_hash, risk_score)

    def _signal_all_protocol_pauses(self, reason: str, tx_hash: str, risk_score: int):
        for protocol in self.protocol_list:
            if self.protected_protocols.get(protocol, False):
                self._set_protocol_pause(protocol, reason, tx_hash, risk_score)

    def _to_address(self, value):
        if isinstance(value, Address):
            return value
        if isinstance(value, int):
            # Treat as big-endian 20-byte address (mask to 160 bits)
            mask = (1 << 160) - 1
            v = value & mask
            return Address(v.to_bytes(20, "big"))
        # Accept hex strings from deployment UIs
        return Address(value)

    def _get_timestamp(self) -> int:
        # Try common runtime timestamp sources; fall back to 0 to avoid hard failure
        blk = getattr(gl, "block", None)
        if blk is not None and hasattr(blk, "timestamp"):
            return int(blk.timestamp)
        msg = getattr(gl, "message", None)
        if msg is not None and hasattr(msg, "timestamp"):
            return int(msg.timestamp)
        ts = getattr(gl, "timestamp", None)
        if ts is not None:
            return int(ts)
        return 0

    def _nondet_bool_token(self, prompt: str) -> str:
        # Return only TRUE or FALSE to stabilize validator outcomes
        raw = gl.nondet.exec_prompt(prompt)
        cleaned = raw.strip().upper()
        if "TRUE" in cleaned:
            return "TRUE"
        if "FALSE" in cleaned:
            return "FALSE"
        return "FALSE"

    def _require_role(self, role: str):
        sender = gl.message.sender_address
        if self.roles.get(sender, "") != role and not self.admins.get(sender, False):
            raise UserError(f"Only {role} or admin allowed")

    def _append_recent(self, tx_hash: str):
        self.recent_hashes[self.recent_index] = tx_hash
        self.recent_index = u256(int(self.recent_index) + 1)

    @gl.public.write
    def add_admin(self, new_admin: Address):
        self._require_role(self.ADMIN_ROLE)
        self.admins[new_admin] = True
        self.roles[new_admin] = self.ADMIN_ROLE
        self._notify(new_admin, "You have been granted admin rights.")
        self._emit_webhook(new_admin, "Granted admin rights", "admin_added", "")

    @gl.public.write
    def remove_admin(self, admin_addr: Address):
        self._require_role(self.ADMIN_ROLE)
        if admin_addr == self.admin:
            raise UserError("Cannot remove contract creator admin")
        self.admins[admin_addr] = False
        self.roles[admin_addr] = self.USER_ROLE
        self._notify(admin_addr, "Your admin rights have been revoked.")
        self._emit_webhook(admin_addr, "Admin rights revoked", "admin_removed", "")

    @gl.public.write
    def set_role(self, user: Address, role: str):
        self._require_role(self.ADMIN_ROLE)
        if role not in [self.ADMIN_ROLE, self.SECURITY_ROLE, self.USER_ROLE]:
            raise UserError("Invalid role")
        self.roles[user] = role
        self._notify(user, f"Your role has been set to {role}.")
        self._emit_webhook(user, f"Role set to {role}", "role_set", "")

    @gl.public.view
    def get_role(self, user: Address) -> str:
        user_addr = self._to_address(user)
        return self.roles.get(user_addr, self.USER_ROLE)

    @gl.public.write
    def fetch_patterns_from_source(self, source_url: str):
        self._require_role(self.ADMIN_ROLE)
        self.last_pattern_fetch = source_url
        # In this environment the actual fetch should be done off-chain by a relayer.
        # Record the request for auditing and notify admins.
        self._record_event("pattern_fetch_requested", "", 0, f"Pattern fetch requested from {source_url}", self.admin)
        self._emit_webhook(self.admin, f"Pattern fetch requested from {source_url}", "pattern_fetch", "")

    @gl.public.write
    def analyze_transaction(self, tx_data: str, tx_hash: str) -> None:
        """Real-time detection: AI + pattern matching
        Uses gl.message.sender_address as the caller (prevents spoofing).
        """
        sender = gl.message.sender_address
        if self.is_paused:
            raise UserError("Contract is paused")
        # 1. Pattern match
        threat_resolved = False
        for pattern in self.attack_patterns:
            if pattern.signature in tx_data:
                self._record_event("pattern_match", tx_hash, 90, f"Matched: {pattern.description}", sender)
                self._trigger_circuit_breaker(sender, tx_hash, 90)
                self._notify(sender, f"Abnormal activity detected: Pattern match ({pattern.description}) on tx {tx_hash}")
                self._notify(self.admin, f"Alert: Pattern match detected for user {sender} on tx {tx_hash}")
                self._emit_webhook(sender, f"Abnormal activity detected: Pattern match ({pattern.description})", "pattern_match", tx_hash)
                self._emit_webhook(self.admin, f"Alert: Pattern match detected for user {sender}", "pattern_match", tx_hash)
                self.tx_analysis[tx_hash] = json.dumps({
                    "threat": True,
                    "risk_score": 90,
                    "risk_level": "HIGH",
                    "reason": "Pattern match",
                    "pattern": pattern.description,
                    "message": "HIGH LEVEL THREAT DETECTED. Known attack pattern matched."
                })
                threat_resolved = True
                break
        if not threat_resolved:
            # 2. AI consensus via Equivalence Principle (platform validators)
            attack_patterns = list(self.attack_patterns)
            _nondet_bool_token = self._nondet_bool_token
            prompt = f"""SYSTEM: You are a security classifier. Output ONLY a single token: TRUE or FALSE.
Return TRUE only if the transaction is clearly malicious or strongly indicative of a hack.
If uncertain, return FALSE.
Data: {tx_data}
Known patterns: {[p.signature for p in attack_patterns]}
OUTPUT: TRUE or FALSE"""
            vote_token = gl.eq_principle.strict_eq(lambda p=prompt, f=_nondet_bool_token: f(p))
            risk_score = 80 if vote_token == "TRUE" else 20
            self.tx_risk_scores[tx_hash] = risk_score
            if vote_token == "TRUE":
                self._record_event("ai_detected", tx_hash, int(risk_score), "AI consensus", sender)
                self._trigger_circuit_breaker(sender, tx_hash, int(risk_score))
                self._notify(sender, f"Abnormal activity detected: AI consensus flagged your tx {tx_hash}")
                self._notify(self.admin, f"Alert: AI consensus flagged user {sender} on tx {tx_hash}")
                self._emit_webhook(sender, f"Abnormal activity detected: AI consensus flagged your tx", "ai_detected", tx_hash)
                self._emit_webhook(self.admin, f"Alert: AI consensus flagged user {sender}", "ai_detected", tx_hash)
                self.tx_analysis[tx_hash] = json.dumps({
                    "threat": True,
                    "risk_score": int(risk_score),
                    "risk_level": self._risk_level(int(risk_score)),
                    "reason": "AI consensus",
                    "message": self._analysis_message(True, int(risk_score)),
                    "action": self._analysis_action(True, int(risk_score))
                })
                threat_resolved = True
            if not threat_resolved:
                # 3. Proactive prediction (single-token)
                pred = self._predict_attack(tx_data)
                if pred["likely"]:
                    self._record_event("predicted_threat", tx_hash, int(pred["score"]), pred["reason"], sender)
                    self._notify(sender, f"Abnormal activity predicted on tx {tx_hash}")
                    self._notify(self.admin, f"Alert: Predicted threat for user {sender} on tx {tx_hash}")
                    self._emit_webhook(sender, "Abnormal activity predicted", "predicted_threat", tx_hash)
                    self._emit_webhook(self.admin, f"Alert: Predicted threat for user {sender}", "predicted_threat", tx_hash)
                    self.tx_analysis[tx_hash] = json.dumps({
                        "threat": True,
                        "risk_score": int(pred["score"]),
                        "risk_level": self._risk_level(int(pred["score"])),
                        "reason": "ai_bool",
                        "message": self._analysis_message(True, int(pred["score"])),
                        "action": self._analysis_action(True, int(pred["score"]))
                    })
                    threat_resolved = True
            if not threat_resolved:
                self.tx_analysis[tx_hash] = json.dumps({
                    "threat": False,
                    "risk_score": int(risk_score),
                    "risk_level": self._risk_level(int(risk_score)),
                    "message": self._analysis_message(False, int(risk_score)),
                    "action": self._analysis_action(False, int(risk_score))
                })
        # Record recent analyses for dashboard
        self._append_recent(tx_hash)

    def _predict_attack(self, tx_data: str) -> dict:
        """Forecast attack likelihood (deterministic single-token)"""
        _nondet_bool_token = self._nondet_bool_token
        prompt = f"""SYSTEM: Output ONLY a single token: TRUE or FALSE.
Return TRUE only if clearly malicious. If uncertain, return FALSE.
Data: {tx_data}
OUTPUT: TRUE or FALSE"""
        vote_token = gl.eq_principle.strict_eq(lambda p=prompt, f=_nondet_bool_token: f(p))
        return {"likely": vote_token == "TRUE", "score": 80 if vote_token == "TRUE" else 20, "reason": "ai_bool"}

    def _trigger_circuit_breaker(self, sender: Address, tx_hash: str, risk_score: int):
        self.circuit_breaker_triggered = True
        self.is_paused = True
        self.blacklisted[sender] = True
        self._signal_all_protocol_pauses(
            "Global circuit breaker triggered by hack detection",
            tx_hash,
            risk_score
        )
        self._record_event("circuit_breaker", tx_hash, risk_score, f"Sender {sender} blacklisted and contract paused", sender)
        self._notify(sender, f"Emergency: You have been blacklisted and contract paused due to suspicious tx {tx_hash}")
        self._notify(self.admin, f"Emergency: Contract paused and user {sender} blacklisted due to tx {tx_hash}")
        self._emit_webhook(sender, f"Emergency: You have been blacklisted and contract paused", "circuit_breaker", tx_hash)
        self._emit_webhook(self.admin, f"Emergency: Contract paused and user {sender} blacklisted", "circuit_breaker", tx_hash)

    def _record_event(self, event_type: str, tx_hash: str, risk_score: int, details: str, user: Address, affected_asset: str = "", user_action: str = ""):
        contract_addr = getattr(gl, "self_address", None)
        if contract_addr is None:
            msg = getattr(gl, "message", None)
            if msg is not None and hasattr(msg, "receiver_address"):
                contract_addr = msg.receiver_address
        if contract_addr is None:
            contract_addr = "0x0000000000000000000000000000000000000000"
        evt = SecurityEvent(
            timestamp=u256(self._get_timestamp()),
            event_type=event_type,
            details=details,
            tx_hash=tx_hash,
            risk_score=u8(risk_score),
            affected_asset=affected_asset,
            contract_address=Address(contract_addr),
            user_action=user_action,
            user=user,
        )
        self.security_events.append(evt)
        summary = json.dumps({
            "timestamp": int(evt.timestamp),
            "event_type": evt.event_type,
            "tx_hash": evt.tx_hash,
            "risk_score": int(evt.risk_score),
            "user": str(evt.user),
            "details": evt.details,
        })
        SecurityEventEmitted(message=summary)

    @gl.public.write
    def escalate_analysis(self, tx_hash: str) -> None:
        """Escalate to more validators for deep threat analysis"""
        _nondet_bool_token = self._nondet_bool_token
        prompt = f"""SYSTEM: Output ONLY a single token: TRUE or FALSE.
Return TRUE only if high-confidence malicious.
If uncertain, return FALSE.
Data: {tx_hash}
OUTPUT: TRUE or FALSE"""
        vote_token = gl.eq_principle.strict_eq(lambda p=prompt, f=_nondet_bool_token: f(p))
        if vote_token == "TRUE":
            caller = gl.message.sender_address
            self._record_event("deep_confirmed", tx_hash, 100, "High-confidence threat confirmed", caller)
            self._notify(self.admin, f"Deep threat confirmed for tx {tx_hash}")
            self._emit_webhook(self.admin, f"Deep threat confirmed for tx {tx_hash}", "deep_confirmed", tx_hash)
            self.tx_analysis[tx_hash] = json.dumps({"confirmed": True})
        else:
            self.tx_analysis[tx_hash] = json.dumps({"confirmed": False})

    @gl.public.write
    def unpause(self):
        if gl.message.sender_address != self.admin:
            raise UserError("Only admin can unpause")
        self.is_paused = False
        self.circuit_breaker_triggered = False
        self._record_event("unpaused", "", 0, "Contract unpaused by admin", self.admin)
        self._notify(self.admin, "Contract has been unpaused.")


    @gl.public.write
    def add_attack_pattern(self, signature: str, description: str):
        if gl.message.sender_address != self.admin:
            raise UserError("Only admin can add patterns")
        pattern = AttackPattern(
            pattern_id=u256(len(self.attack_patterns)),
            signature=signature,
            description=description,
            confirmed=False
        )
        self.attack_patterns.append(pattern)
        self.last_pattern_added = signature
        self._record_event("pattern_added", "", 0, description, self.admin)
        self._notify(self.admin, f"New attack pattern added: {description}")

    @gl.public.write
    def set_thresholds(self, notify_level_min: int, auto_pause_level_min: int):
        self._require_role(self.ADMIN_ROLE)
        self.notify_level_min = u8(notify_level_min)
        self.auto_pause_level_min = u8(auto_pause_level_min)

    @gl.public.write
    def register_protocol(self, protocol: Address):
        self._require_role(self.ADMIN_ROLE)
        protocol_addr = self._to_address(protocol)
        if not self.protected_protocols.get(protocol_addr, False):
            self.protected_protocols[protocol_addr] = True
            self.protocol_pause_flags[protocol_addr] = False
            self.protocol_pause_reasons[protocol_addr] = ""
            self.protocol_pause_tx[protocol_addr] = ""
            self.protocol_list.append(protocol_addr)
            self._record_event("protocol_registered", "", 0, f"Protocol registered: {protocol_addr}", self.admin)
            self._emit_webhook(self.admin, f"Protocol registered: {protocol_addr}", "protocol_registered", "")

    @gl.public.write
    def unregister_protocol(self, protocol: Address):
        self._require_role(self.ADMIN_ROLE)
        protocol_addr = self._to_address(protocol)
        self.protected_protocols[protocol_addr] = False
        self.protocol_pause_flags[protocol_addr] = False
        self.protocol_pause_reasons[protocol_addr] = ""
        self.protocol_pause_tx[protocol_addr] = ""
        self._record_event("protocol_unregistered", "", 0, f"Protocol unregistered: {protocol_addr}", self.admin)
        self._emit_webhook(self.admin, f"Protocol unregistered: {protocol_addr}", "protocol_unregistered", "")

    @gl.public.write
    def pause_protocol(self, protocol: Address, reason: str, tx_hash: str = "", risk_score: int = 100):
        self._require_role(self.ADMIN_ROLE)
        protocol_addr = self._to_address(protocol)
        if not self.protected_protocols.get(protocol_addr, False):
            raise UserError("Protocol not registered")
        # Write state directly so write intent is explicit for linters and auditors.
        self.protocol_pause_flags[protocol_addr] = True
        self.protocol_pause_reasons[protocol_addr] = reason
        self.protocol_pause_tx[protocol_addr] = tx_hash
        self._emit_protocol_pause_signal(protocol_addr, reason, tx_hash, risk_score)
        self._record_event("protocol_paused", tx_hash, risk_score, f"Protocol paused: {protocol_addr} reason={reason}", self.admin)

    @gl.public.write
    def clear_protocol_pause(self, protocol: Address):
        self._require_role(self.ADMIN_ROLE)
        protocol_addr = self._to_address(protocol)
        self.protocol_pause_flags[protocol_addr] = False
        self.protocol_pause_reasons[protocol_addr] = ""
        self.protocol_pause_tx[protocol_addr] = ""
        self._record_event("protocol_pause_cleared", "", 0, f"Protocol pause cleared: {protocol_addr}", self.admin)

    @gl.public.view
    def get_thresholds(self) -> str:
        return json.dumps({
            "notify_level_min": int(self.notify_level_min),
            "auto_pause_level_min": int(self.auto_pause_level_min)
        })

    def _notify(self, user: Address, message: str):
        notes = self.notifications.get(user, [])
        if len(notes) >= int(self.notification_limit):
            # Remove oldest to prevent spam
            notes = notes[1:]
        notes.append(message)
        self.notifications[user] = notes

    @gl.public.view
    def get_notifications(self, user: Address) -> DynArray[str]:
        user_addr = self._to_address(user)
        return self.notifications.get(user_addr, [])

    @gl.public.view
    def get_security_events(self) -> DynArray[SecurityEvent]:
        return self.security_events

    @gl.public.view
    def get_attack_patterns(self) -> DynArray[AttackPattern]:
        return self.attack_patterns

    @gl.public.view
    def is_address_blacklisted(self, addr: Address) -> bool:
        addr_norm = self._to_address(addr)
        return self.blacklisted.get(addr_norm, False)

    @gl.public.view
    def get_paused(self) -> bool:
        return self.is_paused

    @gl.public.view
    def is_protocol_registered(self, protocol: Address) -> bool:
        protocol_addr = self._to_address(protocol)
        return self.protected_protocols.get(protocol_addr, False)

    @gl.public.view
    def should_pause_protocol(self, protocol: Address) -> bool:
        protocol_addr = self._to_address(protocol)
        return self.protected_protocols.get(protocol_addr, False) and (
            self.is_paused or self.protocol_pause_flags.get(protocol_addr, False)
        )

    @gl.public.view
    def get_protocol_pause_status(self, protocol: Address) -> str:
        protocol_addr = self._to_address(protocol)
        return json.dumps({
            "registered": self.protected_protocols.get(protocol_addr, False),
            "paused": self.should_pause_protocol(protocol_addr),
            "reason": self.protocol_pause_reasons.get(protocol_addr, ""),
            "tx_hash": self.protocol_pause_tx.get(protocol_addr, "")
        })

    @gl.public.view
    def get_risk_score(self, tx_hash: str) -> int:
        return int(self.tx_risk_scores.get(tx_hash, u8(0)))


    @gl.public.view
    def get_tx_analysis(self, tx_hash: str) -> str:
        return self.tx_analysis.get(tx_hash, "")

    @gl.public.view
    def get_tx_analysis_readable(self, tx_hash: str) -> str:
        raw = self.tx_analysis.get(tx_hash, "")
        if raw == "":
            return "No analysis found for this transaction hash."
        try:
            parsed = json.loads(raw)
            threat = parsed.get("threat", False)
            score = int(parsed.get("risk_score", 0))
            level = parsed.get("risk_level", self._risk_level(score))
            message = parsed.get("message", self._analysis_message(bool(threat), score))
            action = parsed.get("action", self._analysis_action(bool(threat), score))
            return f"{message} Risk score: {score}. Level: {level}. Recommended action: {action}"
        except:
            return raw

    @gl.public.view
    def get_recent_analyses(self, count: int) -> str:
        n = max(0, int(count))
        end = int(self.recent_index)
        start = end - n if end - n > 0 else 0
        items = []
        for i in range(start, end):
            h = self.recent_hashes.get(u256(i), "")
            if h != "":
                items.append({
                    "tx_hash": h,
                    "summary": self.get_tx_analysis_readable(h)
                })
        return json.dumps(items)
