# HackDetection Intelligent Contract Documentation

## Overview
This contract provides AI-powered, real-time hack detection, emergency response, and continuous learning for smart contracts. It supports multi-admin controls, validator management, external notifications, and integration hooks for dashboards and bots.

## Features
- Real-time detection (AI + pattern matching)
- Deep threat analysis and escalation
- Proactive prediction and risk assessment
- Emergency response (circuit breaker, blacklisting, pausing, alerts)
- Continuous learning (event recording, pattern updates)
- Multi-admin and role-based permissions
- Configurable validator management
- External notification integration (webhook event)
- Rate limiting for notifications
- Enhanced event logging
- Integration hooks for dashboards/bots
- Cross-protocol pause signaling for integrated protocols
- Upgradeability support (see upgradeability_notes.md)

## Usage Guide

### 1. Deployment
- Deploy with an initial admin and validator list.

### 2. Admin Controls
- Add/remove admins: `add_admin`, `remove_admin`
- Set user roles: `set_role(user, role)`

### 3. Pattern Management
- Add attack pattern: `add_attack_pattern(signature, description)`
- Fetch patterns from trusted source: `fetch_patterns_from_source(url)`

### 4. Detection & Response
- Analyze transaction: `analyze_transaction(tx_data, tx_hash)`
- Escalate analysis: `escalate_analysis(tx_hash)`
- Unpause contract: `unpause()`

### 5. Cross-Protocol Protection
- Register protocol for protection: `register_protocol(protocol_address)`
- Remove protocol from protection list: `unregister_protocol(protocol_address)`
- Manual protocol pause signal: `pause_protocol(protocol_address, reason, tx_hash, risk_score)`
- Clear protocol pause signal: `clear_protocol_pause(protocol_address)`
- Protocol guard query: `should_pause_protocol(protocol_address)`
- Protocol status details: `get_protocol_pause_status(protocol_address)`

Integrated protocol contracts should gate sensitive functions with:
- `should_pause_protocol(address(this)) == false`
- Optional sender blacklist checks via `is_address_blacklisted(msg.sender)`

### 6. Notifications
- Get notifications: `get_notifications(user)`
- WebhookNotification event for off-chain alerts

### 7. Event Logging
- Get security events: `get_security_events()`
- SecurityEventEmitted event for dashboards/bots

### 8. Integration
- Listen for `WebhookNotification` and `SecurityEventEmitted` events for external automation

### 9. Upgradeability
- See `upgradeability_notes.md` for migration patterns

## Example Integrations
- DeFi protocol: Monitor all user transactions, auto-pause on threat, and halt when `should_pause_protocol` is true
- NFT marketplace: Detect suspicious transfers, alert owners
- DAO treasury: Escalate large withdrawals for deep analysis
- Bridge: Blacklist addresses on cross-chain exploit detection
- Frontend: Display notifications and event logs to users
- Security bots: Listen for events and trigger automated responses

## Testing
- See `test_hack_detection.py` for test patterns

## Pattern Updater Bot
Use `pattern_updater.py` to fetch attack patterns from web feeds and submit vetted entries to the contract.

### Feed formats supported
- JSON list: `[{"signature":"...", "description":"...", "confidence":85}]`
- JSON object: `{"patterns":[...]}`
- Text lines: `signature|description|confidence`

### Environment variables
- `GENLAYER_RPC_URL` RPC endpoint
- `GENLAYER_CONTRACT` HackDetection contract address
- `GENLAYER_FROM` optional sender address for write txs
- `GENLAYER_API_KEY` optional API key
- `PATTERN_FEED_URLS` comma-separated feed URLs
- `PATTERN_SOURCE_ALLOWLIST` comma-separated allowed feed hostnames (e.g. `example.com,raw.githubusercontent.com`)
- `PATTERN_MIN_CONFIDENCE` minimum score (default `70`)
- `PATTERN_MAX_PER_RUN` cap additions per run (default `10`)
- `PATTERN_DRY_RUN` `1` for preview, `0` to submit on-chain
- `PATTERN_SIGNATURE_REGEX` regex gate for accepted signatures

### Example
```bash
set PATTERN_FEED_URLS=https://example.com/patterns.json,https://example.com/patterns.txt
set GENLAYER_CONTRACT=0xYourContractAddress
set PATTERN_DRY_RUN=1
python pattern_updater.py
```

### Continuous scheduler mode
```bash
set PATTERN_SOURCE_ALLOWLIST=example.com,raw.githubusercontent.com
set PATTERN_SIGNATURE_REGEX=^[a-zA-Z0-9_\-:.()/,\s]{6,180}$
set PATTERN_DRY_RUN=0
python pattern_updater.py --interval 600
```

## Bot Supervisor
Use `bot_supervisor.py` to run both `monitor.py` and `pattern_updater.py` together with automatic restart.

### Environment variables
- `PATTERN_UPDATER_INTERVAL` seconds between updater runs (default `600`)
- `SUPERVISOR_RESTART_DELAY` restart delay after crash (default `5`)
- `SUPERVISOR_CHECK_INTERVAL` health-check loop interval (default `2`)
- `SUPERVISOR_LOG_DIR` log folder (default `logs`)

### Start
```bash
set PATTERN_UPDATER_INTERVAL=600
python bot_supervisor.py
```

### Logs
- `logs/monitor.log`
- `logs/pattern_updater.log`

## Onboarding
- Assign roles to team members
- Set up off-chain relayer for webhook/email/SMS
- Integrate dashboard with event hooks

For more, see GenLayer documentation and contract source code.
