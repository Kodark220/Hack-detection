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
- Upgradeability support (see upgradeability_notes.md)

## Usage Guide

### 1. Deployment
- Deploy with an initial admin and validator list.

### 2. Admin Controls
- Add/remove admins: `add_admin`, `remove_admin`
- Set user roles: `set_role(user, role)`

### 3. Validator Management
- Add/remove validators: `add_validator`, `remove_validator`
- Set validator reputation: `set_validator_reputation`

### 4. Pattern Management
- Add attack pattern: `add_attack_pattern(signature, description)`
- Fetch patterns from trusted source: `fetch_patterns_from_source(url)`

### 5. Detection & Response
- Analyze transaction: `analyze_transaction(tx_data, tx_hash, sender)`
- Escalate analysis: `escalate_analysis(tx_hash)`
- Unpause contract: `unpause()`

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
- DeFi protocol: Monitor all user transactions, auto-pause on threat
- NFT marketplace: Detect suspicious transfers, alert owners
- DAO treasury: Escalate large withdrawals for deep analysis
- Bridge: Blacklist addresses on cross-chain exploit detection
- Frontend: Display notifications and event logs to users
- Security bots: Listen for events and trigger automated responses

## Testing
- See `test_hack_detection.py` for test patterns

## Onboarding
- Assign roles to team members
- Set up off-chain relayer for webhook/email/SMS
- Integrate dashboard with event hooks

For more, see GenLayer documentation and contract source code.
