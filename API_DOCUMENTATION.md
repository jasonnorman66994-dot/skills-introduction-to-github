# Zero Trust Security Framework

A comprehensive Python implementation of Zero Trust Security architecture with Multi-Factor Authentication (MFA), least privilege authorization, session management, and comprehensive audit logging.

## 🔐 Features

### Core Authentication
- **Multi-Factor Authentication (MFA)**: Requires both password and TOTP
- **Secure Token Generation**: SHA256-based authentication tokens
- **Token Verification**: Built-in token validation and verification

### Authorization & Access Control
- **Least Privilege Access**: Role-based policy definition
- **Wildcard Resource Matching**: Support for resource patterns (e.g., `/api/users/*`)
- **Granular Permissions**: Read, Write, Delete, and Admin permissions
- **Policy Revocation**: Dynamic policy management

### Session Management
- **Session Lifecycle**: Create, validate, and invalidate sessions
- **Activity Tracking**: Monitor last activity timestamp
- **Automatic Expiration**: Configurable session timeout
- **User Session Lookup**: Retrieve all sessions for a user

### Audit Logging
- **Comprehensive Event Logging**: Track all security events
- **Event Filtering**: Query by actor, event type, or severity
- **Critical Event Detection**: Identify high-severity incidents
- **JSON Export**: Export audit trails for compliance

### REST API (FastAPI)
- **Authentication Endpoint**: `/api/v1/authenticate`
- **Authorization Endpoint**: `/api/v1/authorize`
- **Policy Management**: Create and manage access policies
- **Audit Access**: Query audit logs and summaries
- **Session Management**: Manage user sessions

## 📋 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jasonnorman66994-dot/skills-introduction-to-github.git
cd skills-introduction-to-github

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .
```

### With Optional Features

```bash
# Development (testing tools)
pip install -e ".[dev]"

# API support (FastAPI)
pip install -e ".[api]"

# Documentation
pip install -e ".[docs]"

# All extras
pip install -e ".[dev,api,docs]"
```

## 🚀 Quick Start

### Authentication Example

```python
from zero_trust import Authenticator, AuthMethod

# Create authenticator
authenticator = Authenticator()

# Authenticate with MFA
credentials = {
    AuthMethod.PASSWORD: "secure_password",
    AuthMethod.TOTP: "123456",
}
token = authenticator.authenticate("user123", credentials)
print(f"Authenticated! Token: {token}")
```

### Authorization Example

```python
from zero_trust import AuthorizationEngine, Policy, Permission

# Create authorization engine
authz = AuthorizationEngine()

# Define a policy
policy = Policy(
    policy_id="policy-001",
    principal="user123",
    resource="/api/users/*",
    permissions={Permission.READ},
)
authz.add_policy(policy)

# Check authorization
allowed = authz.authorize("user123", "/api/users/list", Permission.READ)
print(f"Access {'granted' if allowed else 'denied'}")
```

### Session Management Example

```python
from zero_trust import SessionManager
import uuid

# Create session manager
session_mgr = SessionManager()

# Create a session
session_id = str(uuid.uuid4())
session = session_mgr.create_session(session_id, "user123", "token_abc123")

# Later: verify session is still valid
valid = session_mgr.get_session(session_id) is not None
print(f"Session valid: {valid}")

# Update activity
session_mgr.update_activity(session_id)
```

### Audit Logging Example

```python
from zero_trust import AuditLogger, EventType, Severity

# Create audit logger
audit = AuditLogger()

# Log an event
audit.log_event(
    event_type=EventType.AUTHENTICATION_SUCCESS,
    actor="user123",
    severity=Severity.INFO,
    action="login",
)

# Retrieve events
events = audit.get_events(actor="user123")
print(f"Found {len(events)} events")

# Get summary
summary = audit.get_event_summary()
print(summary)
```

## 🔌 REST API Usage

### Start the API Server

```bash
python -m api.app
# or
uvicorn api.app:app --reload
```

Server runs on `http://localhost:8000`

### API Endpoints

#### Health Check
```bash
GET /health
```

#### Authentication
```bash
POST /api/v1/authenticate
Content-Type: application/json

{
  "user_id": "user123",
  "password": "secure_password",
  "totp": "123456"
}
```

Response:
```json
{
  "token": "dfe4732a2707f150...",
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": 1705430400.123
}
```

#### Authorization Check
```bash
POST /api/v1/authorize
Content-Type: application/json

{
  "principal": "user123",
  "resource": "/api/users/list",
  "permission": "read",
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Response:
```json
{
  "allowed": true,
  "reason": "Access granted"
}
```

#### Create Policy
```bash
POST /api/v1/policies
Content-Type: application/json

{
  "principal": "user123",
  "resource": "/api/users/*",
  "permissions": ["read", "write"]
}
```

#### Get Audit Events
```bash
GET /api/v1/audit/events?actor=user123&limit=50
```

#### Get Audit Summary
```bash
GET /api/v1/audit/summary
```

#### Get Critical Events
```bash
GET /api/v1/audit/critical-events
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=zero_trust

# Specific test
pytest tests/test_authentication.py -v
```

Test coverage includes:
- ✅ Authentication (MFA validation, token generation)
- ✅ Authorization (policy evaluation, wildcard matching)
- ✅ Session management (creation, validation, expiration)
- ✅ Audit logging (event recording, filtering, export)

## 📊 Architecture

```
zero_trust/
├── __init__.py              # Package exports
├── authentication.py        # MFA authentication
├── authorization.py         # Least privilege authorization
├── session.py              # Session management
└── audit.py                # Audit logging

api/
├── __init__.py
└── app.py                  # FastAPI application

tests/
├── conftest.py             # Pytest fixtures
├── test_authentication.py
└── test_authorization.py

example_zero_trust.py        # Usage example
setup.py                     # Package configuration
requirements.txt             # Dependencies
```

## 🔒 Security Principles

1. **Defense in Depth**: Multiple layers of authentication and authorization
2. **Least Privilege**: Users get minimal necessary permissions
3. **Continuous Verification**: Every request is verified
4. **Auditable**: All security events are logged
5. **Fail Secure**: Default deny on any authorization check

## 📝 Configuration

### Session Timeout
```python
session_mgr = SessionManager(session_timeout=7200)  # 2 hours
```

### Audit Event Details
```python
audit.log_event(
    event_type=EventType.AUTHORIZATION_DENIED,
    actor="user123",
    severity=Severity.WARNING,
    resource="/api/admin/settings",
    action="access_admin",
    details={"ip_address": "192.168.1.1", "user_agent": "..."}
)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## ✉️ Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Version**: 0.1.0  
**Last Updated**: April 2026  
**Status**: Alpha
