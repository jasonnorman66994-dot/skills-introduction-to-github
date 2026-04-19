# Zero Trust Security - Quickstart Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Installation

#### Option A: Install from PyPI (recommended)
```bash
pip install zero-trust
```

#### Option B: Install from source
```bash
git clone https://github.com/jasonnorman66994-dot/skills-introduction-to-github.git
cd skills-introduction-to-github
pip install -e .
```

#### Option C: Install with extras
```bash
# For development (testing, linting)
pip install -e ".[dev]"

# For API server
pip install -e ".[api]"

# Everything
pip install -e ".[dev,api,docs]"
```

---

## 📖 5-Minute Tutorial

### 1. Basic Authentication (1 minute)

```python
from zero_trust import Authenticator, AuthMethod

# Create an authenticator
auth = Authenticator()

# Authenticate a user with MFA
credentials = {
    AuthMethod.PASSWORD: "MySecurePassword123",
    AuthMethod.TOTP: "123456",  # 6-digit code from authenticator app
}

try:
    token = auth.authenticate("alice@example.com", credentials)
    print(f"✓ Authenticated! Token: {token[:16]}...")
except ValueError as e:
    print(f"✗ Authentication failed: {e}")
```

### 2. Define Access Policies (1 minute)

```python
from zero_trust import AuthorizationEngine, Policy, Permission

# Create authorization engine
authz = AuthorizationEngine()

# Define a policy: Alice can read user profiles
policy = Policy(
    policy_id="alice-read-profiles",
    principal="alice@example.com",
    resource="/api/users/*",
    permissions={Permission.READ},
)
authz.add_policy(policy)

print(f"✓ Policy created: {policy.policy_id}")
```

### 3. Check Access (1 minute)

```python
# Check if Alice can read a specific user profile
resource = "/api/users/bob@example.com"
permission = Permission.READ

allowed = authz.authorize("alice@example.com", resource, permission)

if allowed:
    print(f"✓ Access granted: Alice can read {resource}")
else:
    print(f"✗ Access denied: Alice cannot read {resource}")

# Check if Alice can modify (she shouldn't be able to)
allowed_write = authz.authorize("alice@example.com", resource, Permission.WRITE)
print(f"✓ Access denied: Alice cannot modify {resource}")
```

### 4. Session Management (1 minute)

```python
from zero_trust import SessionManager
import uuid

# Create session manager
session_mgr = SessionManager()

# Create a session for Alice
session_id = str(uuid.uuid4())
session = session_mgr.create_session(
    session_id,
    user_id="alice@example.com",
    token=token,
    metadata={"ip": "192.168.1.100", "user_agent": "Chrome"}
)

print(f"✓ Session created: {session_id}")
print(f"  Expires at: {session.expires_at}")

# Update activity timestamp
session_mgr.update_activity(session_id)
print(f"✓ Session activity updated")

# Later: Verify session is still valid
valid_session = session_mgr.get_session(session_id)
if valid_session:
    print(f"✓ Session is active")
```

### 5. Audit Logging (1 minute)

```python
from zero_trust import AuditLogger, EventType, Severity

# Create audit logger
audit = AuditLogger()

# Log authentication event
audit.log_event(
    event_type=EventType.AUTHENTICATION_SUCCESS,
    actor="alice@example.com",
    severity=Severity.INFO,
    action="login",
    details={"method": "mfa", "location": "office"},
)

# Log authorization event
audit.log_event(
    event_type=EventType.AUTHORIZATION_ALLOWED,
    actor="alice@example.com",
    severity=Severity.INFO,
    resource="/api/users/bob@example.com",
    action="read",
)

# Retrieve events
events = audit.get_events(actor="alice@example.com")
print(f"✓ Found {len(events)} audit events for Alice")

# Get summary
summary = audit.get_event_summary()
print(f"✓ Audit summary:")
print(f"  Total events: {summary['total_events']}")
print(f"  Event types: {summary['event_types']}")
```

---

## 🔒 Common Use Cases

### Use Case 1: Secure Web Application

```python
from zero_trust import (
    Authenticator, AuthMethod, AuthorizationEngine, Policy, Permission,
    SessionManager, AuditLogger, EventType, Severity, RateLimiter
)
import uuid

class SecureWebApp:
    def __init__(self):
        self.auth = Authenticator()
        self.authz = AuthorizationEngine()
        self.sessions = SessionManager()
        self.audit = AuditLogger()
        self.rate_limit = RateLimiter(max_requests=100, window_size=60)
        
        # Set up default policies
        self._setup_policies()
    
    def _setup_policies(self):
        """Set up default access policies."""
        # Admin policy
        admin_policy = Policy(
            policy_id="admin-all-access",
            principal="admin@example.com",
            resource="/api/*",
            permissions={Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN},
        )
        self.authz.add_policy(admin_policy)
        
        # User policy (can only access own data)
        user_policy = Policy(
            policy_id="user-self-access",
            principal="user@example.com",
            resource="/api/users/user@example.com/*",
            permissions={Permission.READ, Permission.WRITE},
        )
        self.authz.add_policy(user_policy)
    
    def login(self, user_id, password, totp):
        """Handle user login."""
        # Check rate limiting
        if not self.rate_limit.is_allowed(user_id):
            self.audit.log_event(
                EventType.AUTHENTICATION_FAILURE,
                user_id, Severity.WARNING,
                result="rate_limited"
            )
            raise Exception("Too many login attempts. Try again later.")
        
        # Authenticate
        try:
            credentials = {
                AuthMethod.PASSWORD: password,
                AuthMethod.TOTP: totp,
            }
            token = self.auth.authenticate(user_id, credentials)
            
            # Create session
            session_id = str(uuid.uuid4())
            self.sessions.create_session(session_id, user_id, token)
            
            # Log successful authentication
            self.audit.log_event(
                EventType.AUTHENTICATION_SUCCESS,
                user_id, Severity.INFO,
                action="login",
                details={"session_id": session_id}
            )
            
            return session_id
        
        except ValueError as e:
            self.audit.log_event(
                EventType.AUTHENTICATION_FAILURE,
                user_id, Severity.WARNING,
                action="login",
                result="invalid_credentials"
            )
            raise
    
    def handle_request(self, session_id, user_id, resource, action):
        """Handle an API request."""
        # Validate session
        session = self.sessions.get_session(session_id)
        if not session:
            raise Exception("Invalid or expired session")
        
        # Update activity
        self.sessions.update_activity(session_id)
        
        # Check authorization
        permission = Permission(action)
        allowed = self.authz.authorize(user_id, resource, permission)
        
        event_type = EventType.AUTHORIZATION_ALLOWED if allowed else EventType.AUTHORIZATION_DENIED
        severity = Severity.INFO if allowed else Severity.WARNING
        
        self.audit.log_event(
            event_type, user_id, severity,
            resource=resource,
            action=action,
        )
        
        if not allowed:
            raise Exception("Access denied")
        
        return {"status": "success", "data": "resource data"}

# Usage
app = SecureWebApp()
session = app.login("user@example.com", "SecurePass123", "123456")
result = app.handle_request(session, "user@example.com", "/api/users/user@example.com/profile", "read")
print(result)
```

### Use Case 2: Microservice Authentication

```python
from zero_trust import Authenticator, AuthMethod, AuthorizationEngine, Policy, Permission

class MicroserviceAuth:
    """Service-to-service authentication."""
    
    def __init__(self):
        self.auth = Authenticator()
        self.authz = AuthorizationEngine()
        self._setup_service_policies()
    
    def _setup_service_policies(self):
        """Set up service-to-service policies."""
        # Service A can call Service B's read endpoints
        service_a_policy = Policy(
            policy_id="service-a-to-b-read",
            principal="service-a",
            resource="/internal/service-b/api/data/read",
            permissions={Permission.READ},
        )
        self.authz.add_policy(service_a_policy)
        
        # Service B can call Database
        service_b_policy = Policy(
            policy_id="service-b-to-db",
            principal="service-b",
            resource="/internal/database/*",
            permissions={Permission.READ, Permission.WRITE},
        )
        self.authz.add_policy(service_b_policy)
    
    def authenticate_service(self, service_id, service_key):
        """Authenticate a service."""
        credentials = {
            AuthMethod.PASSWORD: service_key,
            AuthMethod.TOTP: "000000",  # Services use dummy TOTP
        }
        return self.auth.authenticate(service_id, credentials)
    
    def authorize_service_call(self, caller, target_resource):
        """Check if service is authorized to call another."""
        return self.authz.authorize(caller, target_resource, Permission.READ)

# Usage
ms_auth = MicroserviceAuth()
service_a_token = ms_auth.authenticate_service("service-a", "service-a-secret-key")
allowed = ms_auth.authorize_service_call("service-a", "/internal/service-b/api/data/read")
print(f"Service A can call Service B: {allowed}")
```

### Use Case 3: Rate Limiting and Brute Force Protection

```python
from zero_trust import RateLimiter, AuthenticationAttemptTracker

class LoginWithBruteForceProtection:
    def __init__(self):
        self.rate_limiter = RateLimiter(max_requests=10, window_size=60)
        self.attempt_tracker = AuthenticationAttemptTracker(
            max_attempts=5, 
            lockout_duration=600  # 10 minutes
        )
    
    def attempt_login(self, user_id, password):
        """Handle login with protection."""
        # Check rate limiting
        if not self.rate_limiter.is_allowed(f"login:{user_id}"):
            return {"success": False, "error": "Too many attempts"}
        
        # Check if user is locked out
        if self.attempt_tracker.is_locked_out(user_id):
            return {"success": False, "error": "Account locked. Try again later."}
        
        # Validate password
        if password == "correct_password":
            self.attempt_tracker.record_success(user_id)
            return {"success": True, "token": "user_token"}
        else:
            locked, remaining = self.attempt_tracker.record_failure(user_id)
            if locked:
                return {"success": False, "error": "Account locked after 5 failed attempts"}
            else:
                return {"success": False, "error": f"Invalid password. {remaining} attempts remaining"}

# Usage
login_handler = LoginWithBruteForceProtection()
print(login_handler.attempt_login("alice", "wrong_password"))
print(login_handler.attempt_login("alice", "correct_password"))
```

---

## 🔌 REST API Usage

### Start the server

```bash
# With FastAPI dev server
python -m uvicorn api.app:app --reload

# Or with gunicorn for production
gunicorn -w 4 -b 0.0.0.0:8000 api.app:app
```

### Example API Calls

```bash
# 1. Authenticate
curl -X POST http://localhost:8000/api/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice@example.com",
    "password": "SecurePass123",
    "totp": "123456"
  }'

# Response: {"token": "abc123...", "session_id": "xyz", "expires_at": 1234567890}

# 2. Create a policy
curl -X POST http://localhost:8000/api/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "alice@example.com",
    "resource": "/api/data/*",
    "permissions": ["read", "write"]
  }'

# 3. Check authorization
curl -X POST http://localhost:8000/api/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "alice@example.com",
    "resource": "/api/data/report1",
    "permission": "read",
    "session_id": "xyz"
  }'

# 4. Get audit events
curl http://localhost:8000/api/v1/audit/events?actor=alice@example.com

# 5. Get audit summary
curl http://localhost:8000/api/v1/audit/summary
```

---

## 🧪 Testing

### Run all tests

```bash
pytest tests/ -v
```

### Run specific test

```bash
pytest tests/test_authentication.py -v
pytest tests/test_integration.py::TestAuthenticationAuthorizationFlow -v
```

### With coverage

```bash
pytest tests/ --cov=zero_trust --cov-report=html
open htmlcov/index.html
```

---

## 📚 Documentation

- **API Documentation:** See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- **Architecture Guide:** See [ARCHITECTURE.md](ARCHITECTURE.md)
- **Deployment Guide:** See [DEPLOYMENT.md](DEPLOYMENT.md)
- **Full README:** See [README.md](README.md)

---

## 🆘 Troubleshooting

### Issue: "UnicodeEncodeError" on Windows
**Solution:** The code uses UTF-8 encoding. Ensure your terminal supports UTF-8 or use Python 3.11+.

### Issue: "ModuleNotFoundError: No module named 'zero_trust'"
**Solution:** Install the package with `pip install -e .` or `pip install zero-trust`

### Issue: TOTP validation fails
**Solution:** Ensure your system clock is synchronized with NTP. TOTP is time-sensitive.

### Issue: "Rate limit exceeded"
**Solution:** Wait for the rate limit window to expire (default 60 seconds) before retrying.

---

## 📞 Next Steps

1. Read the **[Architecture Guide](ARCHITECTURE.md)** for deep dive into Zero Trust
2. Explore the **[API Documentation](API_DOCUMENTATION.md)** for REST endpoints
3. Check **[DEPLOYMENT.md](DEPLOYMENT.md)** for production setup
4. Run the **[example script](example_zero_trust.py)** to see it in action
5. Write **integration tests** for your use case
6. Deploy with Docker or Kubernetes

---

**Happy securing! 🔐**

Questions? Open an issue on [GitHub](https://github.com/jasonnorman66994-dot/skills-introduction-to-github)
