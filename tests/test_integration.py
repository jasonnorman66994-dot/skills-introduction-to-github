"""Integration tests for the zero trust security system."""

import pytest
import uuid
from zero_trust import (
    Authenticator,
    AuthMethod,
    AuthorizationEngine,
    Policy,
    Permission,
    SessionManager,
    AuditLogger,
    EventType,
    Severity,
    RateLimiter,
    AuthenticationAttemptTracker,
    AuthorizationCache,
)


class TestAuthenticationAuthorizationFlow:
    """Test complete authentication to authorization flow."""
    
    def test_full_auth_flow(self, authenticator, authz_engine, valid_credentials):
        """Test complete flow: authenticate user then authorize action."""
        # Step 1: Authenticate
        token = authenticator.authenticate("user123", valid_credentials)
        assert token is not None
        
        # Step 2: Create policy
        policy = Policy(
            policy_id="policy-001",
            principal="user123",
            resource="/api/data",
            permissions={Permission.READ},
        )
        authz_engine.add_policy(policy)
        
        # Step 3: Check authorization
        allowed = authz_engine.authorize("user123", "/api/data", Permission.READ)
        assert allowed is True
        
        # Step 4: Verify unauthorized access is denied
        denied = authz_engine.authorize("user123", "/api/data", Permission.WRITE)
        assert denied is False


class TestSessionManagementFlow:
    """Test session lifecycle with authorization."""
    
    def test_session_lifecycle_with_auth(self, authenticator, authz_engine, valid_credentials):
        """Test session creation, usage, and invalidation."""
        # Authenticate user
        token = authenticator.authenticate("user123", valid_credentials)
        
        # Create session
        session_mgr = SessionManager()
        session_id = str(uuid.uuid4())
        session = session_mgr.create_session(session_id, "user123", token)
        assert session.is_active
        
        # Create authorization policy
        policy = Policy(
            policy_id="api-access",
            principal="user123",
            resource="/api/*",
            permissions={Permission.READ, Permission.WRITE},
        )
        authz_engine.add_policy(policy)
        
        # Verify session is valid and user has access
        assert session_mgr.get_session(session_id) is not None
        assert authz_engine.authorize("user123", "/api/users", Permission.READ)
        
        # Update activity
        session_mgr.update_activity(session_id)
        assert session_mgr.get_session(session_id) is not None
        
        # Invalidate session
        session_mgr.invalidate_session(session_id)
        assert session_mgr.get_session(session_id) is None


class TestAuditLoggingFlow:
    """Test audit logging through authentication and authorization."""
    
    def test_full_audit_trail(self, authenticator, authz_engine, valid_credentials):
        """Test that all operations are properly logged."""
        audit = AuditLogger()
        
        # Log authentication
        try:
            token = authenticator.authenticate("user123", valid_credentials)
            audit.log_event(
                event_type=EventType.AUTHENTICATION_SUCCESS,
                actor="user123",
                severity=Severity.INFO,
                action="login",
            )
        except ValueError:
            audit.log_event(
                event_type=EventType.AUTHENTICATION_FAILURE,
                actor="user123",
                severity=Severity.WARNING,
                action="login",
            )
        
        # Add policy
        policy = Policy(
            policy_id="test-policy",
            principal="user123",
            resource="/api/test",
            permissions={Permission.READ},
        )
        authz_engine.add_policy(policy)
        audit.log_event(
            event_type=EventType.POLICY_ADDED,
            actor="admin",
            severity=Severity.INFO,
            action="add_policy",
        )
        
        # Check authorization
        allowed = authz_engine.authorize("user123", "/api/test", Permission.READ)
        audit.log_event(
            event_type=EventType.AUTHORIZATION_ALLOWED if allowed else EventType.AUTHORIZATION_DENIED,
            actor="user123",
            severity=Severity.INFO,
            action="access_resource",
        )
        
        # Verify audit trail
        events = audit.get_events()
        assert len(events) >= 3
        assert any(e.event_type == EventType.AUTHENTICATION_SUCCESS for e in events)
        assert any(e.event_type == EventType.POLICY_ADDED for e in events)
        assert any(e.event_type == EventType.AUTHORIZATION_ALLOWED for e in events)


class TestRateLimitingFlow:
    """Test rate limiting with authentication attempts."""
    
    def test_brute_force_protection(self):
        """Test authentication rate limiting and brute force protection."""
        limiter = RateLimiter(max_requests=10, window_size=60)
        tracker = AuthenticationAttemptTracker(max_attempts=3, lockout_duration=60)
        
        # Simulate multiple failed login attempts
        for i in range(3):
            user_locked, remaining = tracker.record_failure("user123")
            assert not user_locked
            assert remaining == 3 - i - 1
        
        # Next attempt should lock out the user
        user_locked, remaining = tracker.record_failure("user123")
        assert user_locked
        assert remaining == 0
        
        # Check lockout status
        assert tracker.is_locked_out("user123")
    
    def test_rate_limit_recovery(self):
        """Test that successful authentication resets failure count."""
        tracker = AuthenticationAttemptTracker(max_attempts=3, lockout_duration=60)
        
        # Record some failures
        tracker.record_failure("user456")
        tracker.record_failure("user456")
        
        # Record success (resets failures)
        tracker.record_success("user456")
        
        # Should be able to attempt again
        user_locked, remaining = tracker.record_failure("user456")
        assert not user_locked


class TestAuthorizationCaching:
    """Test authorization caching for performance."""
    
    def test_cache_hit_miss(self, authz_engine):
        """Test cache hit and miss tracking."""
        cache = AuthorizationCache(ttl=300)
        
        # Add policy
        policy = Policy(
            policy_id="cached-policy",
            principal="user789",
            resource="/api/cached",
            permissions={Permission.READ},
        )
        authz_engine.add_policy(policy)
        
        # First call is a cache miss
        result1 = cache.get("user789", "/api/cached", "read")
        assert result1 is None
        assert cache.misses == 1
        
        # Set cache
        cache.set("user789", "/api/cached", "read", True)
        
        # Second call is a cache hit
        result2 = cache.get("user789", "/api/cached", "read")
        assert result2 is True
        assert cache.hits == 1
        
        # Check statistics
        stats = cache.get_stats()
        assert stats["hit_rate"] == "50.0%"
        assert stats["size"] == 1
    
    def test_cache_invalidation(self):
        """Test cache invalidation for principal."""
        cache = AuthorizationCache()
        
        # Cache multiple entries for the same principal
        cache.set("user_a", "/resource1", "read", True)
        cache.set("user_a", "/resource2", "write", True)
        cache.set("user_b", "/resource1", "read", False)
        
        assert cache.get("user_a", "/resource1", "read") is True
        assert cache.get("user_b", "/resource1", "read") is False
        
        # Invalidate user_a
        invalidated = cache.invalidate("user_a")
        assert invalidated == 2
        
        # user_a entries should be cleared
        assert cache.get("user_a", "/resource1", "read") is None
        assert cache.get("user_a", "/resource2", "write") is None
        
        # user_b entry should still be cached
        assert cache.get("user_b", "/resource1", "read") is False


class TestMultiComponentIntegration:
    """Test interaction between multiple components."""
    
    def test_session_auth_audit_integration(self):
        """Test session management with authentication and audit logging."""
        authenticator = Authenticator()
        session_mgr = SessionManager()
        audit = AuditLogger()
        
        # Authenticate
        credentials = {
            AuthMethod.PASSWORD: "secure_password_123",
            AuthMethod.TOTP: "123456",
        }
        token = authenticator.authenticate("integrated_user", credentials)
        
        # Create session and audit
        session_id = str(uuid.uuid4())
        session = session_mgr.create_session(session_id, "integrated_user", token)
        audit.log_event(
            event_type=EventType.SESSION_CREATED,
            actor="integrated_user",
            severity=Severity.INFO,
            details={"session_id": session_id},
        )
        
        # Verify all components
        assert token is not None
        assert session.is_active
        events = audit.get_events(actor="integrated_user")
        assert len(events) == 1
        assert events[0].event_type == EventType.SESSION_CREATED
    
    def test_complete_system_flow(self):
        """Test complete system: auth -> session -> policy -> audit."""
        # Initialize all components
        authenticator = Authenticator()
        authz_engine = AuthorizationEngine()
        session_mgr = SessionManager()
        audit = AuditLogger()
        cache = AuthorizationCache()
        
        # Authenticate user
        credentials = {
            AuthMethod.PASSWORD: "strong_password_2024",
            AuthMethod.TOTP: "654321",
        }
        token = authenticator.authenticate("complete_user", credentials)
        audit.log_event(EventType.AUTHENTICATION_SUCCESS, "complete_user", Severity.INFO)
        
        # Create session
        session_id = str(uuid.uuid4())
        session = session_mgr.create_session(session_id, "complete_user", token)
        
        # Add policies
        for resource, perms in [
            ("/api/users/*", {Permission.READ}),
            ("/api/profile", {Permission.READ, Permission.WRITE}),
        ]:
            policy = Policy(
                policy_id=f"policy-{uuid.uuid4().hex[:4]}",
                principal="complete_user",
                resource=resource,
                permissions=perms,
            )
            authz_engine.add_policy(policy)
        
        # Check authorizations (with caching)
        test_cases = [
            ("/api/users/list", Permission.READ, True),
            ("/api/profile", Permission.WRITE, True),
            ("/api/admin", Permission.READ, False),
        ]
        
        for resource, perm, expected in test_cases:
            cached_result = cache.get("complete_user", resource, perm.value)
            if cached_result is None:
                result = authz_engine.authorize("complete_user", resource, perm)
                cache.set("complete_user", resource, perm.value, result)
            else:
                result = cached_result
            
            assert result == expected
            audit.log_event(
                EventType.AUTHORIZATION_ALLOWED if result else EventType.AUTHORIZATION_DENIED,
                "complete_user",
                Severity.INFO,
            )
        
        # Verify complete audit trail
        audit_summary = audit.get_event_summary()
        assert audit_summary["total_events"] >= 4
