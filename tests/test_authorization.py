"""Tests for the authorization module."""

import pytest
from zero_trust.authorization import AuthorizationEngine, Policy, Permission


class TestAuthorizationEngine:
    """Test suite for AuthorizationEngine class."""
    
    def test_add_policy(self, authz_engine, sample_policies):
        """Test adding policies to the authorization engine."""
        policy = sample_policies[0]
        authz_engine.add_policy(policy)
        
        assert policy.policy_id in authz_engine.policies
        assert authz_engine.policies[policy.policy_id] == policy
    
    def test_add_multiple_policies_same_principal(self, authz_engine, sample_policies):
        """Test adding multiple policies for the same principal."""
        policy1 = sample_policies[0]
        policy2 = sample_policies[1]
        
        authz_engine.add_policy(policy1)
        authz_engine.add_policy(policy2)
        
        assert len(authz_engine.policy_index["user123"]) == 2
    
    def test_authorize_exact_resource_match(self, authz_engine, sample_policies):
        """Test authorization with exact resource path."""
        policy = sample_policies[1]  # /api/users/user123/profile
        authz_engine.add_policy(policy)
        
        allowed = authz_engine.authorize("user123", "/api/users/user123/profile", Permission.READ)
        assert allowed is True
    
    def test_authorize_wildcard_resource_match(self, authz_engine, sample_policies):
        """Test authorization with wildcard resource pattern."""
        policy = sample_policies[0]  # /api/users/*
        authz_engine.add_policy(policy)
        
        # Should match /api/users/list
        allowed = authz_engine.authorize("user123", "/api/users/list", Permission.READ)
        assert allowed is True
        
        # Should match /api/users/123
        allowed = authz_engine.authorize("user123", "/api/users/123", Permission.READ)
        assert allowed is True
    
    def test_authorize_wildcard_mismatch(self, authz_engine, sample_policies):
        """Test authorization fails for resources outside wildcard pattern."""
        policy = sample_policies[0]  # /api/users/*
        authz_engine.add_policy(policy)
        
        # Should not match /api/admin/settings
        allowed = authz_engine.authorize("user123", "/api/admin/settings", Permission.READ)
        assert allowed is False
    
    def test_authorize_permission_denied(self, authz_engine, sample_policies):
        """Test authorization fails when permission is not granted."""
        policy = sample_policies[0]  # Only READ permission
        authz_engine.add_policy(policy)
        
        # WRITE is not granted
        allowed = authz_engine.authorize("user123", "/api/users/list", Permission.WRITE)
        assert allowed is False
    
    def test_authorize_principal_not_found(self, authz_engine):
        """Test authorization fails for unknown principal."""
        allowed = authz_engine.authorize("unknown_user", "/api/users/list", Permission.READ)
        assert allowed is False
    
    def test_authorize_no_matching_policy(self, authz_engine, sample_policies):
        """Test authorization fails when no policy matches."""
        policy = sample_policies[0]
        authz_engine.add_policy(policy)
        
        allowed = authz_engine.authorize("user456", "/api/users/list", Permission.READ)
        assert allowed is False
    
    def test_revoke_policy(self, authz_engine, sample_policies):
        """Test policy revocation."""
        policy = sample_policies[0]
        authz_engine.add_policy(policy)
        
        # Verify policy exists
        assert authz_engine.authorize("user123", "/api/users/list", Permission.READ) is True
        
        # Revoke policy
        revoked = authz_engine.revoke_policy(policy.policy_id)
        assert revoked is True
        
        # Verify policy is removed
        assert policy.policy_id not in authz_engine.policies
        assert authz_engine.authorize("user123", "/api/users/list", Permission.READ) is False
    
    def test_revoke_nonexistent_policy(self, authz_engine):
        """Test revoking a policy that doesn't exist."""
        revoked = authz_engine.revoke_policy("nonexistent")
        assert revoked is False
    
    def test_least_privilege_admin_vs_user(self, authz_engine, sample_policies):
        """Test that least privilege prevents user from admin access."""
        user_policy = sample_policies[0]
        admin_policy = sample_policies[2]
        
        authz_engine.add_policy(user_policy)
        authz_engine.add_policy(admin_policy)
        
        # User should not have admin access
        allowed_user = authz_engine.authorize("user123", "/api/admin/settings", Permission.DELETE)
        assert allowed_user is False
        
        # Admin should have admin access
        allowed_admin = authz_engine.authorize("admin001", "/api/admin/settings", Permission.DELETE)
        assert allowed_admin is True
    
    def test_multiple_permissions_granted(self, authz_engine):
        """Test policy with multiple permissions."""
        policy = Policy(
            policy_id="multi-perm",
            principal="user123",
            resource="/api/data",
            permissions={Permission.READ, Permission.WRITE},
        )
        authz_engine.add_policy(policy)
        
        assert authz_engine.authorize("user123", "/api/data", Permission.READ) is True
        assert authz_engine.authorize("user123", "/api/data", Permission.WRITE) is True
        assert authz_engine.authorize("user123", "/api/data", Permission.DELETE) is False
