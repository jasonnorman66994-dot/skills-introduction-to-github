"""Pytest configuration and fixtures for zero trust tests."""

import pytest
from zero_trust import Authenticator, AuthorizationEngine, Policy, Permission
from zero_trust.authentication import AuthMethod


@pytest.fixture
def authenticator():
    """Provide a fresh Authenticator instance for each test."""
    return Authenticator()


@pytest.fixture
def authz_engine():
    """Provide a fresh AuthorizationEngine instance for each test."""
    return AuthorizationEngine()


@pytest.fixture
def valid_credentials():
    """Provide valid MFA credentials for testing."""
    return {
        AuthMethod.PASSWORD: "secure_password_123",
        AuthMethod.TOTP: "123456",
    }


@pytest.fixture
def authenticated_token(authenticator, valid_credentials):
    """Generate an authenticated token for testing."""
    return authenticator.authenticate("testuser", valid_credentials)


@pytest.fixture
def sample_policies():
    """Provide sample policies for testing."""
    return [
        Policy(
            policy_id="read-users",
            principal="user123",
            resource="/api/users/*",
            permissions={Permission.READ},
        ),
        Policy(
            policy_id="manage-profile",
            principal="user123",
            resource="/api/users/user123/profile",
            permissions={Permission.READ, Permission.WRITE},
        ),
        Policy(
            policy_id="admin-access",
            principal="admin001",
            resource="/api/admin/*",
            permissions={Permission.READ, Permission.WRITE, Permission.DELETE},
        ),
    ]
