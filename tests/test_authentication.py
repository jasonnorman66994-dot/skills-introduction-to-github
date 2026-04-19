"""Tests for the authentication module."""

import pytest
from zero_trust.authentication import Authenticator, AuthMethod


class TestAuthenticator:
    """Test suite for Authenticator class."""
    
    def test_authenticate_success(self, authenticator, valid_credentials):
        """Test successful authentication with valid MFA credentials."""
        token = authenticator.authenticate("user123", valid_credentials)
        assert token is not None
        assert len(token) == 64  # SHA256 hex digest
    
    def test_authenticate_missing_password(self, authenticator, valid_credentials):
        """Test authentication fails when password is missing."""
        creds = {AuthMethod.TOTP: "123456"}
        with pytest.raises(ValueError, match="Missing required authentication methods"):
            authenticator.authenticate("user123", creds)
    
    def test_authenticate_missing_totp(self, authenticator, valid_credentials):
        """Test authentication fails when TOTP is missing."""
        creds = {AuthMethod.PASSWORD: "secure_password_123"}
        with pytest.raises(ValueError, match="Missing required authentication methods"):
            authenticator.authenticate("user123", creds)
    
    def test_authenticate_invalid_password(self, authenticator):
        """Test authentication fails with short password."""
        creds = {
            AuthMethod.PASSWORD: "short",
            AuthMethod.TOTP: "123456",
        }
        with pytest.raises(ValueError, match="Invalid password"):
            authenticator.authenticate("user123", creds)
    
    def test_authenticate_invalid_totp(self, authenticator):
        """Test authentication fails with invalid TOTP format."""
        creds = {
            AuthMethod.PASSWORD: "secure_password_123",
            AuthMethod.TOTP: "not_a_number",
        }
        with pytest.raises(ValueError, match="Invalid TOTP token"):
            authenticator.authenticate("user123", creds)
    
    def test_authenticate_invalid_totp_length(self, authenticator):
        """Test authentication fails with wrong TOTP length."""
        creds = {
            AuthMethod.PASSWORD: "secure_password_123",
            AuthMethod.TOTP: "12345",  # Only 5 digits
        }
        with pytest.raises(ValueError, match="Invalid TOTP token"):
            authenticator.authenticate("user123", creds)
    
    def test_token_uniqueness(self, authenticator, valid_credentials):
        """Test that each authentication generates a unique token."""
        token1 = authenticator.authenticate("user123", valid_credentials)
        token2 = authenticator.authenticate("user123", valid_credentials)
        assert token1 != token2
    
    def test_verify_token_valid(self, authenticator, authenticated_token):
        """Test token verification for valid token."""
        assert authenticator.verify_token(authenticated_token) is True
    
    def test_verify_token_invalid(self, authenticator):
        """Test token verification for invalid token."""
        invalid_token = "invalid_token_12345"
        assert authenticator.verify_token(invalid_token) is False
    
    def test_multiple_users(self, authenticator, valid_credentials):
        """Test authentication for multiple users."""
        token1 = authenticator.authenticate("user1", valid_credentials)
        token2 = authenticator.authenticate("user2", valid_credentials)
        
        assert token1 != token2
        assert authenticator.verify_token(token1)
        assert authenticator.verify_token(token2)
