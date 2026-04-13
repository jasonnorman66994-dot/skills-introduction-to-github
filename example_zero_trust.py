#!/usr/bin/env python3
"""
Example: Zero Trust Security Implementation

Demonstrates multi-factor authentication and least privilege authorization.
"""

from zero_trust import Authenticator, AuthorizationEngine, Policy, Permission
from zero_trust.authentication import AuthMethod


def main():
    print("=" * 60)
    print("Zero Trust Security Example")
    print("=" * 60)
    
    # Step 1: Authenticate with MFA
    print("\n[1] Authenticating user with MFA...")
    authenticator = Authenticator()
    
    try:
        credentials = {
            AuthMethod.PASSWORD: "secure_password_123",
            AuthMethod.TOTP: "123456",
        }
        token = authenticator.authenticate("user123", credentials)
        print(f"✓ Authentication successful")
        print(f"  Token: {token[:16]}...")
        print(f"  Token valid: {authenticator.verify_token(token)}")
    except ValueError as e:
        print(f"✗ Authentication failed: {e}")
        return
    
    # Step 2: Set up authorization with least privilege
    print("\n[2] Setting up least privilege authorization policies...")
    authz = AuthorizationEngine()
    
    # Policy 1: User can read user list
    policy_read = Policy(
        policy_id="policy-001",
        principal="user123",
        resource="/api/users/*",
        permissions={Permission.READ},
    )
    authz.add_policy(policy_read)
    print(f"✓ Added policy: {policy_read.policy_id}")
    print(f"  Principal: {policy_read.principal}")
    print(f"  Resource: {policy_read.resource}")
    print(f"  Permissions: {[p.value for p in policy_read.permissions]}")
    
    # Policy 2: User can write to their own profile
    policy_write = Policy(
        policy_id="policy-002",
        principal="user123",
        resource="/api/users/user123/profile",
        permissions={Permission.READ, Permission.WRITE},
    )
    authz.add_policy(policy_write)
    print(f"\n✓ Added policy: {policy_write.policy_id}")
    print(f"  Principal: {policy_write.principal}")
    print(f"  Resource: {policy_write.resource}")
    print(f"  Permissions: {[p.value for p in policy_write.permissions]}")
    
    # Step 3: Test authorization
    print("\n[3] Testing authorization checks...")
    
    test_cases = [
        ("user123", "/api/users/list", Permission.READ, "Read users list"),
        ("user123", "/api/users/user123/profile", Permission.READ, "Read own profile"),
        ("user123", "/api/users/user123/profile", Permission.WRITE, "Update own profile"),
        ("user123", "/api/users/user456/profile", Permission.WRITE, "Update other user (denied)"),
        ("user123", "/api/admin/settings", Permission.READ, "Access admin (denied)"),
    ]
    
    for principal, resource, permission, description in test_cases:
        allowed = authz.authorize(principal, resource, permission)
        status = "✓ ALLOWED" if allowed else "✗ DENIED"
        print(f"\n  {status}: {description}")
        print(f"    Principal: {principal}")
        print(f"    Resource: {resource}")
        print(f"    Permission: {permission.value}")
    
    # Step 4: Policy revocation
    print("\n[4] Revoking policy...")
    revoked = authz.revoke_policy("policy-002")
    if revoked:
        print(f"✓ Policy revoked: policy-002")
        
        # Re-test after revocation
        allowed = authz.authorize("user123", "/api/users/user123/profile", Permission.WRITE)
        print(f"  After revocation - Access to /api/users/user123/profile: {'✗ DENIED' if not allowed else '✓ ALLOWED'}")
    
    print("\n" + "=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
