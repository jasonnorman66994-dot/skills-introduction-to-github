"""Authorization module implementing least privilege access control."""

from enum import Enum
from typing import Set, Dict, List
from dataclasses import dataclass


class Permission(Enum):
    """Resource permissions."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


@dataclass
class Policy:
    """Access control policy definition."""
    policy_id: str
    principal: str
    resource: str
    permissions: Set[Permission]
    conditions: Dict[str, any] = None
    
    def __init__(self, policy_id: str, principal: str, resource: str, 
                 permissions: Set[Permission], conditions: Dict[str, any] = None):
        self.policy_id = policy_id
        self.principal = principal
        self.resource = resource
        self.permissions = permissions
        self.conditions = conditions or {}


class AuthorizationEngine:
    """Implements least privilege authorization with policy evaluation."""
    
    def __init__(self):
        self.policies: Dict[str, Policy] = {}
        self.policy_index: Dict[str, List[str]] = {}  # principal -> policy_ids
    
    def add_policy(self, policy: Policy) -> None:
        """
        Add an access control policy.
        
        Args:
            policy: The policy to add
        """
        self.policies[policy.policy_id] = policy
        
        # Index by principal for faster lookup
        if policy.principal not in self.policy_index:
            self.policy_index[policy.principal] = []
        self.policy_index[policy.principal].append(policy.policy_id)
    
    def authorize(self, principal: str, resource: str, permission: Permission) -> bool:
        """
        Check if a principal can perform an action on a resource.
        
        Args:
            principal: The user/service principal
            resource: The resource being accessed
            permission: The permission being requested
            
        Returns:
            True if authorized, False otherwise
        """
        if principal not in self.policy_index:
            return False
        
        policy_ids = self.policy_index[principal]
        
        for policy_id in policy_ids:
            policy = self.policies[policy_id]
            
            # Check if resource matches (support wildcards)
            if self._resource_matches(policy.resource, resource):
                # Check if permission is granted
                if permission in policy.permissions:
                    # Check conditions if any
                    if self._conditions_satisfied(policy.conditions):
                        return True
        
        return False
    
    def _resource_matches(self, policy_resource: str, requested_resource: str) -> bool:
        """Check if requested resource matches policy resource pattern."""
        if policy_resource == requested_resource:
            return True
        
        # Handle wildcard patterns (e.g., /api/users/*)
        if policy_resource.endswith("/*"):
            prefix = policy_resource[:-2]
            return requested_resource.startswith(prefix)
        
        return False
    
    def _conditions_satisfied(self, conditions: Dict[str, any]) -> bool:
        """Evaluate policy conditions."""
        # Simplified - in production implement full condition evaluation
        if not conditions:
            return True
        return True
    
    def revoke_policy(self, policy_id: str) -> bool:
        """
        Revoke an access control policy.
        
        Args:
            policy_id: The policy to revoke
            
        Returns:
            True if revoked, False if not found
        """
        if policy_id not in self.policies:
            return False
        
        policy = self.policies[policy_id]
        self.policies.pop(policy_id)
        
        # Remove from index
        if policy.principal in self.policy_index:
            self.policy_index[policy.principal].remove(policy_id)
            if not self.policy_index[policy.principal]:
                del self.policy_index[policy.principal]
        
        return True
