"""Caching layer for authorization decisions and policies."""

import time
from typing import Dict, Optional, Tuple, Set
from functools import wraps


class CacheEntry:
    """Represents a cached authorization decision."""
    
    def __init__(self, result: bool, ttl: int = 300):
        self.result = result
        self.created_at = time.time()
        self.ttl = ttl
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return time.time() - self.created_at > self.ttl
    
    def __repr__(self) -> str:
        return f"CacheEntry(result={self.result}, age={time.time() - self.created_at:.1f}s)"


class AuthorizationCache:
    """Cache for authorization decisions to improve performance."""
    
    def __init__(self, ttl: int = 300, max_size: int = 10000):
        """
        Initialize the cache.
        
        Args:
            ttl: Time-to-live for cache entries in seconds
            max_size: Maximum number of cache entries
        """
        self.ttl = ttl
        self.max_size = max_size
        self.cache: Dict[str, CacheEntry] = {}
        self.hits = 0
        self.misses = 0
    
    def _make_key(self, principal: str, resource: str, permission: str) -> str:
        """Create a cache key from authorization parameters."""
        return f"{principal}:{resource}:{permission}"
    
    def get(self, principal: str, resource: str, permission: str) -> Optional[bool]:
        """
        Retrieve a cached authorization decision.
        
        Args:
            principal: The user principal
            resource: The resource being accessed
            permission: The permission being requested
            
        Returns:
            The cached result or None if not cached or expired
        """
        key = self._make_key(principal, resource, permission)
        
        if key in self.cache:
            entry = self.cache[key]
            if not entry.is_expired():
                self.hits += 1
                return entry.result
            else:
                del self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, principal: str, resource: str, permission: str, result: bool) -> None:
        """
        Cache an authorization decision.
        
        Args:
            principal: The user principal
            resource: The resource being accessed
            permission: The permission being requested
            result: The authorization result
        """
        # Evict oldest entry if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.cache.keys(), 
                           key=lambda k: self.cache[k].created_at)
            del self.cache[oldest_key]
        
        key = self._make_key(principal, resource, permission)
        self.cache[key] = CacheEntry(result, self.ttl)
    
    def invalidate(self, principal: Optional[str] = None) -> int:
        """
        Invalidate cache entries for a principal or all entries.
        
        Args:
            principal: Principal to invalidate, or None for all
            
        Returns:
            Number of cache entries invalidated
        """
        if principal is None:
            count = len(self.cache)
            self.cache.clear()
            return count
        
        # Remove entries for specific principal
        prefix = f"{principal}:"
        keys_to_remove = [k for k in self.cache.keys() if k.startswith(prefix)]
        
        for key in keys_to_remove:
            del self.cache[key]
        
        return len(keys_to_remove)
    
    def get_stats(self) -> Dict[str, any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "total_requests": total,
            "hit_rate": f"{hit_rate:.1f}%",
            "ttl": self.ttl,
        }
    
    def clear(self) -> None:
        """Clear all cache entries and reset statistics."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0


class PolicyCache:
    """Cache for policies to improve authorization performance."""
    
    def __init__(self, ttl: int = 600):
        """
        Initialize policy cache.
        
        Args:
            ttl: Time-to-live for policy cache entries
        """
        self.ttl = ttl
        self.principals: Dict[str, Tuple[float, Set[str]]] = {}  # principal -> (timestamp, policy_ids)
    
    def cache_principal_policies(self, principal: str, policy_ids: Set[str]) -> None:
        """
        Cache the policies for a principal.
        
        Args:
            principal: The user principal
            policy_ids: Set of policy IDs for the principal
        """
        self.principals[principal] = (time.time(), policy_ids)
    
    def get_principal_policies(self, principal: str) -> Optional[Set[str]]:
        """
        Retrieve cached policies for a principal.
        
        Args:
            principal: The user principal
            
        Returns:
            Set of policy IDs or None if expired
        """
        if principal in self.principals:
            timestamp, policy_ids = self.principals[principal]
            if time.time() - timestamp < self.ttl:
                return policy_ids
            else:
                del self.principals[principal]
        
        return None
    
    def invalidate_principal(self, principal: str) -> bool:
        """
        Invalidate cache for a specific principal.
        
        Args:
            principal: The principal to invalidate
            
        Returns:
            True if invalidated, False if not cached
        """
        if principal in self.principals:
            del self.principals[principal]
            return True
        return False
    
    def invalidate_all(self) -> int:
        """Invalidate all policy cache entries."""
        count = len(self.principals)
        self.principals.clear()
        return count


def cached(cache: AuthorizationCache):
    """
    Decorator to cache authorization decisions.
    
    Usage:
        @cached(auth_cache)
        def authorize(principal, resource, permission):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(self, principal, resource, permission):
            # Check cache first
            cached_result = cache.get(principal, resource, permission)
            if cached_result is not None:
                return cached_result
            
            # Call the actual function
            result = func(self, principal, resource, permission)
            
            # Cache the result
            cache.set(principal, resource, permission, result)
            
            return result
        
        return wrapper
    
    return decorator
