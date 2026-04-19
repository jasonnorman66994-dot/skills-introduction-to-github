"""Rate limiting for API endpoints and authentication attempts."""

import time
from typing import Dict, Tuple
from collections import deque


class RateLimiter:
    """Token bucket rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 100, window_size: int = 60):
        """
        Initialize the rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in the window
            window_size: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_size = window_size
        self.buckets: Dict[str, deque] = {}
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request is allowed for the given identifier.
        
        Args:
            identifier: User ID, IP address, or other identifier
            
        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        now = time.time()
        
        if identifier not in self.buckets:
            self.buckets[identifier] = deque()
        
        bucket = self.buckets[identifier]
        
        # Remove old requests outside the window
        while bucket and bucket[0] < now - self.window_size:
            bucket.popleft()
        
        # Check if limit is exceeded
        if len(bucket) >= self.max_requests:
            return False
        
        # Add current request
        bucket.append(now)
        return True
    
    def get_remaining(self, identifier: str) -> int:
        """
        Get remaining requests for the identifier.
        
        Args:
            identifier: User ID, IP address, or other identifier
            
        Returns:
            Number of remaining requests in the current window
        """
        now = time.time()
        
        if identifier not in self.buckets:
            return self.max_requests
        
        bucket = self.buckets[identifier]
        
        # Remove old requests outside the window
        while bucket and bucket[0] < now - self.window_size:
            bucket.popleft()
        
        return max(0, self.max_requests - len(bucket))
    
    def reset(self, identifier: str) -> None:
        """
        Reset rate limit for an identifier.
        
        Args:
            identifier: User ID, IP address, or other identifier
        """
        if identifier in self.buckets:
            self.buckets[identifier].clear()


class AuthenticationAttemptTracker:
    """Track and limit authentication attempts to prevent brute force attacks."""
    
    def __init__(self, max_attempts: int = 5, lockout_duration: int = 300):
        """
        Initialize the tracker.
        
        Args:
            max_attempts: Maximum failed attempts before lockout
            lockout_duration: Lockout time in seconds
        """
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration
        self.failed_attempts: Dict[str, Tuple[int, float]] = {}  # user_id -> (count, timestamp)
        self.locked_out_until: Dict[str, float] = {}  # user_id -> timestamp
    
    def record_failure(self, user_id: str) -> Tuple[bool, int]:
        """
        Record a failed authentication attempt.
        
        Args:
            user_id: The user attempting authentication
            
        Returns:
            (is_locked_out, remaining_attempts)
        """
        now = time.time()
        
        # Check if user is locked out
        if user_id in self.locked_out_until:
            if now < self.locked_out_until[user_id]:
                return True, 0
            else:
                # Lockout expired
                del self.locked_out_until[user_id]
        
        # Check if previous attempts expired
        if user_id in self.failed_attempts:
            count, timestamp = self.failed_attempts[user_id]
            if now - timestamp > self.lockout_duration:
                # Reset attempts if window expired
                self.failed_attempts[user_id] = (1, now)
                return False, self.max_attempts - 1
        
        # Increment failure count
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = (0, now)
        
        count, _ = self.failed_attempts[user_id]
        count += 1
        self.failed_attempts[user_id] = (count, now)
        
        # Check if should lock out
        if count >= self.max_attempts:
            self.locked_out_until[user_id] = now + self.lockout_duration
            return True, 0
        
        return False, self.max_attempts - count
    
    def record_success(self, user_id: str) -> None:
        """
        Record a successful authentication attempt (reset failures).
        
        Args:
            user_id: The user who successfully authenticated
        """
        if user_id in self.failed_attempts:
            del self.failed_attempts[user_id]
        
        if user_id in self.locked_out_until:
            del self.locked_out_until[user_id]
    
    def is_locked_out(self, user_id: str) -> bool:
        """
        Check if a user is locked out from authentication.
        
        Args:
            user_id: The user to check
            
        Returns:
            True if locked out, False otherwise
        """
        if user_id not in self.locked_out_until:
            return False
        
        if time.time() < self.locked_out_until[user_id]:
            return True
        
        # Lockout expired
        del self.locked_out_until[user_id]
        return False
