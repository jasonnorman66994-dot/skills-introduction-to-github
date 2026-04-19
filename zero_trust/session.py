"""Session management for authenticated users."""

import time
from typing import Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Session:
    """Represents an authenticated user session."""
    session_id: str
    user_id: str
    token: str
    created_at: float
    last_activity: float
    expires_at: float
    is_active: bool = True
    metadata: Dict[str, any] = field(default_factory=dict)


class SessionManager:
    """Manages user sessions with expiration and activity tracking."""
    
    def __init__(self, session_timeout: int = 3600):
        """
        Initialize the SessionManager.
        
        Args:
            session_timeout: Session expiration time in seconds (default: 1 hour)
        """
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = session_timeout
    
    def create_session(self, session_id: str, user_id: str, token: str, 
                      metadata: Dict[str, any] = None) -> Session:
        """
        Create a new session.
        
        Args:
            session_id: Unique session identifier
            user_id: The user ID for this session
            token: The authentication token
            metadata: Optional session metadata
            
        Returns:
            The created Session object
        """
        now = time.time()
        session = Session(
            session_id=session_id,
            user_id=user_id,
            token=token,
            created_at=now,
            last_activity=now,
            expires_at=now + self.session_timeout,
            metadata=metadata or {},
        )
        self.sessions[session_id] = session
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve a session by ID.
        
        Args:
            session_id: The session identifier
            
        Returns:
            The Session if found and active, None otherwise
        """
        session = self.sessions.get(session_id)
        if session and self.is_session_valid(session):
            return session
        return None
    
    def update_activity(self, session_id: str) -> bool:
        """
        Update the last activity timestamp for a session.
        
        Args:
            session_id: The session identifier
            
        Returns:
            True if updated, False if session not found or expired
        """
        session = self.sessions.get(session_id)
        if session and self.is_session_valid(session):
            session.last_activity = time.time()
            return True
        return False
    
    def is_session_valid(self, session: Session) -> bool:
        """
        Check if a session is still valid.
        
        Args:
            session: The session to validate
            
        Returns:
            True if session is active and not expired, False otherwise
        """
        if not session.is_active:
            return False
        
        if time.time() > session.expires_at:
            session.is_active = False
            return False
        
        return True
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate a session.
        
        Args:
            session_id: The session identifier
            
        Returns:
            True if invalidated, False if not found
        """
        session = self.sessions.get(session_id)
        if session:
            session.is_active = False
            return True
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions from memory.
        
        Returns:
            Number of sessions cleaned up
        """
        now = time.time()
        expired_ids = [
            sid for sid, session in self.sessions.items()
            if session.expires_at < now
        ]
        
        for sid in expired_ids:
            del self.sessions[sid]
        
        return len(expired_ids)
    
    def get_user_sessions(self, user_id: str) -> list[Session]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: The user identifier
            
        Returns:
            List of active sessions for the user
        """
        return [
            session for session in self.sessions.values()
            if session.user_id == user_id and self.is_session_valid(session)
        ]
