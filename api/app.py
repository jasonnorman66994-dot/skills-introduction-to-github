"""FastAPI application for Zero Trust Security API."""

from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Set
import uuid
import time

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
)

# FastAPI app
app = FastAPI(
    title="Zero Trust Security API",
    description="Multi-factor authentication and least privilege authorization API",
    version="0.1.0",
)

# Initialize core components
authenticator = Authenticator()
authz_engine = AuthorizationEngine()
session_manager = SessionManager(session_timeout=3600)
audit_logger = AuditLogger()


# ============ Pydantic Models ============

class AuthenticateRequest(BaseModel):
    """Request model for authentication."""
    user_id: str = Field(..., description="User identifier")
    password: str = Field(..., description="User password", min_length=8)
    totp: str = Field(..., description="6-digit TOTP token", regex="^[0-9]{6}$")


class AuthenticateResponse(BaseModel):
    """Response model for successful authentication."""
    token: str = Field(..., description="Authentication token")
    session_id: str = Field(..., description="Session identifier")
    expires_at: float = Field(..., description="Session expiration timestamp")


class PolicyRequest(BaseModel):
    """Request model for creating policies."""
    principal: str = Field(..., description="User or principal ID")
    resource: str = Field(..., description="Resource path (supports wildcards)")
    permissions: Set[str] = Field(..., description="Set of permissions", example=["read", "write"])


class AuthorizeRequest(BaseModel):
    """Request model for authorization checks."""
    principal: str = Field(..., description="User or principal ID")
    resource: str = Field(..., description="Resource path")
    permission: str = Field(..., description="Permission to check")
    session_id: Optional[str] = Field(None, description="Session ID for activity tracking")


class AuthorizeResponse(BaseModel):
    """Response model for authorization checks."""
    allowed: bool = Field(..., description="Authorization result")
    reason: Optional[str] = Field(None, description="Reason for decision")


class EventSummary(BaseModel):
    """Response model for audit event summary."""
    total_events: int
    event_types: Dict[str, int]
    severity_distribution: Dict[str, int]
    actors: Dict[str, int]


# ============ Health Check ============

@app.get("/health", tags=["Health"])
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "healthy", "service": "Zero Trust Security API"}


# ============ Authentication Endpoints ============

@app.post("/api/v1/authenticate", response_model=AuthenticateResponse, tags=["Authentication"])
async def authenticate(request: AuthenticateRequest) -> AuthenticateResponse:
    """
    Authenticate a user with multi-factor authentication.
    
    Requires both password and TOTP (Time-based One-Time Password).
    """
    try:
        credentials = {
            AuthMethod.PASSWORD: request.password,
            AuthMethod.TOTP: request.totp,
        }
        token = authenticator.authenticate(request.user_id, credentials)
        
        # Create session
        session_id = str(uuid.uuid4())
        session = session_manager.create_session(session_id, request.user_id, token)
        
        # Log successful authentication
        audit_logger.log_event(
            event_type=EventType.AUTHENTICATION_SUCCESS,
            actor=request.user_id,
            severity=Severity.INFO,
            action="user_login",
            result="success",
        )
        
        return AuthenticateResponse(
            token=token,
            session_id=session_id,
            expires_at=session.expires_at,
        )
    
    except ValueError as e:
        # Log failed authentication
        audit_logger.log_event(
            event_type=EventType.AUTHENTICATION_FAILURE,
            actor=request.user_id,
            severity=Severity.WARNING,
            action="user_login",
            result="failed",
            details={"reason": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


# ============ Authorization Endpoints ============

@app.post("/api/v1/policies", tags=["Policies"])
async def create_policy(request: PolicyRequest) -> dict:
    """Create a new access control policy."""
    try:
        # Convert string permissions to Permission enums
        permissions = {Permission(p) for p in request.permissions}
        
        policy_id = f"policy-{uuid.uuid4().hex[:8]}"
        policy = Policy(
            policy_id=policy_id,
            principal=request.principal,
            resource=request.resource,
            permissions=permissions,
        )
        authz_engine.add_policy(policy)
        
        # Log policy creation
        audit_logger.log_event(
            event_type=EventType.POLICY_ADDED,
            actor="admin",
            severity=Severity.INFO,
            resource=request.resource,
            action="create_policy",
            details={
                "policy_id": policy_id,
                "principal": request.principal,
                "permissions": list(request.permissions),
            },
        )
        
        return {
            "policy_id": policy_id,
            "principal": request.principal,
            "resource": request.resource,
            "permissions": list(request.permissions),
        }
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission: {str(e)}",
        )


@app.post("/api/v1/authorize", response_model=AuthorizeResponse, tags=["Authorization"])
async def authorize(request: AuthorizeRequest) -> AuthorizeResponse:
    """
    Check if a principal is authorized to perform an action on a resource.
    """
    try:
        # Update session activity if session_id provided
        if request.session_id:
            session_manager.update_activity(request.session_id)
        
        # Convert permission string to Permission enum
        permission = Permission(request.permission)
        
        # Check authorization
        allowed = authz_engine.authorize(
            request.principal,
            request.resource,
            permission,
        )
        
        # Log authorization check
        event_type = EventType.AUTHORIZATION_ALLOWED if allowed else EventType.AUTHORIZATION_DENIED
        severity = Severity.INFO if allowed else Severity.WARNING
        
        audit_logger.log_event(
            event_type=event_type,
            actor=request.principal,
            severity=severity,
            resource=request.resource,
            action=request.permission,
            result="allowed" if allowed else "denied",
        )
        
        return AuthorizeResponse(
            allowed=allowed,
            reason="Access granted" if allowed else "Access denied - insufficient permissions",
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission: {str(e)}",
        )


# ============ Audit Logging Endpoints ============

@app.get("/api/v1/audit/events", tags=["Audit"])
async def get_audit_events(
    actor: Optional[str] = None,
    limit: int = 100,
) -> dict:
    """
    Retrieve audit events with optional filtering.
    """
    if actor:
        events = audit_logger.get_events(actor=actor)
    else:
        events = audit_logger.get_recent_events(limit=limit)
    
    return {
        "count": len(events),
        "events": [e.to_dict() for e in events],
    }


@app.get("/api/v1/audit/summary", response_model=EventSummary, tags=["Audit"])
async def get_audit_summary() -> EventSummary:
    """Get a summary of audit events."""
    summary = audit_logger.get_event_summary()
    return EventSummary(**summary)


@app.get("/api/v1/audit/critical-events", tags=["Audit"])
async def get_critical_events() -> dict:
    """
    Retrieve all critical security events.
    """
    critical_events = audit_logger.get_critical_events()
    return {
        "count": len(critical_events),
        "events": [e.to_dict() for e in critical_events],
    }


# ============ Session Endpoints ============

@app.post("/api/v1/sessions/{session_id}/invalidate", tags=["Sessions"])
async def invalidate_session(session_id: str) -> dict:
    """
    Invalidate a user session.
    """
    result = session_manager.invalidate_session(session_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )
    
    return {
        "session_id": session_id,
        "status": "invalidated",
    }


@app.get("/api/v1/sessions/{session_id}", tags=["Sessions"])
async def get_session(session_id: str) -> dict:
    """
    Get details about a session.
    """
    session = session_manager.get_session(session_id)
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired",
        )
    
    return {
        "session_id": session.session_id,
        "user_id": session.user_id,
        "created_at": session.created_at,
        "last_activity": session.last_activity,
        "expires_at": session.expires_at,
        "is_active": session.is_active,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
