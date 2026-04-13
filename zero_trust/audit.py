"""Audit logging for security events."""

import time
from enum import Enum
from typing import Dict, Optional
from dataclasses import dataclass, field
import json


class EventType(Enum):
    """Types of security events to audit."""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_ALLOWED = "authorization_allowed"
    AUTHORIZATION_DENIED = "authorization_denied"
    POLICY_ADDED = "policy_added"
    POLICY_REVOKED = "policy_revoked"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_INVALIDATED = "session_invalidated"
    PRIVILEGE_ESCALATION_ATTEMPT = "privilege_escalation_attempt"
    RESOURCE_ACCESS = "resource_access"


class Severity(Enum):
    """Event severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Represents a security audit event."""
    event_id: str
    timestamp: float
    event_type: EventType
    severity: Severity
    actor: str  # User or system component performing the action
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    details: Dict[str, any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, any]:
        """Convert event to dictionary format."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "actor": self.actor,
            "resource": self.resource,
            "action": self.action,
            "result": self.result,
            "details": self.details,
        }


class AuditLogger:
    """Logs and retrieves security audit events."""
    
    def __init__(self):
        self.events: list[AuditEvent] = []
        self.event_counter = 0
    
    def log_event(self, event_type: EventType, actor: str, severity: Severity,
                 resource: Optional[str] = None, action: Optional[str] = None,
                 result: Optional[str] = None, details: Dict[str, any] = None) -> AuditEvent:
        """
        Log a security event.
        
        Args:
            event_type: Type of event
            actor: User or component performing the action
            severity: Event severity level
            resource: Resource being accessed
            action: Action being performed
            result: Result of the action
            details: Additional event details
            
        Returns:
            The created AuditEvent
        """
        self.event_counter += 1
        event_id = f"audit-{self.event_counter:06d}"
        
        event = AuditEvent(
            event_id=event_id,
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            actor=actor,
            resource=resource,
            action=action,
            result=result,
            details=details or {},
        )
        
        self.events.append(event)
        return event
    
    def get_events(self, actor: Optional[str] = None,
                  event_type: Optional[EventType] = None,
                  severity: Optional[Severity] = None) -> list[AuditEvent]:
        """
        Retrieve audit events with optional filtering.
        
        Args:
            actor: Filter by actor
            event_type: Filter by event type
            severity: Filter by severity
            
        Returns:
            List of matching audit events
        """
        filtered_events = self.events
        
        if actor:
            filtered_events = [e for e in filtered_events if e.actor == actor]
        
        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        
        if severity:
            filtered_events = [e for e in filtered_events if e.severity == severity]
        
        return filtered_events
    
    def get_critical_events(self) -> list[AuditEvent]:
        """
        Retrieve all critical security events.
        
        Returns:
            List of critical events
        """
        return self.get_events(severity=Severity.CRITICAL)
    
    def get_recent_events(self, limit: int = 100) -> list[AuditEvent]:
        """
        Retrieve the most recent audit events.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of recent events (newest first)
        """
        return list(reversed(self.events[-limit:]))
    
    def export_events_json(self, filepath: str, actor: Optional[str] = None) -> None:
        """
        Export audit events to JSON file.
        
        Args:
            filepath: Path to save JSON file
            actor: Optional actor filter
        """
        events_to_export = self.get_events(actor=actor)
        events_data = [e.to_dict() for e in events_to_export]
        
        with open(filepath, 'w') as f:
            json.dump(events_data, f, indent=2)
    
    def get_event_summary(self) -> Dict[str, any]:
        """
        Get a summary of audit events.
        
        Returns:
            Dictionary with event statistics
        """
        event_types = {}
        severity_counts = {}
        actor_counts = {}
        
        for event in self.events:
            event_types[event.event_type.value] = event_types.get(event.event_type.value, 0) + 1
            severity_counts[event.severity.value] = severity_counts.get(event.severity.value, 0) + 1
            actor_counts[event.actor] = actor_counts.get(event.actor, 0) + 1
        
        return {
            "total_events": len(self.events),
            "event_types": event_types,
            "severity_distribution": severity_counts,
            "actors": actor_counts,
        }
