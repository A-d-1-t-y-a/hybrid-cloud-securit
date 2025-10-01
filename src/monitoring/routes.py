"""
Security Monitoring API Routes for Hybrid Cloud Security Framework
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from src.monitoring.siem_engine import SIEMEngine, SecurityEvent

router = APIRouter()
security = HTTPBearer()

# Global SIEM engine instance
siem_engine = SIEMEngine()


class EventIngestRequest(BaseModel):
    """Event ingestion request"""
    event_id: Optional[str] = None
    timestamp: Optional[str] = None
    source: str
    event_type: str
    severity: str
    description: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    resource: Optional[str] = None
    metadata: Optional[Dict] = None


class EventSearchRequest(BaseModel):
    """Event search request"""
    source: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    user_id: Optional[str] = None
    limit: int = 100


class TrainingRequest(BaseModel):
    """Training data request"""
    events: List[EventIngestRequest]


class DashboardResponse(BaseModel):
    """Security dashboard response"""
    total_events: int
    severity_breakdown: Dict[str, int]
    recent_events_count: int
    top_event_types: List[List[Any]]
    top_sources: List[List[Any]]
    threat_indicators_count: int
    anomaly_detector_trained: bool


@router.post("/events/ingest")
async def ingest_event(
    event_data: EventIngestRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Ingest security event"""
    try:
        # Convert to dictionary
        event_dict = event_data.dict()
        
        # Ingest event
        event = await siem_engine.ingest_event(event_dict)
        
        return {
            "message": "Event ingested successfully",
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error ingesting event: {str(e)}"
        )


@router.post("/events/search")
async def search_events(
    search_query: EventSearchRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Search security events"""
    try:
        # Convert to dictionary
        query_dict = search_query.dict()
        
        # Search events
        events = await siem_engine.search_events(query_dict)
        
        # Convert events to response format
        event_responses = []
        for event in events:
            event_responses.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "resource": event.resource,
                "metadata": event.metadata
            })
        
        return {
            "events": event_responses,
            "total_count": len(event_responses)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error searching events: {str(e)}"
        )


@router.get("/dashboard", response_model=DashboardResponse)
async def get_security_dashboard(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get security dashboard data"""
    try:
        dashboard_data = await siem_engine.get_security_dashboard()
        
        return DashboardResponse(
            total_events=dashboard_data["total_events"],
            severity_breakdown=dashboard_data["severity_breakdown"],
            recent_events_count=dashboard_data["recent_events_count"],
            top_event_types=dashboard_data["top_event_types"],
            top_sources=dashboard_data["top_sources"],
            threat_indicators_count=dashboard_data["threat_indicators_count"],
            anomaly_detector_trained=dashboard_data["anomaly_detector_trained"]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting dashboard: {str(e)}"
        )


@router.post("/train")
async def train_anomaly_detector(
    training_data: TrainingRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Train anomaly detection model"""
    try:
        # Convert training data to SecurityEvent objects
        training_events = []
        for event_data in training_data.events:
            event = SecurityEvent(
                event_id=event_data.event_id or f"evt_{datetime.utcnow().timestamp()}",
                timestamp=datetime.fromisoformat(event_data.timestamp) if event_data.timestamp else datetime.utcnow(),
                source=event_data.source,
                event_type=event_data.event_type,
                severity=event_data.severity,
                description=event_data.description,
                user_id=event_data.user_id,
                ip_address=event_data.ip_address,
                resource=event_data.resource,
                metadata=event_data.metadata
            )
            training_events.append(event)
        
        # Train model
        success = await siem_engine.train_anomaly_detector(training_events)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Training failed"
            )
        
        return {
            "message": "Anomaly detector trained successfully",
            "training_samples": len(training_events)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error training model: {str(e)}"
        )


@router.get("/threat-indicators")
async def get_threat_indicators(
    limit: int = 100,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get threat indicators"""
    try:
        indicators = siem_engine.threat_indicators[-limit:]  # Get latest indicators
        
        indicator_responses = []
        for indicator in indicators:
            indicator_responses.append({
                "indicator_id": indicator.indicator_id,
                "indicator_type": indicator.indicator_type,
                "value": indicator.value,
                "confidence": indicator.confidence,
                "source": indicator.source,
                "first_seen": indicator.first_seen.isoformat(),
                "last_seen": indicator.last_seen.isoformat(),
                "tags": indicator.tags
            })
        
        return {
            "threat_indicators": indicator_responses,
            "total_count": len(siem_engine.threat_indicators)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting threat indicators: {str(e)}"
        )


@router.get("/correlation-rules")
async def get_correlation_rules(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get correlation rules"""
    try:
        return {
            "correlation_rules": siem_engine.correlation_rules,
            "alert_thresholds": siem_engine.alert_thresholds
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting correlation rules: {str(e)}"
        )


@router.post("/correlation-rules")
async def add_correlation_rule(
    rule_name: str,
    rule_config: Dict[str, Any],
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Add new correlation rule"""
    try:
        siem_engine.correlation_rules[rule_name] = rule_config
        
        return {
            "message": "Correlation rule added successfully",
            "rule_name": rule_name,
            "rule_config": rule_config
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error adding correlation rule: {str(e)}"
        )


@router.get("/events/recent")
async def get_recent_events(
    hours: int = 24,
    limit: int = 100,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get recent events"""
    try:
        # Calculate cutoff time
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Filter recent events
        recent_events = [
            e for e in siem_engine.events 
            if e.timestamp >= cutoff_time
        ]
        
        # Sort by timestamp (newest first) and limit
        recent_events.sort(key=lambda x: x.timestamp, reverse=True)
        recent_events = recent_events[:limit]
        
        # Convert to response format
        event_responses = []
        for event in recent_events:
            event_responses.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "resource": event.resource
            })
        
        return {
            "events": event_responses,
            "total_count": len(recent_events),
            "time_range_hours": hours
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting recent events: {str(e)}"
        )


@router.get("/events/statistics")
async def get_event_statistics(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Get event statistics"""
    try:
        # Calculate statistics
        total_events = len(siem_engine.events)
        
        # Severity breakdown
        severity_counts = {}
        for event in siem_engine.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
        
        # Event type breakdown
        event_type_counts = {}
        for event in siem_engine.events:
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        
        # Source breakdown
        source_counts = {}
        for event in siem_engine.events:
            source_counts[event.source] = source_counts.get(event.source, 0) + 1
        
        return {
            "total_events": total_events,
            "severity_breakdown": severity_counts,
            "event_type_breakdown": event_type_counts,
            "source_breakdown": source_counts,
            "threat_indicators_count": len(siem_engine.threat_indicators),
            "anomaly_detector_trained": siem_engine.trained
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error getting event statistics: {str(e)}"
        )
