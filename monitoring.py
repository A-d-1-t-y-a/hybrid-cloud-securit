#!/usr/bin/env python3
"""
Security monitoring and SIEM services
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
from sqlalchemy.orm import Session
from models import SecurityEvent, AuditLog
from ml_engine import anomaly_detector

class MonitoringService:
    """Security monitoring service"""
    
    def __init__(self, db: Session):
        self.db = db
        # Ensure model is ready
        if not anomaly_detector.is_trained:
            anomaly_detector.train()
    
    def ingest_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest security event"""
        try:
            # RUN REAL ML PREDICTION
            ml_analysis = anomaly_detector.predict(event_data)
            
            # Enrich metadata with ML scores
            metadata = event_data.get("metadata", {})
            metadata.update({
                "ml_anomaly_score": ml_analysis.get("anomaly_score"),
                "ml_risk_level": ml_analysis.get("risk_level")
            })
            
            # Auto-escalate severity if ML says CRITICAL
            severity = event_data.get("severity", "low")
            if ml_analysis.get("is_anomaly"):
                severity = "critical" if ml_analysis.get("risk_level") == "CRITICAL" else "high"

            # Create security event
            event = SecurityEvent(
                event_id=f"evt_{self._generate_id()}",
                source=event_data.get("source", "unknown"),
                event_type=event_data.get("event_type", "unknown"),
                severity=severity,
                description=event_data.get("description", "") + f" [ML Risk: {ml_analysis.get('risk_level')}]",
                user_id=event_data.get("user_id"),
                ip_address=event_data.get("ip_address"),
                event_metadata=metadata
            )
            
            self.db.add(event)
            self.db.commit()
            
            return {
                "message": "Event ingested successfully",
                "event_id": event.event_id,
                "timestamp": event.created_at.isoformat(),
                "ml_analysis": ml_analysis
            }
        except Exception as e:
            self.db.rollback()
            raise ValueError(f"Failed to ingest event: {str(e)}")
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get security dashboard data"""
        try:
            # Get total events
            total_events = self.db.query(SecurityEvent).count()
            
            # Get severity breakdown
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            events = self.db.query(SecurityEvent).all()
            
            for event in events:
                severity = event.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Get recent events
            recent_events = self.db.query(SecurityEvent).order_by(
                SecurityEvent.created_at.desc()
            ).limit(10).all()
            
            return {
                "total_events": total_events,
                "critical_events": severity_counts.get("critical", 0),
                "high_severity_events": severity_counts.get("high", 0),
                "medium_severity_events": severity_counts.get("medium", 0),
                "low_severity_events": severity_counts.get("low", 0),
                "recent_events": len(recent_events),
                "severity_breakdown": severity_counts,
                "recent_events_count": len(recent_events),
                "top_event_types": ["authentication", "data_access", "system_change"],
                "top_sources": ["firewall", "ids", "application"],
                "threat_indicators_count": severity_counts.get("critical", 0) + severity_counts.get("high", 0),
                "anomaly_detector_trained": anomaly_detector.is_trained,
                "ml_engine_status": "online"
            }
        except Exception as e:
            raise ValueError(f"Failed to get dashboard data: {str(e)}")
    
    def get_events(self, limit: int = 100) -> Dict[str, Any]:
        """Get security events"""
        try:
            events = self.db.query(SecurityEvent).order_by(
                SecurityEvent.created_at.desc()
            ).limit(limit).all()
            
            events_data = []
            for event in events:
                events_data.append({
                    "event_id": event.event_id,
                    "source": event.source,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "description": event.description,
                    "user_id": event.user_id,
                    "ip_address": event.ip_address,
                    "timestamp": event.created_at.isoformat()
                })
            
            return {
                "events": events_data,
                "total_count": len(events_data)
            }
        except Exception as e:
            raise ValueError(f"Failed to get events: {str(e)}")
    
    def log_audit_event(self, user_id: str, action: str, resource: str, 
                       ip_address: str = None, user_agent: str = None, 
                       metadata: Dict = None) -> None:
        """Log audit event"""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                ip_address=ip_address,
                user_agent=user_agent,
                event_metadata=metadata or {}
            )
            
            self.db.add(audit_log)
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise ValueError(f"Failed to log audit event: {str(e)}")
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        import secrets
        return secrets.token_urlsafe(16)
