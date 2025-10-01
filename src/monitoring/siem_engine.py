"""
Security Information and Event Management (SIEM) Engine
"""

import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np

from src.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    description: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    resource: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    indicator_id: str
    indicator_type: str
    value: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]


class SIEMEngine:
    """Security Information and Event Management Engine"""
    
    def __init__(self):
        self.events: List[SecurityEvent] = []
        self.threat_indicators: List[ThreatIndicator] = []
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.correlation_rules = self._load_correlation_rules()
        self.alert_thresholds = self._load_alert_thresholds()
        self.trained = False
    
    def _load_correlation_rules(self) -> Dict[str, Dict]:
        """Load correlation rules for threat detection"""
        return {
            "brute_force": {
                "pattern": "multiple_failed_logins",
                "threshold": 5,
                "time_window": 300,  # 5 minutes
                "severity": "high"
            },
            "privilege_escalation": {
                "pattern": "unusual_privilege_usage",
                "threshold": 3,
                "time_window": 600,  # 10 minutes
                "severity": "critical"
            },
            "data_exfiltration": {
                "pattern": "large_data_transfer",
                "threshold": 1000000,  # 1MB
                "time_window": 3600,  # 1 hour
                "severity": "high"
            },
            "suspicious_activity": {
                "pattern": "unusual_access_patterns",
                "threshold": 10,
                "time_window": 1800,  # 30 minutes
                "severity": "medium"
            }
        }
    
    def _load_alert_thresholds(self) -> Dict[str, float]:
        """Load alert thresholds for different event types"""
        return {
            "critical": 0.9,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3
        }
    
    async def ingest_event(self, event_data: Dict[str, Any]) -> SecurityEvent:
        """Ingest security event"""
        try:
            event = SecurityEvent(
                event_id=event_data.get("event_id", f"evt_{datetime.utcnow().timestamp()}"),
                timestamp=datetime.fromisoformat(event_data.get("timestamp", datetime.utcnow().isoformat())),
                source=event_data.get("source", "unknown"),
                event_type=event_data.get("event_type", "unknown"),
                severity=event_data.get("severity", "low"),
                description=event_data.get("description", ""),
                user_id=event_data.get("user_id"),
                ip_address=event_data.get("ip_address"),
                resource=event_data.get("resource"),
                metadata=event_data.get("metadata", {})
            )
            
            self.events.append(event)
            
            # Trigger real-time analysis
            await self._analyze_event(event)
            
            logger.info(f"Event ingested: {event.event_id}")
            return event
            
        except Exception as e:
            logger.error(f"Error ingesting event: {str(e)}")
            raise
    
    async def _analyze_event(self, event: SecurityEvent):
        """Analyze event for threats and anomalies"""
        try:
            # Check correlation rules
            await self._check_correlation_rules(event)
            
            # Check for anomalies
            await self._check_anomalies(event)
            
            # Update threat indicators
            await self._update_threat_indicators(event)
            
        except Exception as e:
            logger.error(f"Error analyzing event: {str(e)}")
    
    async def _check_correlation_rules(self, event: SecurityEvent):
        """Check event against correlation rules"""
        try:
            for rule_name, rule_config in self.correlation_rules.items():
                if await self._matches_rule(event, rule_config):
                    await self._generate_alert(event, rule_name, rule_config)
                    
        except Exception as e:
            logger.error(f"Error checking correlation rules: {str(e)}")
    
    async def _matches_rule(self, event: SecurityEvent, rule_config: Dict) -> bool:
        """Check if event matches correlation rule"""
        try:
            pattern = rule_config["pattern"]
            threshold = rule_config["threshold"]
            time_window = rule_config["time_window"]
            
            # Get events within time window
            cutoff_time = event.timestamp - timedelta(seconds=time_window)
            recent_events = [
                e for e in self.events 
                if e.timestamp >= cutoff_time and e.event_type == pattern
            ]
            
            return len(recent_events) >= threshold
            
        except Exception as e:
            logger.error(f"Error matching rule: {str(e)}")
            return False
    
    async def _check_anomalies(self, event: SecurityEvent):
        """Check for anomalous behavior"""
        try:
            if not self.trained:
                return
            
            # Extract features from event
            features = self._extract_event_features(event)
            
            # Predict anomaly
            anomaly_score = self.anomaly_detector.decision_function([features])[0]
            
            if anomaly_score < -0.5:  # Threshold for anomaly
                await self._generate_anomaly_alert(event, anomaly_score)
                
        except Exception as e:
            logger.error(f"Error checking anomalies: {str(e)}")
    
    def _extract_event_features(self, event: SecurityEvent) -> List[float]:
        """Extract numerical features from event"""
        try:
            features = [
                len(event.description),
                hash(event.source) % 1000,
                hash(event.event_type) % 1000,
                hash(event.severity) % 1000,
                1 if event.user_id else 0,
                1 if event.ip_address else 0,
                1 if event.resource else 0,
                event.timestamp.hour,
                event.timestamp.weekday()
            ]
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return [0.0] * 9
    
    async def _update_threat_indicators(self, event: SecurityEvent):
        """Update threat indicators based on event"""
        try:
            # Extract indicators from event
            indicators = self._extract_indicators(event)
            
            for indicator in indicators:
                # Check if indicator already exists
                existing = next(
                    (i for i in self.threat_indicators if i.value == indicator["value"]),
                    None
                )
                
                if existing:
                    existing.last_seen = event.timestamp
                    existing.confidence = max(existing.confidence, indicator["confidence"])
                else:
                    new_indicator = ThreatIndicator(
                        indicator_id=f"ind_{datetime.utcnow().timestamp()}",
                        indicator_type=indicator["type"],
                        value=indicator["value"],
                        confidence=indicator["confidence"],
                        source=event.source,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        tags=indicator.get("tags", [])
                    )
                    self.threat_indicators.append(new_indicator)
                    
        except Exception as e:
            logger.error(f"Error updating threat indicators: {str(e)}")
    
    def _extract_indicators(self, event: SecurityEvent) -> List[Dict]:
        """Extract threat indicators from event"""
        indicators = []
        
        # IP address indicator
        if event.ip_address:
            indicators.append({
                "type": "ip_address",
                "value": event.ip_address,
                "confidence": 0.8,
                "tags": ["network"]
            })
        
        # User indicator
        if event.user_id:
            indicators.append({
                "type": "user",
                "value": event.user_id,
                "confidence": 0.6,
                "tags": ["identity"]
            })
        
        # Resource indicator
        if event.resource:
            indicators.append({
                "type": "resource",
                "value": event.resource,
                "confidence": 0.7,
                "tags": ["resource"]
            })
        
        return indicators
    
    async def _generate_alert(self, event: SecurityEvent, rule_name: str, rule_config: Dict):
        """Generate security alert"""
        try:
            alert = {
                "alert_id": f"alert_{datetime.utcnow().timestamp()}",
                "timestamp": datetime.utcnow().isoformat(),
                "rule_name": rule_name,
                "severity": rule_config["severity"],
                "description": f"Correlation rule triggered: {rule_name}",
                "event_id": event.event_id,
                "source": event.source,
                "recommended_actions": self._get_recommended_actions(rule_name)
            }
            
            logger.warning(f"Security alert generated: {alert['alert_id']}")
            return alert
            
        except Exception as e:
            logger.error(f"Error generating alert: {str(e)}")
    
    async def _generate_anomaly_alert(self, event: SecurityEvent, anomaly_score: float):
        """Generate anomaly alert"""
        try:
            alert = {
                "alert_id": f"anomaly_{datetime.utcnow().timestamp()}",
                "timestamp": datetime.utcnow().isoformat(),
                "rule_name": "anomaly_detection",
                "severity": "high",
                "description": f"Anomalous behavior detected (score: {anomaly_score:.2f})",
                "event_id": event.event_id,
                "source": event.source,
                "anomaly_score": anomaly_score,
                "recommended_actions": ["Investigate user behavior", "Review access patterns"]
            }
            
            logger.warning(f"Anomaly alert generated: {alert['alert_id']}")
            return alert
            
        except Exception as e:
            logger.error(f"Error generating anomaly alert: {str(e)}")
    
    def _get_recommended_actions(self, rule_name: str) -> List[str]:
        """Get recommended actions for rule"""
        actions = {
            "brute_force": [
                "Block IP address",
                "Enable additional authentication",
                "Notify security team"
            ],
            "privilege_escalation": [
                "Review user permissions",
                "Investigate access logs",
                "Notify administrators"
            ],
            "data_exfiltration": [
                "Block data transfer",
                "Review user access",
                "Notify data protection team"
            ],
            "suspicious_activity": [
                "Monitor user activity",
                "Review access patterns",
                "Investigate further"
            ]
        }
        return actions.get(rule_name, ["Investigate incident"])
    
    async def train_anomaly_detector(self, training_events: List[SecurityEvent]) -> bool:
        """Train anomaly detection model"""
        try:
            if not training_events:
                return False
            
            # Extract features from training events
            features = [self._extract_event_features(event) for event in training_events]
            
            # Scale features
            scaled_features = self.scaler.fit_transform(features)
            
            # Train anomaly detector
            self.anomaly_detector.fit(scaled_features)
            self.trained = True
            
            logger.info(f"Anomaly detector trained with {len(training_events)} events")
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {str(e)}")
            return False
    
    async def get_security_dashboard(self) -> Dict[str, Any]:
        """Get security dashboard data"""
        try:
            # Calculate metrics
            total_events = len(self.events)
            critical_events = len([e for e in self.events if e.severity == "critical"])
            high_events = len([e for e in self.events if e.severity == "high"])
            medium_events = len([e for e in self.events if e.severity == "medium"])
            low_events = len([e for e in self.events if e.severity == "low"])
            
            # Get recent events (last 24 hours)
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            recent_events = [e for e in self.events if e.timestamp >= cutoff_time]
            
            # Get top event types
            event_types = {}
            for event in recent_events:
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            top_event_types = sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Get top sources
            sources = {}
            for event in recent_events:
                sources[event.source] = sources.get(event.source, 0) + 1
            
            top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                "total_events": total_events,
                "severity_breakdown": {
                    "critical": critical_events,
                    "high": high_events,
                    "medium": medium_events,
                    "low": low_events
                },
                "recent_events_count": len(recent_events),
                "top_event_types": top_event_types,
                "top_sources": top_sources,
                "threat_indicators_count": len(self.threat_indicators),
                "anomaly_detector_trained": self.trained
            }
            
        except Exception as e:
            logger.error(f"Error getting security dashboard: {str(e)}")
            return {}
    
    async def search_events(self, query: Dict[str, Any]) -> List[SecurityEvent]:
        """Search events based on query"""
        try:
            filtered_events = self.events.copy()
            
            # Filter by source
            if "source" in query:
                filtered_events = [e for e in filtered_events if e.source == query["source"]]
            
            # Filter by event type
            if "event_type" in query:
                filtered_events = [e for e in filtered_events if e.event_type == query["event_type"]]
            
            # Filter by severity
            if "severity" in query:
                filtered_events = [e for e in filtered_events if e.severity == query["severity"]]
            
            # Filter by time range
            if "start_time" in query and "end_time" in query:
                start_time = datetime.fromisoformat(query["start_time"])
                end_time = datetime.fromisoformat(query["end_time"])
                filtered_events = [
                    e for e in filtered_events 
                    if start_time <= e.timestamp <= end_time
                ]
            
            # Filter by user
            if "user_id" in query:
                filtered_events = [e for e in filtered_events if e.user_id == query["user_id"]]
            
            # Sort by timestamp (newest first)
            filtered_events.sort(key=lambda x: x.timestamp, reverse=True)
            
            # Limit results
            limit = query.get("limit", 100)
            return filtered_events[:limit]
            
        except Exception as e:
            logger.error(f"Error searching events: {str(e)}")
            return []
