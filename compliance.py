#!/usr/bin/env python3
"""
Compliance and governance services
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

from typing import Dict, List, Any
from sqlalchemy.orm import Session
from models import CompliancePolicy, AuditLog
from config import settings

class ComplianceService:
    """Compliance and governance service"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_compliance_status(self) -> Dict[str, Any]:
        """Get overall compliance status - fully dynamic based on policies"""
        try:
            # Get all policies
            all_policies = self.db.query(CompliancePolicy).all()
            active_policies = [p for p in all_policies if p.is_active]
            
            # Initialize standards tracking
            standards_tracking = {
                "GDPR": {"count": 0, "active": 0},
                "HIPAA": {"count": 0, "active": 0},
                "SOX": {"count": 0, "active": 0},
                "ISO27001": {"count": 0, "active": 0},
                "PCI_DSS": {"count": 0, "active": 0}
            }
            
            # Count policies per standard
            for policy in all_policies:
                if policy.compliance_standards and isinstance(policy.compliance_standards, list):
                    for standard in policy.compliance_standards:
                        if standard in standards_tracking:
                            standards_tracking[standard]["count"] += 1
                            if policy.is_active:
                                standards_tracking[standard]["active"] += 1
            
            # Calculate scores for each standard
            standards = {}
            total_score = 0
            standards_with_policies = 0
            
            for standard, data in standards_tracking.items():
                if data["count"] > 0:
                    # Score based on percentage of active policies
                    score = int((data["active"] / data["count"]) * 100)
                    standards[standard] = {
                        "score": score,
                        "status": "compliant" if score >= 80 else "non-compliant",
                        "findings": 0 if score >= 90 else (100 - score) // 10
                    }
                    total_score += score
                    standards_with_policies += 1
                else:
                    # No policies for this standard - assume baseline
                    standards[standard] = {
                        "score": 75,
                        "status": "needs-attention",
                        "findings": 3
                    }
                    total_score += 75
                    standards_with_policies += 1
            
            # Calculate overall score
            overall_score = int(total_score / standards_with_policies) if standards_with_policies > 0 else 0
            
            # Generate dynamic recommendations
            recommendations = []
            for standard, data in standards.items():
                if data["score"] < 90:
                    recommendations.append(f"Improve {standard} compliance (current: {data['score']}%)")
            
            if not recommendations:
                recommendations.append("Maintain current compliance levels")
            
            return {
                "overall_score": overall_score,
                "standards": standards,
                "total_policies": len(all_policies),
                "active_policies": len(active_policies),
                "recommendations": recommendations
            }
        except Exception as e:
            # Return minimal data on error
            return {
                "overall_score": 0,
                "standards": {
                    "GDPR": {"score": 0, "status": "unknown", "findings": 0},
                    "HIPAA": {"score": 0, "status": "unknown", "findings": 0},
                    "SOX": {"score": 0, "status": "unknown", "findings": 0},
                    "ISO27001": {"score": 0, "status": "unknown", "findings": 0},
                    "PCI_DSS": {"score": 0, "status": "unknown", "findings": 0}
                },
                "total_policies": 0,
                "active_policies": 0,
                "recommendations": ["Unable to calculate compliance status"]
            }
    
    def get_policies(self) -> List[Dict[str, Any]]:
        """Get all compliance policies"""
        try:
            policies = self.db.query(CompliancePolicy).all()
            
            policies_data = []
            for policy in policies:
                policies_data.append({
                    "policy_id": policy.policy_id,
                    "name": policy.name,
                    "description": policy.description,
                    "policy_type": policy.policy_type,
                    "framework": policy.compliance_standards[0] if policy.compliance_standards else "General",
                    "compliance_standards": policy.compliance_standards,
                    "is_active": policy.is_active,
                    "created_at": policy.created_at.isoformat() if policy.created_at else None,
                    "updated_at": policy.updated_at.isoformat() if policy.updated_at else None
                })
            
            return policies_data
        except Exception as e:
            return []
    
    def create_policy(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new compliance policy"""
        try:
            policy = CompliancePolicy(
                policy_id=f"policy_{self._generate_id()}",
                name=policy_data.get("name"),
                description=policy_data.get("description"),
                policy_type=policy_data.get("policy_type"),
                compliance_standards=policy_data.get("compliance_standards", []),
                is_active=True
            )
            
            self.db.add(policy)
            self.db.commit()
            
            return {
                "message": "Policy created successfully",
                "policy_id": policy.policy_id
            }
        except Exception as e:
            self.db.rollback()
            raise ValueError(f"Failed to create policy: {str(e)}")
    
    def get_audit_trail(self, limit: int = 100) -> Dict[str, Any]:
        """Get audit trail"""
        try:
            audit_logs = self.db.query(AuditLog).order_by(
                AuditLog.created_at.desc()
            ).limit(limit).all()
            
            audit_data = []
            for log in audit_logs:
                audit_data.append({
                    "user_id": log.user_id,
                    "action": log.action,
                    "resource": log.resource,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "metadata": log.event_metadata,
                    "timestamp": log.created_at.isoformat()
                })
            
            return {
                "audit_logs": audit_data,
                "total_count": len(audit_data)
            }
        except Exception as e:
            raise ValueError(f"Failed to get audit trail: {str(e)}")
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        import secrets
        return secrets.token_urlsafe(16)
