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
        """Get overall compliance status"""
        try:
            # Calculate compliance scores based on policies
            policies = self.db.query(CompliancePolicy).filter(
                CompliancePolicy.is_active == True
            ).all()
            
            # Default compliance data
            compliance_data = {
                "overall_score": 85,
                "standards": {
                    "GDPR": {"score": 90, "status": "compliant"},
                    "HIPAA": {"score": 85, "status": "compliant"},
                    "SOX": {"score": 88, "status": "compliant"},
                    "ISO27001": {"score": 92, "status": "compliant"},
                    "PCI_DSS": {"score": 87, "status": "compliant"}
                },
                "recommendations": [
                    "Enhance data encryption for sensitive information",
                    "Implement additional access controls",
                    "Update security policies regularly"
                ]
            }
            
            # Update scores based on active policies
            if policies:
                total_policies = len(policies)
                active_policies = len([p for p in policies if p.is_active])
                compliance_percentage = (active_policies / total_policies) * 100 if total_policies > 0 else 0
                
                compliance_data["overall_score"] = int(compliance_percentage)
                
                # Update individual standards based on policies
                for policy in policies:
                    if policy.compliance_standards:
                        for standard in policy.compliance_standards:
                            if standard in compliance_data["standards"]:
                                # Increase score for each active policy
                                compliance_data["standards"][standard]["score"] = min(
                                    compliance_data["standards"][standard]["score"] + 2, 100
                                )
            
            return compliance_data
        except Exception as e:
            raise ValueError(f"Failed to get compliance status: {str(e)}")
    
    def get_policies(self) -> Dict[str, Any]:
        """Get compliance policies"""
        try:
            policies = self.db.query(CompliancePolicy).filter(
                CompliancePolicy.is_active == True
            ).all()
            
            policies_data = []
            for policy in policies:
                policies_data.append({
                    "policy_id": policy.policy_id,
                    "name": policy.name,
                    "description": policy.description,
                    "policy_type": policy.policy_type,
                    "compliance_standards": policy.compliance_standards,
                    "created_at": policy.created_at.isoformat()
                })
            
            return {
                "policies": policies_data,
                "total_count": len(policies_data)
            }
        except Exception as e:
            raise ValueError(f"Failed to get policies: {str(e)}")
    
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
