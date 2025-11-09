from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas import ComplianceStatus
from auth import get_current_user
from compliance import ComplianceService

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

@router.get("/status", response_model=ComplianceStatus)
async def get_compliance_status(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    compliance_service = ComplianceService(db)
    return compliance_service.get_compliance_status()

@router.get("/policies")
async def get_policies(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    compliance_service = ComplianceService(db)
    return compliance_service.get_policies()

