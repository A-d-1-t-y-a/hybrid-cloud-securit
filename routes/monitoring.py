from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas import SecurityEventRequest
from auth import get_current_user
from monitoring import MonitoringService

router = APIRouter(prefix="/api/v1/monitoring", tags=["Security Monitoring"])

@router.post("/events/ingest")
async def ingest_event(event_data: SecurityEventRequest, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitoring_service = MonitoringService(db)
    event_dict = {
        "source": event_data.source,
        "event_type": event_data.event_type,
        "severity": event_data.severity,
        "description": event_data.description,
        "user_id": event_data.user_id,
        "ip_address": event_data.ip_address
    }
    
    result = monitoring_service.ingest_event(event_dict)
    return result

@router.get("/dashboard")
async def get_security_dashboard(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitoring_service = MonitoringService(db)
    return monitoring_service.get_dashboard_data()

@router.get("/events")
async def get_events(limit: int = 100, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitoring_service = MonitoringService(db)
    return monitoring_service.get_events(limit)

