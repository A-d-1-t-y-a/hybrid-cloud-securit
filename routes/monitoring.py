from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from database import get_db
from schemas import SecurityEventRequest
from auth import get_current_user
from monitoring import MonitoringService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/monitoring", tags=["Security Monitoring"])

@router.post("/events/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_event(
    event_data: SecurityEventRequest, 
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Ingest a new security event into the monitoring system
    
    Args:
        event_data: Security event details
    
    Returns:
        - event_id: Unique event identifier
        - status: Ingestion status
    """
    try:
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
    except SQLAlchemyError as e:
        logger.error(f"Database error during event ingestion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest security event due to database error"
        )
    except Exception as e:
        logger.error(f"Error ingesting event: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest security event: {str(e)}"
        )

@router.get("/dashboard", status_code=status.HTTP_200_OK)
async def get_security_dashboard(
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get security monitoring dashboard data
    
    Returns:
        - metrics: Dashboard metrics
        - recent_events: Recent security events
        - statistics: Event statistics
    """
    try:
        monitoring_service = MonitoringService(db)
        dashboard_data = monitoring_service.get_dashboard_data()
        return dashboard_data
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching dashboard: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load dashboard data due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching dashboard: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load dashboard data: {str(e)}"
        )

@router.get("/events", status_code=status.HTTP_200_OK)
async def get_events(
    limit: int = 100, 
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get security events with pagination
    
    Args:
        limit: Maximum number of events to return (default: 100, max: 1000)
    
    Returns:
        - events: List of security events
        - total_count: Total number of events
    """
    try:
        # Validate limit
        if limit < 1 or limit > 1000:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Limit must be between 1 and 1000"
            )
        
        monitoring_service = MonitoringService(db)
        events_data = monitoring_service.get_events(limit)
        return events_data
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching events: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch events due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching events: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch events: {str(e)}"
        )
