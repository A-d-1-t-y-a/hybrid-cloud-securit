from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from database import get_db
from schemas import ComplianceStatus
from auth import get_current_user
from compliance import ComplianceService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

@router.get("/status", response_model=ComplianceStatus, status_code=status.HTTP_200_OK)
async def get_compliance_status(
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get overall compliance status and scores
    
    Returns:
        - overall_score: Overall compliance percentage
        - standards: Compliance scores by standard (GDPR, HIPAA, etc.)
        - last_updated: Last assessment timestamp
    """
    try:
        compliance_service = ComplianceService(db)
        compliance_status = compliance_service.get_compliance_status()
        return compliance_status
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching compliance status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch compliance status due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching compliance status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch compliance status: {str(e)}"
        )

@router.get("/policies", status_code=status.HTTP_200_OK)
async def get_policies(
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get all compliance policies
    
    Returns:
        - policies: List of compliance policies
        - total_count: Total number of policies
    """
    try:
        compliance_service = ComplianceService(db)
        policies_data = compliance_service.get_policies()
        return policies_data
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching policies: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch policies due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching policies: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch policies: {str(e)}"
        )
