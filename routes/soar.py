from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from database import get_db
from schemas import SOARWorkflowRequest
from auth import get_current_user
from soar import SOARService
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR"])

@router.post("/workflows", status_code=status.HTTP_201_CREATED)
async def create_workflow(
    workflow_data: SOARWorkflowRequest, 
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Create a new SOAR automation workflow
    
    Args:
        workflow_data: Workflow configuration including name, triggers, and actions
    
    Returns:
        - workflow_id: Unique workflow identifier
        - status: Workflow status
        - created_at: Creation timestamp
    """
    try:
        soar_service = SOARService(db)
        workflow_dict = {
            "name": workflow_data.name,
            "description": workflow_data.description,
            "trigger_conditions": workflow_data.trigger_conditions,
            "actions": workflow_data.actions,
            "status": workflow_data.status
        }
        
        result = soar_service.create_workflow(workflow_dict)
        return result
    except SQLAlchemyError as e:
        logger.error(f"Database error creating workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create workflow due to database error"
        )
    except ValueError as e:
        logger.error(f"Validation error creating workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error creating workflow: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create workflow: {str(e)}"
        )

@router.get("/workflows", status_code=status.HTTP_200_OK)
async def get_workflows(
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get all SOAR workflows
    
    Returns:
        - workflows: List of all workflows
        - total_count: Total number of workflows
    """
    try:
        soar_service = SOARService(db)
        workflows_data = soar_service.get_workflows()
        return workflows_data
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching workflows: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch workflows due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching workflows: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch workflows: {str(e)}"
        )

@router.get("/automation/status", status_code=status.HTTP_200_OK)
async def get_automation_status(
    current_user: dict = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    """
    Get SOAR automation system status
    
    Returns:
        - active_workflows: Number of active workflows
        - total_executions: Total workflow executions
        - success_rate: Workflow success rate percentage
        - last_execution: Last execution timestamp
    """
    try:
        soar_service = SOARService(db)
        automation_status = soar_service.get_automation_status()
        return automation_status
    except SQLAlchemyError as e:
        logger.error(f"Database error fetching automation status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch automation status due to database error"
        )
    except Exception as e:
        logger.error(f"Error fetching automation status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch automation status: {str(e)}"
        )
