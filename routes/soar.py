from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas import SOARWorkflowRequest
from auth import get_current_user
from soar import SOARService

router = APIRouter(prefix="/api/v1/soar", tags=["SOAR"])

@router.post("/workflows")
async def create_workflow(workflow_data: SOARWorkflowRequest, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    soar_service = SOARService(db)
    workflow_dict = {
        "name": workflow_data.name,
        "description": workflow_data.description,
        "trigger_conditions": workflow_data.trigger_conditions,
        "actions": workflow_data.actions,
        "status": workflow_data.status
    }
    return soar_service.create_workflow(workflow_dict)

@router.get("/workflows")
async def get_workflows(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    soar_service = SOARService(db)
    return soar_service.get_workflows()

@router.get("/automation/status")
async def get_automation_status(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    soar_service = SOARService(db)
    return soar_service.get_automation_status()

