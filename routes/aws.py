from fastapi import APIRouter, Depends
from typing import Dict, Any
from datetime import datetime
import secrets
from auth import get_current_user
from aws_integration import aws_integration

router = APIRouter(prefix="/api/v1/aws", tags=["AWS Integration"])

@router.get("/status")
async def get_aws_status(current_user: dict = Depends(get_current_user)):
    try:
        aws_status = aws_integration.test_aws_connection()
        return aws_status
    except Exception as e:
        return {
            "status": "error",
            "message": f"AWS connection failed: {str(e)}",
            "timestamp": datetime.utcnow().isoformat()
        }

@router.post("/store-data")
async def store_data_in_aws(data: Dict[str, str], current_user: dict = Depends(get_current_user)):
    try:
        content = data.get("data", "")
        key = data.get("key", f"data_{secrets.token_urlsafe(16)}")
        
        result = aws_integration.store_encrypted_data(content, key)
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to store data in AWS: {str(e)}",
            "note": "AWS credentials need to be configured for full functionality",
            "timestamp": datetime.utcnow().isoformat()
        }

@router.get("/retrieve-data/{key}")
async def retrieve_data_from_aws(key: str, current_user: dict = Depends(get_current_user)):
    try:
        data = aws_integration.retrieve_encrypted_data(key)
        return {
            "status": "success",
            "data": data,
            "key": key,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to retrieve data from AWS: {str(e)}",
            "note": "AWS credentials need to be configured for full functionality",
            "timestamp": datetime.utcnow().isoformat()
        }

@router.post("/send-metrics")
async def send_aws_metrics(metrics_data: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    try:
        namespace = metrics_data.get("namespace", "HybridCloudSecurity")
        metric_name = metrics_data.get("metric_name", "SecurityEvent")
        value = metrics_data.get("value", 1.0)
        unit = metrics_data.get("unit", "Count")
        
        result = aws_integration.send_cloudwatch_metrics(namespace, metric_name, value, unit)
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to send metrics to AWS: {str(e)}",
            "note": "AWS credentials need to be configured for full functionality",
            "timestamp": datetime.utcnow().isoformat()
        }

@router.get("/security-metrics")
async def get_aws_security_metrics(current_user: dict = Depends(get_current_user)):
    try:
        metrics = aws_integration.get_security_metrics()
        return metrics
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to get security metrics: {str(e)}",
            "note": "AWS credentials need to be configured for full functionality",
            "timestamp": datetime.utcnow().isoformat()
        }

