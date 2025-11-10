from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any
from datetime import datetime
import secrets
from auth import get_current_user
from aws_integration import aws_integration
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/aws", tags=["AWS Integration"])

@router.get("/status", status_code=status.HTTP_200_OK)
async def get_aws_status(current_user: dict = Depends(get_current_user)):
    """
    Get AWS connection status and service availability
    
    Returns:
        - status: Connection status (connected/failed)
        - services: Dict of service statuses
        - region: AWS region
        - account_id: Masked AWS account ID (optional)
    """
    try:
        aws_status = aws_integration.test_aws_connection()
        
        # If AWS is not configured, return a clear message
        if aws_status.get("status") == "failed":
            return {
                "status": "disconnected",
                "message": "AWS credentials not configured or invalid",
                "services": {
                    "s3": "unavailable",
                    "cloudwatch": "unavailable",
                    "iam": "unavailable"
                },
                "region": "N/A",
                "account_id": "N/A",
                "timestamp": datetime.utcnow().isoformat()
            }
        
        return aws_status
    except Exception as e:
        logger.error(f"AWS status check failed: {str(e)}")
        return {
            "status": "error",
            "message": "AWS connection test failed. Please check credentials and configuration.",
            "error_detail": str(e),
            "services": {
                "s3": "error",
                "cloudwatch": "error",
                "iam": "error"
            },
            "region": "N/A",
            "account_id": "N/A",
            "timestamp": datetime.utcnow().isoformat()
        }

@router.post("/store-data", status_code=status.HTTP_201_CREATED)
async def store_data_in_aws(data: Dict[str, str], current_user: dict = Depends(get_current_user)):
    """
    Store encrypted data in AWS S3
    
    Args:
        data: Dict containing 'data' (content) and 'key' (optional S3 key)
    
    Returns:
        - status: Operation status
        - bucket: S3 bucket name
        - key: S3 object key
    """
    try:
        content = data.get("data")
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data content is required"
            )
        
        key = data.get("key", f"data_{secrets.token_urlsafe(16)}")
        
        result = aws_integration.store_encrypted_data(content, key)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to store data in AWS: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AWS S3 service unavailable: {str(e)}"
        )

@router.get("/retrieve-data/{key}", status_code=status.HTTP_200_OK)
async def retrieve_data_from_aws(key: str, current_user: dict = Depends(get_current_user)):
    """
    Retrieve encrypted data from AWS S3
    
    Args:
        key: S3 object key
    
    Returns:
        - status: Operation status
        - data: Retrieved data
        - key: S3 object key
    """
    try:
        if not key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="S3 key is required"
            )
        
        data = aws_integration.retrieve_encrypted_data(key)
        return {
            "status": "success",
            "data": data,
            "key": key,
            "timestamp": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve data from AWS: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Data not found or AWS S3 service unavailable: {str(e)}"
        )

@router.post("/send-metrics", status_code=status.HTTP_201_CREATED)
async def send_aws_metrics(metrics_data: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    """
    Send custom metrics to AWS CloudWatch
    
    Args:
        metrics_data: Dict containing namespace, metric_name, value, unit
    
    Returns:
        - status: Operation status
        - namespace: CloudWatch namespace
        - metric_name: Metric name
        - value: Metric value
    """
    try:
        namespace = metrics_data.get("namespace", "HybridCloudSecurity")
        metric_name = metrics_data.get("metric_name", "SecurityEvent")
        value = metrics_data.get("value")
        unit = metrics_data.get("unit", "Count")
        
        if value is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Metric value is required"
            )
        
        result = aws_integration.send_cloudwatch_metrics(namespace, metric_name, value, unit)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to send metrics to AWS: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AWS CloudWatch service unavailable: {str(e)}"
        )

@router.get("/security-metrics", status_code=status.HTTP_200_OK)
async def get_aws_security_metrics(current_user: dict = Depends(get_current_user)):
    """
    Get security metrics from AWS CloudWatch
    
    Returns:
        - metrics: List of metric datapoints
        - period: Metric period
    """
    try:
        metrics = aws_integration.get_security_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Failed to get security metrics: {str(e)}")
        # Return empty metrics instead of error for better UX
        return {
            "metrics": [],
            "period": "1 hour",
            "message": "No metrics available or AWS CloudWatch not configured",
            "timestamp": datetime.utcnow().isoformat()
        }
