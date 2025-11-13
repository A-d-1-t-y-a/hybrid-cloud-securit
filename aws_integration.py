#!/usr/bin/env python3
"""
AWS Integration for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import boto3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from config import settings
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSIntegration:
    """AWS integration service for cloud security"""
    
    def __init__(self):
        """Initialize AWS services"""
        self.s3_client = None
        self.cloudwatch_client = None
        self.iam_client = None
        self.lambda_client = None
        self.initialized = False
        
        try:
            # Check if AWS credentials are configured (already stripped in config.py)
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            if not access_key or not secret_key:
                logger.warning("AWS credentials not configured. AWS features will be unavailable.")
                logger.warning(f"Access Key ID present: {bool(access_key)}, Secret Key present: {bool(secret_key)}")
                return
            
            # Validate credentials format (basic check)
            if len(access_key) < 16 or len(secret_key) < 30:
                logger.warning(f"AWS credentials appear to be invalid format. Access Key length: {len(access_key)}, Secret Key length: {len(secret_key)}")
            
            # Log first few characters for debugging (without exposing full key)
            logger.info(f"Initializing AWS services with Access Key starting with: {access_key[:4]}...")
            
            # Create AWS clients with explicit credentials
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.cloudwatch_client = boto3.client(
                'cloudwatch',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.initialized = True
            logger.info(f"AWS services initialized successfully in region: {settings.AWS_REGION}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS services: {e}")
            logger.error(f"Access Key ID (first 4 chars): {settings.AWS_ACCESS_KEY_ID[:4] if settings.AWS_ACCESS_KEY_ID else 'N/A'}...")
            self.initialized = False
    
    def reinitialize(self):
        """Reinitialize AWS services (useful if credentials were updated)"""
        # Reset all clients
        self.s3_client = None
        self.cloudwatch_client = None
        self.iam_client = None
        self.lambda_client = None
        self.initialized = False
        
        # Reinitialize with current credentials
        try:
            access_key = settings.AWS_ACCESS_KEY_ID
            secret_key = settings.AWS_SECRET_ACCESS_KEY
            
            if not access_key or not secret_key:
                logger.warning("Cannot reinitialize: AWS credentials not configured")
                return
            
            # Create AWS clients with explicit credentials
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.cloudwatch_client = boto3.client(
                'cloudwatch',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=settings.AWS_REGION
            )
            self.initialized = True
            logger.info(f"AWS services reinitialized successfully in region: {settings.AWS_REGION}")
        except Exception as e:
            logger.error(f"Failed to reinitialize AWS services: {e}")
            self.initialized = False
    
    def _ensure_initialized(self):
        """Ensure AWS services are initialized, reinitialize if credentials are now available"""
        access_key = settings.AWS_ACCESS_KEY_ID
        secret_key = settings.AWS_SECRET_ACCESS_KEY
        
        # Debug logging
        if access_key:
            logger.debug(f"Access Key ID found (length: {len(access_key)}, starts with: {access_key[:4]}...)")
        else:
            logger.debug("Access Key ID is empty or not set")
        
        if secret_key:
            logger.debug(f"Secret Access Key found (length: {len(secret_key)})")
        else:
            logger.debug("Secret Access Key is empty or not set")
        
        # If not initialized but credentials are now available, try to initialize
        if not self.initialized and access_key and secret_key:
            logger.info("Credentials detected but services not initialized. Attempting to initialize...")
            self.reinitialize()
        elif not self.initialized:
            logger.warning("AWS services not initialized and credentials are missing")
        
        return self.initialized
    
    def store_encrypted_data(self, data: str, key: str) -> Dict[str, Any]:
        """Store encrypted data in S3"""
        try:
            # Try to initialize if credentials are available
            if not self._ensure_initialized():
                raise ValueError("AWS services not initialized. Please check your AWS credentials in .env file.")
            
            if not self.s3_client:
                raise ValueError("AWS S3 client not available. Please check your AWS credentials in .env file.")
            
            # Check if bucket is configured (already stripped in config.py)
            bucket = settings.AWS_S3_BUCKET
            if not bucket:
                raise ValueError("AWS_S3_BUCKET is not configured in .env file")
            
            # Create S3 object key
            s3_key = f"encrypted-data/{key}"
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=data.encode('utf-8'),
                ServerSideEncryption='AES256'
            )
            
            return {
                "status": "success",
                "bucket": bucket,
                "key": s3_key,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to store data in S3: {error_msg}")
            
            # Provide more helpful error messages
            if "InvalidAccessKeyId" in error_msg:
                raise ValueError(
                    "Invalid AWS Access Key ID. Please verify:\n"
                    "1. Your AWS_ACCESS_KEY_ID in .env file is correct\n"
                    "2. There are no extra spaces or quotes around the key\n"
                    "3. The key exists in your AWS account\n"
                    "4. You have restarted the server after updating .env"
                )
            elif "SignatureDoesNotMatch" in error_msg:
                raise ValueError(
                    "AWS Secret Access Key mismatch. Please verify:\n"
                    "1. Your AWS_SECRET_ACCESS_KEY in .env file is correct\n"
                    "2. There are no extra spaces or quotes around the key\n"
                    "3. The secret key matches the access key ID\n"
                    "4. You have restarted the server after updating .env"
                )
            elif "NoSuchBucket" in error_msg:
                raise ValueError(
                    f"S3 bucket '{bucket}' does not exist. Please:\n"
                    f"1. Verify the bucket name in AWS_S3_BUCKET is correct\n"
                    f"2. Ensure the bucket exists in region {settings.AWS_REGION}\n"
                    "3. Check your AWS credentials have permission to access this bucket"
                )
            else:
                raise
    
    def retrieve_encrypted_data(self, key: str) -> str:
        """Retrieve encrypted data from S3"""
        try:
            # Try to initialize if credentials are available
            if not self._ensure_initialized():
                raise ValueError("AWS services not initialized. Please check your AWS credentials in .env file.")
            
            if not self.s3_client:
                raise ValueError("AWS S3 client not available. Please check your AWS credentials in .env file.")
            
            s3_key = f"encrypted-data/{key}"
            
            response = self.s3_client.get_object(
                Bucket=settings.AWS_S3_BUCKET,
                Key=s3_key
            )
            
            return response['Body'].read().decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to retrieve data from S3: {e}")
            raise
    
    def send_cloudwatch_metrics(self, namespace: str, metric_name: str, 
                               value: float, unit: str = "Count") -> Dict[str, Any]:
        """Send metrics to CloudWatch"""
        try:
            # Try to initialize if credentials are available
            if not self._ensure_initialized():
                raise ValueError("AWS services not initialized. Please check your AWS credentials in .env file.")
            
            if not self.cloudwatch_client:
                raise ValueError("AWS CloudWatch client not available. Please check your AWS credentials in .env file.")
            
            response = self.cloudwatch_client.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        'MetricName': metric_name,
                        'Value': value,
                        'Unit': unit,
                        'Timestamp': datetime.utcnow()
                    }
                ]
            )
            
            return {
                "status": "success",
                "namespace": namespace,
                "metric_name": metric_name,
                "value": value,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to send metrics to CloudWatch: {e}")
            raise
    
    def create_iam_user(self, username: str, policies: List[str]) -> Dict[str, Any]:
        """Create IAM user with policies"""
        try:
            # Create user
            self.iam_client.create_user(UserName=username)
            
            # Attach policies
            for policy in policies:
                self.iam_client.attach_user_policy(
                    UserName=username,
                    PolicyArn=policy
                )
            
            # Create access key
            access_key_response = self.iam_client.create_access_key(UserName=username)
            
            return {
                "status": "success",
                "username": username,
                "access_key_id": access_key_response['AccessKey']['AccessKeyId'],
                "secret_access_key": access_key_response['AccessKey']['SecretAccessKey'],
                "policies": policies,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to create IAM user: {e}")
            raise
    
    def execute_lambda_function(self, function_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Lambda function for SOAR automation"""
        try:
            response = self.lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps(payload)
            )
            
            result = json.loads(response['Payload'].read())
            
            return {
                "status": "success",
                "function_name": function_name,
                "result": result,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to execute Lambda function: {e}")
            raise
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics from CloudWatch"""
        try:
            # Try to initialize if credentials are available
            if not self._ensure_initialized():
                # Return empty metrics instead of raising error for better UX
                return {
                    "metrics": [],
                    "period": "1 hour",
                    "message": "AWS credentials not configured",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            if not self.cloudwatch_client:
                return {
                    "metrics": [],
                    "period": "1 hour",
                    "message": "AWS CloudWatch client not available",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            end_time = datetime.utcnow()
            start_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            
            response = self.cloudwatch_client.get_metric_statistics(
                Namespace='HybridCloudSecurity',
                MetricName='SecurityEvents',
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum', 'Average', 'Maximum']
            )
            
            return {
                "metrics": response['Datapoints'],
                "period": "1 hour",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get security metrics: {e}")
            raise
    
    def test_aws_connection(self) -> Dict[str, Any]:
        """Test AWS connection and services"""
        try:
            # Try to initialize if credentials are available
            if not self._ensure_initialized():
                return {
                    "status": "failed",
                    "error": "AWS credentials not configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in .env file",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            if not self.s3_client or not self.cloudwatch_client or not self.iam_client:
                return {
                    "status": "failed",
                    "error": "AWS clients not initialized. Please check your credentials.",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            # Test S3 connection
            s3_response = self.s3_client.list_buckets()
            s3_status = "connected" if s3_response else "failed"
            
            # Test CloudWatch connection
            cw_response = self.cloudwatch_client.list_metrics()
            cw_status = "connected" if cw_response else "failed"
            
            # Test IAM connection
            iam_response = self.iam_client.list_users()
            iam_status = "connected" if iam_response else "failed"
            
            return {
                "status": "success",
                "services": {
                    "s3": s3_status,
                    "cloudwatch": cw_status,
                    "iam": iam_status
                },
                "region": settings.AWS_REGION,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"AWS connection test failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

# Create AWS integration instance
aws_integration = AWSIntegration()
