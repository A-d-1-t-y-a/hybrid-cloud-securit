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
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION
            )
            self.cloudwatch_client = boto3.client(
                'cloudwatch',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION
            )
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION
            )
            self.lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=settings.AWS_REGION
            )
            logger.info("AWS services initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AWS services: {e}")
            raise
    
    def store_encrypted_data(self, data: str, key: str) -> Dict[str, Any]:
        """Store encrypted data in S3"""
        try:
            # Create S3 object key
            s3_key = f"encrypted-data/{key}"
            
            # Upload to S3
            self.s3_client.put_object(
                Bucket=settings.AWS_S3_BUCKET,
                Key=s3_key,
                Body=data.encode('utf-8'),
                ServerSideEncryption='AES256'
            )
            
            return {
                "status": "success",
                "bucket": settings.AWS_S3_BUCKET,
                "key": s3_key,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to store data in S3: {e}")
            raise
    
    def retrieve_encrypted_data(self, key: str) -> str:
        """Retrieve encrypted data from S3"""
        try:
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
