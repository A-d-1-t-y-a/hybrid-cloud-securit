"""
Custom middleware for Hybrid Cloud Security Framework
"""

import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from src.core.logging import get_logger

logger = get_logger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for request validation"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Add security headers
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """Logging middleware for request/response logging"""
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Log request
        start_time = time.time()
        logger.info(f"Request {request_id}: {request.method} {request.url}")
        
        # Process request
        response = await call_next(request)
        
        # Log response
        process_time = time.time() - start_time
        logger.info(f"Response {request_id}: {response.status_code} - {process_time:.3f}s")
        
        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response
