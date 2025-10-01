#!/usr/bin/env python3
"""
Hybrid Cloud Security Framework - Main Application
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import uvicorn

from src.core.config import Settings, get_settings
from src.core.database import init_db
from src.core.logging import setup_logging
from src.iam.routes import router as iam_router
from src.data_protection.routes import router as data_protection_router
from src.monitoring.routes import router as monitoring_router
from src.compliance.routes import router as compliance_router
from src.soar.routes import router as soar_router
from src.core.middleware import SecurityMiddleware, LoggingMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logging.info("Starting Hybrid Cloud Security Framework...")
    await init_db()
    logging.info("Database initialized successfully")
    
    yield
    
    # Shutdown
    logging.info("Shutting down Hybrid Cloud Security Framework...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    settings = get_settings()
    
    app = FastAPI(
        title="Hybrid Cloud Security Framework",
        description="Comprehensive security framework for hybrid cloud environments",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add custom middleware
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(LoggingMiddleware)
    
    # Include routers
    app.include_router(iam_router, prefix="/api/v1/iam", tags=["Identity & Access Management"])
    app.include_router(data_protection_router, prefix="/api/v1/data-protection", tags=["Data Protection"])
    app.include_router(monitoring_router, prefix="/api/v1/monitoring", tags=["Security Monitoring"])
    app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance & Governance"])
    app.include_router(soar_router, prefix="/api/v1/soar", tags=["SOAR Platform"])
    
    return app


# Create the application instance
app = create_app()


@app.get("/", response_model=Dict[str, Any])
async def root():
    """Root endpoint with framework information"""
    return {
        "message": "Hybrid Cloud Security Framework",
        "version": "1.0.0",
        "author": "Nithin Bonagiri (X24137430)",
        "supervisor": "Prof. Sean Heeney",
        "institution": "National College of Ireland",
        "status": "operational",
        "components": {
            "iam": "Identity and Access Management",
            "data_protection": "Data Protection and Classification",
            "monitoring": "Security Monitoring and SIEM",
            "compliance": "Compliance and Governance",
            "soar": "Security Orchestration and Response"
        }
    }


@app.get("/health", response_model=Dict[str, Any])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "version": "1.0.0"
    }


@app.get("/api/v1/framework/status", response_model=Dict[str, Any])
async def framework_status():
    """Framework status and component health"""
    return {
        "framework": "Hybrid Cloud Security Framework",
        "status": "operational",
        "components": {
            "iam": {"status": "active", "endpoints": 8},
            "data_protection": {"status": "active", "endpoints": 6},
            "monitoring": {"status": "active", "endpoints": 10},
            "compliance": {"status": "active", "endpoints": 7},
            "soar": {"status": "active", "endpoints": 9}
        },
        "security_standards": [
            "SAML 2.0", "OAuth 2.0", "OpenID Connect",
            "AES-256", "RSA-4096", "ECC P-384",
            "GDPR", "HIPAA", "SOX", "ISO 27001", "PCI DSS"
        ],
        "expert_validation": {
            "panel_size": "8-10 security professionals",
            "validation_phases": 4,
            "assessment_criteria": 4
        },
        "case_studies": {
            "organizations": 5,
            "sectors": ["Healthcare", "Financial Services", "Government", "Technology", "Manufacturing"],
            "implementation_status": "in_progress"
        }
    }


if __name__ == "__main__":
    # Setup logging
    setup_logging()
    
    # Run the application
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
