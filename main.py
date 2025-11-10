from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from dotenv import load_dotenv
from database import create_tables
from routes import iam, data_protection, monitoring, compliance, soar, aws, dashboard
from auth import get_current_user

load_dotenv()

app = FastAPI(
    title="Hybrid Cloud Security Framework",
    description="Comprehensive security framework for hybrid cloud environments",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

create_tables()

app.include_router(iam.router)
app.include_router(data_protection.router)
app.include_router(monitoring.router)
app.include_router(compliance.router)
app.include_router(soar.router)
app.include_router(aws.router)
app.include_router(dashboard.router)

@app.get("/")
async def root():
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

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/v1/framework/status")
async def get_framework_status():
    return {
        "framework": "Hybrid Cloud Security Framework",
        "status": "operational",
        "components": {
            "iam": {"status": "active", "endpoints": 4},
            "data_protection": {"status": "active", "endpoints": 3},
            "monitoring": {"status": "active", "endpoints": 3},
            "compliance": {"status": "active", "endpoints": 2},
            "soar": {"status": "active", "endpoints": 3},
            "aws_integration": {"status": "active", "endpoints": 5}
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
        },
        "aws_integration": {
            "s3_storage": "active",
            "cloudwatch_monitoring": "active",
            "iam_management": "active",
            "lambda_automation": "active"
        }
    }
