#!/usr/bin/env python3
"""
Hybrid Cloud Security Framework - Setup Script
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def run_command(command: str, description: str) -> bool:
    """Run a command and return success status"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False


def check_python_version():
    """Check Python version"""
    print("🐍 Checking Python version...")
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")


def create_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    directories = [
        "logs",
        "data",
        "temp",
        "backups",
        "docs",
        "tests"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   ✅ Created {directory}/")


def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing dependencies...")
    return run_command("pip install -r requirements.txt", "Installing Python packages")


def setup_environment():
    """Setup environment variables"""
    print("🔧 Setting up environment...")
    
    env_content = """# Hybrid Cloud Security Framework - Environment Configuration

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/hybrid_cloud_security
REDIS_URL=redis://localhost:6379/0

# Security Configuration
SECRET_KEY=your-secret-key-here-change-in-production
JWT_SECRET_KEY=your-jwt-secret-key-here-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30

# Encryption Keys (Generate new keys for production)
AES_KEY=your-aes-256-key-here-32-bytes-long
RSA_PRIVATE_KEY=your-rsa-private-key-here
RSA_PUBLIC_KEY=your-rsa-public-key-here

# Cloud Provider Configuration (Optional)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_REGION=us-east-1

AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_TENANT_ID=your-azure-tenant-id

GCP_PROJECT_ID=your-gcp-project-id
GCP_CREDENTIALS_PATH=path/to/gcp-credentials.json

# Monitoring Configuration
ELASTICSEARCH_URL=http://localhost:9200
PROMETHEUS_URL=http://localhost:9090
LOG_LEVEL=INFO

# CORS Configuration
ALLOWED_ORIGINS=["http://localhost:3000", "http://localhost:8080"]

# Expert Panel Configuration
EXPERT_PANEL_SIZE=10
VALIDATION_PHASES=4

# Case Study Configuration
CASE_STUDY_ORGANIZATIONS=5
IMPLEMENTATION_TIMELINE=24

# Security Standards
ENABLE_SAML=true
ENABLE_OAUTH=true
ENABLE_OPENID=true
ENABLE_MFA=true

# Compliance Standards
ENABLE_GDPR=true
ENABLE_HIPAA=true
ENABLE_SOX=true
ENABLE_ISO27001=true
ENABLE_PCI_DSS=true
"""
    
    with open(".env", "w") as f:
        f.write(env_content)
    
    print("✅ Environment file created (.env)")
    print("⚠️  Please update the .env file with your actual configuration")


def setup_database():
    """Setup database (PostgreSQL)"""
    print("🗄️ Setting up database...")
    print("   📝 Please ensure PostgreSQL is installed and running")
    print("   📝 Create database: hybrid_cloud_security")
    print("   📝 Update DATABASE_URL in .env file")


def setup_redis():
    """Setup Redis"""
    print("🔴 Setting up Redis...")
    print("   📝 Please ensure Redis is installed and running")
    print("   📝 Update REDIS_URL in .env file if needed")


def run_tests():
    """Run tests"""
    print("🧪 Running tests...")
    return run_command("python -m pytest tests/ -v", "Running test suite")


def generate_documentation():
    """Generate documentation"""
    print("📚 Generating documentation...")
    return run_command("python -m mkdocs build", "Generating documentation")


def main():
    """Main setup function"""
    print("🚀 Hybrid Cloud Security Framework Setup")
    print("=" * 50)
    print(f"Author: Nithin Bonagiri (X24137430)")
    print(f"Supervisor: Prof. Sean Heeney")
    print(f"Institution: National College of Ireland")
    print()
    
    # Check Python version
    check_python_version()
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Setup failed at dependency installation")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Setup database
    setup_database()
    
    # Setup Redis
    setup_redis()
    
    print()
    print("✅ Setup completed successfully!")
    print()
    print("📋 Next Steps:")
    print("   1. Update .env file with your configuration")
    print("   2. Start PostgreSQL and Redis services")
    print("   3. Run: python main.py")
    print("   4. Visit: http://localhost:8000/docs")
    print()
    print("🔗 GitHub Repository: https://github.com/yourusername/hybrid-cloud-security")
    print("📧 Contact: nithin.bonagiri@student.ncirl.ie")


if __name__ == "__main__":
    main()
