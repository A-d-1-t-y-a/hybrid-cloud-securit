#!/usr/bin/env python3
"""
Hybrid Cloud Security Framework - Startup Script
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import os
import sys
import subprocess
from pathlib import Path


def check_python_version():
    """Check Python version"""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    return True


def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import sqlalchemy
        print("✅ Core dependencies available")
        return True
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        print("Please run: pip install -r requirements.txt")
        return False


def create_directories():
    """Create necessary directories if they don't exist"""
    directories = ["logs", "data", "temp", "backups"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✅ Project directories ready")


def start_application():
    """Start the FastAPI application"""
    print("🚀 Starting Hybrid Cloud Security Framework...")
    print("=" * 60)
    print("Author: Nithin Bonagiri (X24137430)")
    print("Supervisor: Prof. Sean Heeney")
    print("Institution: National College of Ireland")
    print()
    
    try:
        # Start the application
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "main:app", 
            "--host", "0.0.0.0", 
            "--port", "8000", 
            "--reload"
        ])
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"❌ Error starting application: {e}")


def main():
    """Main startup function"""
    print("🔐 Hybrid Cloud Security Framework")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        print("\n📦 Installing dependencies...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Start application
    start_application()


if __name__ == "__main__":
    main()
