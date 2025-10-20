#!/usr/bin/env python3
"""
Startup script for Hybrid Cloud Security Framework
Author: Nithin Bonagiri (X24137430)
Supervisor: Prof. Sean Heeney
Institution: National College of Ireland
"""

import uvicorn
from database import create_tables
from config import settings

def main():
    """Main startup function"""
    print("🚀 Starting Hybrid Cloud Security Framework...")
    print("=" * 60)
    print(f"Author: Nithin Bonagiri (X24137430)")
    print(f"Supervisor: Prof. Sean Heeney")
    print(f"Institution: National College of Ireland")
    print(f"Version: {settings.APP_VERSION}")
    print("=" * 60)
    
    # Create database tables
    print("📊 Creating database tables...")
    try:
        create_tables()
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"⚠️ Database setup warning: {e}")
    
    print("\n🌐 Starting server...")
    print(f"📚 API Documentation: http://{settings.HOST}:{settings.PORT}/docs")
    print(f"🔍 Alternative Docs: http://{settings.HOST}:{settings.PORT}/redoc")
    print(f"🏠 Homepage: http://{settings.HOST}:{settings.PORT}/")
    print("\n" + "=" * 60)
    
    # Start the server
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )

if __name__ == "__main__":
    main()
