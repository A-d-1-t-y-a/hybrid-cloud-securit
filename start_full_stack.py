#!/usr/bin/env python3
import subprocess
import sys
import time
import os
import signal
import threading
from pathlib import Path

def start_security_framework_backend():
    print("Starting Hybrid Cloud Security Framework Backend...")
    # Activate virtual environment and run backend
    if os.name == 'nt':  # Windows
        activate_cmd = "venv\\Scripts\\activate && py run.py"
    else:  # Unix/Linux/Mac
        activate_cmd = "source venv/bin/activate && python run.py"
    
    print(f"Backend command: {activate_cmd}")
    
    backend_process = subprocess.Popen(
        activate_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return backend_process

def start_security_framework_frontend():
    print("Starting Hybrid Cloud Security Framework Frontend...")
    
    # Don't change directory, run from root with proper path
    if os.name == 'nt':  # Windows
        activate_cmd = "venv\\Scripts\\activate && py -m streamlit run frontend/app.py --server.port 8501 --server.address localhost"
    else:  # Unix/Linux/Mac
        activate_cmd = "source venv/bin/activate && python -m streamlit run frontend/app.py --server.port 8501 --server.address localhost"
    
    print(f"Frontend command: {activate_cmd}")
    
    frontend_process = subprocess.Popen(
        activate_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=os.getcwd()  # Ensure we're in the root directory
    )
    return frontend_process

def monitor_application_process(process, process_name):
    while process.poll() is None:
        time.sleep(1)
    
    print(f"{process_name} process ended unexpectedly")
    return process.returncode

def main():
    print("Hybrid Cloud Security Framework - Full Stack Application")
    print("=" * 80)
    print("Author: Nithin Bonagiri (X24137430)")
    print("Supervisor: Prof. Sean Heeney")
    print("Institution: National College of Ireland")
    print("=" * 80)
    
    security_framework_backend_process = None
    security_framework_frontend_process = None
    
    try:
        security_framework_backend_process = start_security_framework_backend()
        print("Waiting for backend to start...")
        time.sleep(5)
        
        # Check if backend is still running
        if security_framework_backend_process.poll() is not None:
            print("Backend failed to start!")
            stdout, stderr = security_framework_backend_process.communicate()
            print(f"Backend stdout: {stdout}")
            print(f"Backend stderr: {stderr}")
            return
        
        security_framework_frontend_process = start_security_framework_frontend()
        print("Waiting for frontend to start...")
        time.sleep(8)  # Give frontend more time to start
        
        # Check if frontend is still running
        if security_framework_frontend_process.poll() is not None:
            print("Frontend failed to start!")
            stdout, stderr = security_framework_frontend_process.communicate()
            print(f"Frontend stdout: {stdout}")
            print(f"Frontend stderr: {stderr}")
            return
        
        print("\nFull Stack Application Started Successfully!")
        print("=" * 80)
        print("Frontend (Streamlit): http://localhost:8501")
        print("Backend API: http://localhost:8000")
        print("API Documentation: http://localhost:8000/docs")
        print("Alternative Docs: http://localhost:8000/redoc")
        print("=" * 80)
        print("Press Ctrl+C to stop both services")
        print("=" * 80)
        print("NOTE: Use http://localhost:8501 (not 0.0.0.0) to access the frontend")
        print("=" * 80)
        
        backend_monitoring_thread = threading.Thread(target=monitor_application_process, args=(security_framework_backend_process, "Backend"))
        frontend_monitoring_thread = threading.Thread(target=monitor_application_process, args=(security_framework_frontend_process, "Frontend"))
        
        backend_monitoring_thread.daemon = True
        frontend_monitoring_thread.daemon = True
        
        backend_monitoring_thread.start()
        frontend_monitoring_thread.start()
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down services...")
        
        if security_framework_frontend_process:
            print("Stopping frontend...")
            security_framework_frontend_process.terminate()
            try:
                security_framework_frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                security_framework_frontend_process.kill()
        
        if security_framework_backend_process:
            print("Stopping backend...")
            security_framework_backend_process.terminate()
            try:
                security_framework_backend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                security_framework_backend_process.kill()
        
        print("All services stopped successfully!")
        
    except Exception as e:
        print(f"Error starting services: {e}")
        
        if security_framework_frontend_process:
            security_framework_frontend_process.terminate()
        if security_framework_backend_process:
            security_framework_backend_process.terminate()
        
        sys.exit(1)

if __name__ == "__main__":
    main()
