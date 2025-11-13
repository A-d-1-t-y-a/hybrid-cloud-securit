#!/usr/bin/env python3
import subprocess
import sys
import time
import os
import signal
import threading
from pathlib import Path

def get_venv_python():
    """Get the Python executable from the virtual environment"""
    if os.name == 'nt':  # Windows
        return os.path.join('venv', 'Scripts', 'python.exe')
    else:  # Unix/Linux/Mac
        return os.path.join('venv', 'bin', 'python')

def check_port_in_use(port):
    """Check if a port is already in use"""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def start_security_framework_backend():
    """Start the backend server"""
    print("Starting Hybrid Cloud Security Framework Backend...")
    
    venv_python = get_venv_python()
    if not os.path.exists(venv_python):
        print(f"ERROR: Virtual environment not found at {venv_python}")
        print("Please run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt")
        return None
    
    # Check if port 8000 is already in use
    if check_port_in_use(8000):
        print("WARNING: Port 8000 is already in use. Backend might already be running.")
    
    backend_process = subprocess.Popen(
        [venv_python, 'run.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    return backend_process

def start_security_framework_frontend():
    """Start the frontend server"""
    print("Starting Hybrid Cloud Security Framework Frontend...")
    
    venv_python = get_venv_python()
    if not os.path.exists(venv_python):
        print(f"ERROR: Virtual environment not found at {venv_python}")
        return None
    
    # Check if port 8501 is already in use
    if check_port_in_use(8501):
        print("WARNING: Port 8501 is already in use. Frontend might already be running.")
    
    frontend_process = subprocess.Popen(
        [venv_python, '-m', 'streamlit', 'run', 'frontend/app.py', 
         '--server.port', '8501', 
         '--server.address', '127.0.0.1',
         '--server.headless', 'true'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        cwd=os.getcwd()
    )
    
    return frontend_process

def print_output(process, process_name):
    """Print output from a process in real-time"""
    try:
        for line in iter(process.stdout.readline, ''):
            if line:
                print(f"[{process_name}] {line.rstrip()}")
    except Exception as e:
        print(f"Error reading {process_name} output: {e}")

def monitor_application_process(process, process_name):
    """Monitor a process and print its output"""
    if process:
        output_thread = threading.Thread(
            target=print_output, 
            args=(process, process_name),
            daemon=True
        )
        output_thread.start()
        
        while process.poll() is None:
            time.sleep(1)
        
        print(f"{process_name} process ended with code: {process.returncode}")
        return process.returncode

def main():
    print("Hybrid Cloud Security Framework - Full Stack Application")
    print("=" * 80)
    print("Author: Nithin Bonagiri (X24137430)")
    print("Supervisor: Prof. Sean Heeney")
    print("Institution: National College of Ireland")
    print("=" * 80)
    print()
    
    security_framework_backend_process = None
    security_framework_frontend_process = None
    
    try:
        # Start backend
        security_framework_backend_process = start_security_framework_backend()
        if not security_framework_backend_process:
            print("Failed to start backend!")
            return
        
        print("Waiting for backend to start (5 seconds)...")
        time.sleep(5)
        
        # Check if backend is still running
        if security_framework_backend_process.poll() is not None:
            print("Backend failed to start!")
            stdout, stderr = security_framework_backend_process.communicate(timeout=2)
            print(f"Backend output: {stdout}")
            if stderr:
                print(f"Backend errors: {stderr}")
            return
        
        # Start frontend
        security_framework_frontend_process = start_security_framework_frontend()
        if not security_framework_frontend_process:
            print("Failed to start frontend!")
            return
        
        print("Waiting for frontend to start (10 seconds)...")
        time.sleep(10)
        
        # Check if frontend is still running
        if security_framework_frontend_process.poll() is not None:
            print("Frontend failed to start!")
            stdout, stderr = security_framework_frontend_process.communicate(timeout=2)
            print(f"Frontend output: {stdout}")
            if stderr:
                print(f"Frontend errors: {stderr}")
            return
        
        print("\n" + "=" * 80)
        print("Full Stack Application Started Successfully!")
        print("=" * 80)
        print("Frontend (Streamlit): http://127.0.0.1:8501")
        print("Backend API: http://127.0.0.1:8000")
        print("API Documentation: http://127.0.0.1:8000/docs")
        print("Alternative Docs: http://127.0.0.1:8000/redoc")
        print("=" * 80)
        print("Press Ctrl+C to stop both services")
        print("=" * 80)
        print()
        
        # Start monitoring threads
        backend_monitoring_thread = threading.Thread(
            target=monitor_application_process, 
            args=(security_framework_backend_process, "Backend"),
            daemon=True
        )
        frontend_monitoring_thread = threading.Thread(
            target=monitor_application_process, 
            args=(security_framework_frontend_process, "Frontend"),
            daemon=True
        )
        
        backend_monitoring_thread.start()
        frontend_monitoring_thread.start()
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            # Check if processes are still running
            if security_framework_backend_process.poll() is not None:
                print("Backend process ended unexpectedly!")
                break
            if security_framework_frontend_process.poll() is not None:
                print("Frontend process ended unexpectedly!")
                break
            
    except KeyboardInterrupt:
        print("\n" + "=" * 80)
        print("Shutting down services...")
        print("=" * 80)
        
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
        import traceback
        traceback.print_exc()
        
        if security_framework_frontend_process:
            security_framework_frontend_process.terminate()
        if security_framework_backend_process:
            security_framework_backend_process.terminate()
        
        sys.exit(1)

if __name__ == "__main__":
    main()

