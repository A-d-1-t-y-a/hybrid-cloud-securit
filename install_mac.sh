#!/bin/bash

echo "=========================================="
echo "Hybrid Cloud Security Framework"
echo "Mac Installation Script"
echo "=========================================="
echo ""

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo "Found: $PYTHON_VERSION"
echo ""

# Remove old virtual environment if it exists
if [ -d "venv" ]; then
    echo "Removing old virtual environment..."
    rm -rf venv
fi

# Create new virtual environment
echo "Creating new virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
echo "Installing dependencies..."
echo "This may take a few minutes..."
pip install -r requirements.txt

# Verify installation
echo ""
echo "Verifying installation..."
python -c "import fastapi; print('✓ FastAPI installed')" || echo "✗ FastAPI failed"
python -c "import streamlit; print('✓ Streamlit installed')" || echo "✗ Streamlit failed"
python -c "import sqlalchemy; print('✓ SQLAlchemy installed')" || echo "✗ SQLAlchemy failed"
python -c "import boto3; print('✓ Boto3 installed')" || echo "✗ Boto3 failed"

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To start the application:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run: python start_full_stack.py"
echo ""
echo "Or use the quick start:"
echo "  source venv/bin/activate && python start_full_stack.py"
echo ""

