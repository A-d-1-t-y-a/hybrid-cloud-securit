import os
from dotenv import load_dotenv

load_dotenv()

class SecurityFrameworkConfig:
    API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
    APP_TITLE = "Hybrid Cloud Security Framework"
    APP_ICON = ""
    LAYOUT = "wide"
    THEME = "dark"
    
    SIDEBAR_STYLE = """
    <style>
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #1e3a8a 0%, #1e40af 100%);
    }
    .sidebar .sidebar-content .block-container {
        padding-top: 1rem;
    }
    </style>
    """
    
    MAIN_STYLE = """
    <style>
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .security-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    .compliance-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 0.5rem 0;
    }
    </style>
    """
