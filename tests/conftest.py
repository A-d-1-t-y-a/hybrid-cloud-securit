import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database import get_db
from models import Base
from main import app

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_security_framework.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db):
    return TestClient(app)

@pytest.fixture
def test_user_data():
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "role": "user"
    }

@pytest.fixture
def auth_token(client, test_user_data):
    client.post("/api/v1/iam/register", json=test_user_data)
    response = client.post("/api/v1/iam/login", json={
        "username": test_user_data["username"],
        "password": test_user_data["password"]
    })
    return response.json()["access_token"]

