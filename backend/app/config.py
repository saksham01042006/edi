import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR.parent / ".env")

PROJECT_NAME = "PrivTrace"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./privtrace.db")
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
SECRET_KEY = os.getenv("SECRET_KEY", "development-secret")
DEBUG = os.getenv("DEBUG", "true").lower() == "true"
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "1048576"))
