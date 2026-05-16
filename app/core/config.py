"""Application configuration for FATV."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


class Config:
    # Use an environment variable in real deployments:
    # PowerShell: $env:FATV_SECRET_KEY="your-random-secret"
    # Bash: export FATV_SECRET_KEY="your-random-secret"
    SECRET_KEY = os.environ.get("FATV_SECRET_KEY", "fatv-dev-secret-change-me")
    UPLOAD_FOLDER = str(BASE_DIR / "uploads")
    REPORT_FOLDER = str(BASE_DIR / "reports")
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024
