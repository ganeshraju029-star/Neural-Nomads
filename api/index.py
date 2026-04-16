"""Vercel serverless function for Flask app"""

import sys
import os

# Add parent directory to path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the already-instantiated app from app.py
from app import app_instance, app

# The app_instance is already initialized with all security systems
# The WSGI app is available as 'app' for Vercel to use
