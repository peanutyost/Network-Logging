#!/bin/bash
# Script to run the FastAPI server
uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload

