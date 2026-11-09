@echo off
title AI Smart Grid Honeypot - System Setup
echo ===============================================================================
echo Setting up AI-Enhanced Smart Grid Honeypot Environment...
echo ===============================================================================

echo [1/4] Installing Required Dependencies...
python -m pip install -r requirements.txt

echo [2/4] Initializing Database & 10 Smart Homes...
python database/db_initializer.py

echo [3/4] Training AI Classification Models...
python detection/random_forest.py
python detection/model_evaluation.py

echo [4/4] Verifying Test Suite...
python -m pytest tests/ -v

echo ===============================================================================
echo Environment Setup 100%% Complete!
echo Double click 'run_dashboard.bat' or run 'streamlit run app.py' to launch!
echo ===============================================================================
pause

