@echo off
title AI Smart Grid Honeypot - Pytest Suite
echo ===============================================================================
echo Running Complete Automated Test Suite (17 Tests across 5 Subsystems)...
echo ===============================================================================
python -m pytest tests/ -v
echo ===============================================================================
pause

